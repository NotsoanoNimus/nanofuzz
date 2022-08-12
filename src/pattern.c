/*
 * pattern.h
 *
 * Pattern syntax parsing.
 *
 */

#include "pattern.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>



// A ranging structure used in the pattern blocks to determine the amount of times, if set,
//   to repeat a block of pattern data.
struct _fuzz_range_t {
    unsigned char single;   // If non-zero, the 'base' value is the static amount to generate; no ranging.
    unsigned short base;
    unsigned short high;
} __attribute__((__packed__));

// A single unit of the fuzz factory used to generate fuzzer output.
struct _fuzz_pattern_block_t {
    // The type of pattern block being constructed: string, variable, reference, sub, etc.
    pattern_block_type type;
    // Represents a pointer to the node's data.
    //   This could point to a string, another List, etc. depending on the type.
    void* data;
    // How many times to produce this specific node's data. Defaults to 1.
    fuzz_range_t count;
    // This label is the name of the variable assigned to the block, if any.
    const char label[FUZZ_MAX_PATTERN_LABEL_NAME_LENGTH];
} __attribute__((__packed__));

// Represents a single contiguous block of memory which all of the block items get joined into.
//   This is what nanofuzz will actually use in generating content.
struct _fuzz_factory_t {
    // Pointer to the blob of nodes...
    void* node_seq;
    // ... of size count, each = sizeof(fuzz_pattern_block_t)
    size_t count;
    // Keep a pointer to the underlying list. This makes everything easy to destroy.
    List_t* _list;
};

// Creates a context for a fuzzing pattern parser. This is so static variables
//   don't step on each other in case multiple patterns are being initialized by this library at once.
struct _fuzz_ctx_t {
    // Tracks an overall context's nesting hierarchy; entry points for each layer as it builds.
    //   These values are intended to be ephemeral pointers used just while building the factory.
    fuzz_pattern_block_t** p_nest_tracker;
    // Tracks the index into the above, preventing over-complexity of input patterns.
    size_t nest_level;
};



// Some [important] local static functions.
static inline int __bracket_parse_range( fuzz_pattern_block_t* p_block, const char* p_content, int comma );
static List_t* __parse_pattern( struct _fuzz_ctx_t* const p_ctx, const char* p_pattern );



// Seek the closest closing marker character in a pattern string.
//   Returns NULL if the target character isn't found, or if the target is only ONE char ahead
//   of the start of the input string.
static const char* __seek_marker_end( const char* start, char const target ) {
    const char* end = start;
    while( *(++end) ) {
        if ( *end == target ) {
            if ( (end-start) > 1 )  return end;
            else break;
        }
    }
    return NULL;
}



// Generate a fresh parsing context. For now, inline is OK.
static inline struct _fuzz_ctx_t* const __Context__new() {
    struct _fuzz_ctx_t* p_ctx = (struct _fuzz_ctx_t*)calloc( 1, sizeof(struct _fuzz_ctx_t) );

    p_ctx->p_nest_tracker = (fuzz_pattern_block_t**)calloc(
        FUZZ_MAX_NESTING_COMPLEXITY, sizeof(fuzz_pattern_block_t*) );
    p_ctx->nest_level = 0;

    return (struct _fuzz_ctx_t* const)p_ctx;
}

// Destroy a context. For now, this simply frees the context and tracker.
static void __Context__delete( struct _fuzz_ctx_t* const p ) {
    if ( p ) {
        if ( p->p_nest_tracker )  free( p->p_nest_tracker );
        free( (void*)p );
    }
}



// Compress the contents of a pattern block list into a single calloc and set it in the factory.
static inline fuzz_factory_t* __compress_List_to_factory( List_t* p_list ) {
    if ( NULL == p_list || List__get_count( p_list ) < 1 )  return NULL;

    // Fetch the list items count, calloc, set each cell, and create the factory.
    fuzz_factory_t* x = (fuzz_factory_t*)calloc( 1, sizeof(fuzz_factory_t) );
    x->count = List__get_count( p_list );
    x->_list = p_list;

    // Create the new blob and start filling it out.
    unsigned char* scroll = (unsigned char*)calloc( x->count, sizeof(fuzz_pattern_block_t) );

    // Assign the node sequence to the created heap blob.
    x->node_seq = scroll;

    // Move data into the blob. Since the linked list implementation inserts the data like a stack,
    //   the list HEAD actually contains the final element. Therefore, the insertion into adjacent
    //   memory cells needs to happen in reverse.
    scroll += ( x->count * sizeof(fuzz_pattern_block_t) );

    ListNode_t* y = List__get_head( p_list );
    while ( NULL != y && scroll >= (unsigned char*)(x->node_seq) ) {
        scroll -= sizeof(fuzz_pattern_block_t);
        memcpy( scroll, y->node, sizeof(fuzz_pattern_block_t) );
        y = y->next;
    }

    // Return the built factory.
    return x;
}



// Get the blob data from the given fuzz factory struct.
void* PatternFactory__get_data( fuzz_factory_t* p_fact ) {
    return p_fact->node_seq;
}



// Get the size of the pattern factory's data blob.
size_t PatternFactory__get_data_size( fuzz_factory_t* p_fact ) {
    return (size_t)(p_fact->count * sizeof(fuzz_pattern_block_t));
}



// Frees space used by a pattern factory by destroying it and its nodes' datas from the heap.
void PatternFactory__delete( fuzz_factory_t* p_fact ) {
    // TODO: Rather than just blindly deleting, get the type of each block and delete accordingly.
    if ( NULL == p_fact )  return;

    fuzz_pattern_block_t* x = (fuzz_pattern_block_t*)&(p_fact->node_seq);
    for ( size_t i = 0; i < p_fact->count; i++ ) {
        if ( NULL != x && x->data )  free( x->data );
        x++;
    }

    if ( NULL != p_fact->node_seq )  free( p_fact->node_seq );

    if ( NULL != p_fact->_list )  List__delete( p_fact->_list );

    free( p_fact );
}



// Explain step-by-step what the fuzz factory is doing to generate strings through the given factory.
void PatternFactory__explain( FILE* fp_stream, fuzz_factory_t* p_fact ) {
    if ( NULL == p_fact ) {
        fprintf( fp_stream, "The pattern factory is NULL.\n" );
        return;
    }

    size_t nest = 0;

    // Iterate the factory nodes and explain each.
    for ( size_t i = 0; i < p_fact->count; i++ ) {
        fuzz_pattern_block_t* p = (fuzz_pattern_block_t*)(p_fact->node_seq + (i*sizeof(fuzz_pattern_block_t)));
        if ( NULL == p ) {
            fprintf( fp_stream, "~~ Misunderstood pattern block at node '%lu'. This is problematic!\n", i );
            continue;
        }

        // Preliminary/Common string output and setup.
        fprintf( fp_stream, "[Step %5lu] ", (i+1) );
        for ( size_t j = 0; j < nest; j++ )  fprintf( fp_stream, ">" );
        fprintf( fp_stream, " " );

        // Create a string describing the range of occurrence for the pattern object, if any.
        //   The longest range is 'XXXXX to YYYYY' (15 bytes - inc null-term).
        char* p_range_str = (char*)calloc( 15, sizeof(char) );
        if ( p->count.single )
            snprintf( p_range_str, 15, "%d", p->count.base );
        else
            snprintf( p_range_str, 15, "%u to %u", p->count.base, p->count.high );

        // Based on the item's type, read some information about it.
        switch ( p->type ) {

            case string: {
                fprintf( fp_stream, "Output static string: '%s' (%s times)\n",
                    (const char*)(p->data), p_range_str );
                break;
            }

            case sub: {
                fprintf( fp_stream, "vvv  Enter subsequence layer (nest tag %lu), which runs '%s' times.\n",
                    *((size_t*)(p->data)), p_range_str );
                nest++;
                break;
            }
            case ret: {
                fprintf( fp_stream, "^^^  Repeat subsequence layer as applicable; goes '%lu' nodes back.\n",
                    *((size_t*)(p->data)) );
                nest--;
                break;
            }

            default : {
                fprintf( fp_stream, "~~~~~ Misunderstood pattern block TYPE (%u) at node '%lu'. Problem!\n",
                    p->type, i );
                break;
            }

        }

        free( p_range_str );
    }
}



// Build the fuzz factory. Since this is only intended to run as part of the
//   wind-up cycle, optimization is not an essential concern here.
fuzz_factory_t* PatternFactory__new( const char* p_pattern_str ) {
    clear_fuzz_error();

    struct _fuzz_ctx_t* const p_ctx = __Context__new();
    List_t* p_the_sequence = __parse_pattern( p_ctx, p_pattern_str );
    __Context__delete( p_ctx );

    return __compress_List_to_factory( p_the_sequence );
}


// Define a set of functional or syntactically special characters.
static const char special_chars[] = "$\\[{(";
// Macro to register a fuzz error inside a fuzz_ctx (the pattern_parse func mainly).
#define FUZZ_ERR_IN_CTX(errtype,errstr) { set_fuzz_error( p_ctx->nest_level, (p-p_pattern), errtype, errstr ); goto __err_exit; }
// Internal, recursive pattern parsing. This is called recursively generally
//   when the nesting level () changes.
static List_t* __parse_pattern( struct _fuzz_ctx_t* const p_ctx, const char* p_pattern ) {
    size_t len, nest_level;
    const char* p;
    List_t* p_seq;

    len = strnlen( p_pattern, (FUZZ_MAX_PATTERN_LENGTH-1) );
    nest_level = p_ctx->nest_level;

    p = p_pattern;
    p_seq = List__new( FUZZ_MAX_PATTERN_LENGTH );

    // Let's go!
    printf( "Parsing %lu bytes of input.\n", len );
    for ( ; (*p) && p < (p_pattern+len); p++ ) {
        printf( "READ: %c\n", *p );
        fuzz_pattern_block_t* p_new_block = NULL;

        switch( *p ) {

            case '$':
                break;


            case '\\':
                break;


            case '[':
                break;

            // ********** REPETITION **********
            case '{': {
                // The current block ptr cannot be NULL.
                if ( NULL == *((p_ctx->p_nest_tracker)+nest_level) ) {
                    FUZZ_ERR_IN_CTX( FUZZ_ERROR_INVALID_SYNTAX,
                        "The repetition statement '{}' must follow a valid string or other pattern." )
                }

                // Make sure a closing brace is found.
                const char* end = __seek_marker_end( p, '}' );
                if ( NULL == end ) {
                    FUZZ_ERR_IN_CTX( FUZZ_ERROR_INVALID_SYNTAX,
                        "Pattern contains unclosed or empty repetition statement '{}'" );
                }

                // Character check. Limit commas to only one occurrence.
                int comma = 0;
                for ( const char* x = (p+1); x < end; x++ ) {
                    if (  ( (*x != ',') || (',' == *x && comma) ) && !isdigit( (int)*x )  ) {
                        FUZZ_ERR_IN_CTX( FUZZ_ERROR_INVALID_SYNTAX,
                            "Repetition '{}' statements can only contain digits and a single comma" );
                    } else if ( (',' == *x) )  comma = 1;
                }

                // A final outer check that the only char inside the brackets is NOT just a comma.
                if ( 1 == (end-1-p) && comma ) {
                    FUZZ_ERR_IN_CTX( FUZZ_ERROR_INVALID_SYNTAX,
                        "Repetition '{}' statements cannot consist of a single comma only" );
                }

                // Parse the field data and set the range information on the current block pointer.
                const char* t = strndup( p+1, (end-1)-p );
                int res = __bracket_parse_range( *((p_ctx->p_nest_tracker)+nest_level), t, comma );
                free( (void*)t );

                if ( 0 == res ) {
                    FUZZ_ERR_IN_CTX( FUZZ_ERROR_INVALID_SYNTAX,
                        "Repetition '{}' statement has an invalid range; please refer to the pattern documentation" );
                }

                // Set 'p' to end. It will increment to the character after '}' once the for-loop continues.
                p = end;
                break;
            }

            // ********** SUBSEQUENCE (NEST) **********
            case '(': {
                // Play nicely. 1 is added here since the FUZZ_.. def is NOT 0-based, it's 1-based :)
                if ( (nest_level+1) >= FUZZ_MAX_NESTING_COMPLEXITY ) {
                    // TODO: Fix the static string here!
                    FUZZ_ERR_IN_CTX( FUZZ_ERROR_TOO_MUCH_NESTING,
                        "Subsequence '()' statements can only be nested up to 5 times."
                        " Consider simplifying your pattern." );
                }

                // Find the next closing parenthesis according to the coming nest level.
                //   Essentially what this does is look ahead in the string to find the matching
                //   end of the opening nest, regardless of () nests between.
                size_t pres = (nest_level+1);
                const char* p_seek = (p+1);
                for ( ; (*p_seek) && pres > nest_level; p_seek++ )
                    pres += (  ((*p_seek == '(')*1) + ((*p_seek == ')')*-1)  );

                p_seek--;   // back out by 1

                // If the nest level didn't shift around properly
                if ( pres > nest_level ) {
                    FUZZ_ERR_IN_CTX( FUZZ_ERROR_INVALID_SYNTAX,
                        "Subsequence '()' statements are not closed properly." );
                }


                // Create the sub block and continue the necessary recursion.
                //   'sub' is essentially just a marker for 'ret', which points to it
                p_new_block = NEW_PATTERN_BLOCK;
                *((p_ctx->p_nest_tracker)+nest_level) = p_new_block;
                p_new_block->type = sub;

                size_t* p_ns = (size_t*)calloc( 1, sizeof(size_t) );
                *p_ns = nest_level;
                p_new_block->data = p_ns;

                (p_new_block->count).single = 1;
                (p_new_block->count).base = 1;
                List__add_node( p_seq, p_new_block );


                //// RECURSION: Prepare a new substring and parse it anew.
                char* p_sub = (char*)strndup( (p+1), (p_seek-1-p) );
printf( "SEEK: (%c) %s\n", *p_seek, p_sub );

                (p_ctx->nest_level)++;   // increase the nest level and enter
                List_t* p_pre = __parse_pattern( p_ctx, p_sub );
                (p_ctx->nest_level)--;   // ... and now leave the nest

                free( p_sub );

                // Make sure the returned list has some nodes. If not, problem.
                if ( !p_pre || List__get_count( p_pre ) < 1 ) {
                    char* const p_m = "Invalid, empty, or NULL branch inside Subsequence '()' statement.";
                    FUZZ_ERR_IN_CTX( FUZZ_ERROR_INVALID_SYNTAX, p_m );
                }

                // At this point, essentially linearly staple the output of the sub in memory.
                List_t* x = List__reverse( p_pre );
                for ( ListNode_t* y = List__get_head( x ); y; y = y->next )
                    List__add_node( p_seq, y->node );


                // Create the ret node and point it back to 'p_new_block'.
                fuzz_pattern_block_t* p_ret = NEW_PATTERN_BLOCK;
                //*(p_nest_tracker+nest_level) = p_new_block; //<- DO NOT
                p_ret->type = ret;

                size_t* p_sz = (size_t*)calloc( 1, sizeof(size_t) );
                *p_sz = List__get_count( x );   //how many nodes to wade backward through
                p_ret->data = p_sz;

                p_new_block = p_ret;


                // Finally, advance the pointer to the 'p_seek' location;
                //   presumably where the closing ')' was found.
                p = p_seek;
                break;
            }

            // ********** STATIC STRING **********
            default : {
                // Move 'p' along until it encounters a special char or the end.
                const char* start = p;
                while( *p ) {
//printf( "statstrch = %c\n", *p );
                    for ( int j = 0; special_chars[j]; j++ ) {
                        if ( *p == special_chars[j] ) {
//printf( "--- FOUND %c\n", *p );
                            p--;   //need to back-step by one
                            goto __static_string_stop;
                        }
                    }

                    p++;
                }

                // Code that reaches here either encountered the end of the pattern string
                //   or the iterator encountered a special character.
                __static_string_stop:
//printf( "plabel: %c\n", *p );
                    if ( p > start ) {
printf( "p1: %c\n", *p );
                        p_new_block = NEW_PATTERN_BLOCK;
                        *((p_ctx->p_nest_tracker)+nest_level) = p_new_block;
                        char* z = (char*)strndup(  start, ( p-start + (1*('{' != *(p+1))) )  );
                        p_new_block->type = string;
                        p_new_block->data = z;
                        (p_new_block->count).single = 1;
                        (p_new_block->count).base = 1;
                    }

                    // If the coming special char is a '{' we need to catalog the current static string (if one was defined)
                    //   and create another. Consider the sample string '1234{8}56' -- only '4' should be replicated 8 times.
                    if ( '{' == *(p+1) ) {
//printf( "p2: %c\n", *p );
                        // If coming special character is a bracket then two new blocks need to be created.
                        //   First, add the most recently-created node. Then update the pointer for its reuse further on.
                        if ( p_new_block )  List__add_node( p_seq, p_new_block );

                        // Create the next static character.
                        fuzz_pattern_block_t* p_pre_bracket_char = NEW_PATTERN_BLOCK;
                        p_new_block = p_pre_bracket_char;   //see above

                        unsigned char* z = (unsigned char*)calloc( 2, sizeof(unsigned char) );
                        z[0] = (unsigned char)(*p);
                        z[1] = (unsigned char)'\0';

                        p_pre_bracket_char->type = string;
                        p_pre_bracket_char->data = z;
                        // Do not set the range/count property here -- the repetition seq will do it.

                        // Set the new head of the nest.
                        *((p_ctx->p_nest_tracker)+nest_level) = p_pre_bracket_char;
                    }

               break;
            }
        }

        // Add the (maybe-)populated node onto the list and continue;
        if ( p_new_block )  List__add_node( p_seq, p_new_block );
        continue;

        __err_exit:
            if ( p_new_block )  free( p_new_block );
            //if ( p_nest_tracker ) free( p_nest_tracker );
            List__delete( p_seq );
            return NULL;
    }

    // Assign the list to the factory and return it.
printf( "List elements: %lu\n", List__get_count( p_seq ) );
    //if ( p_nest_tracker )  free( p_nest_tracker );

    return p_seq;
//    return __compress_List_to_factory( p_seq );
}



// Returns a 16-bit WORD between 1 and 65535 from a string.
static uint16_t __get_valid_uint16( const char* p_str ) {
    if ( NULL == p_str || strnlen( p_str, 6 ) > 5 )  return 0;

    for ( size_t i = 0; i < strnlen( p_str, 6 ); i++ )
        if ( !isdigit( (int)(p_str[i]) ) )  return 0;

    uint16_t val = (uint16_t)atoi( p_str );
    if ( val < 1 || val > UINT16_MAX )  return 0;

    return val;
}

// $1 - Block to set range; $2 - Range's inner text content; v$3 - >0 if a comma is present to split the range.
//   Once this method is called, all other syntactical checks are already completed; just parse.
static inline int __bracket_parse_range( fuzz_pattern_block_t* p_block, const char* p_content, int comma ) {
    if ( NULL == p_block )  return 0;

    if ( comma ) {
        // The block is NOT single and the range must be parsed from the given string.
        // ZERO is permitted here, and assumed when the left side of the comma is empty
        (p_block->count).single = 0;
        if ( ',' == *p_content ) {
            // value is from 0 to the second operand
            (p_block->count).base = 0;

            // The __get_valid_uint16 function essentially forces the number to be 1+, so this is safe.
            char* p_high = (char*)strdup( (p_content+1) );
            uint16_t high = __get_valid_uint16( p_high );
            free( p_high );

            if ( high )
                (p_block->count).high = high;
            else
                return 0;

        } else {
            // left side has a base value
            char* p_save;
            char* token;

            token = strtok_r( (char*)p_content, ",", &p_save );
            if ( NULL == token )  return 0;

            // Parse the low value, allowing an explicitly-given '0' value.
            uint16_t low = __get_valid_uint16( token );
            if ( (*token == '0') && !low )   //first char must be 0 AND atoi didn't get num
                (p_block->count).base = 0;
            else if ( low )
                (p_block->count).base = low;
            else
                return 0;

            // Now parse the high, if it's not present, allow up to the max of 65535.
            token = strtok_r( NULL, ",", &p_save );
            if ( NULL == token ) {
                (p_block->count).high = 65535;
            } else {
                uint16_t high = __get_valid_uint16( token );
                if ( high )
                    (p_block->count).high = high;
                else
                    return 0;
            }

            // Finally, ensure the high value exceeds the base one.
            if ( (p_block->count).high <= (p_block->count).base )  return 0;

        }
    } else {
        // Easy: just grab the integer, make sure it's in-range (1-65535), and mark the range as 'single'.
        (p_block->count).single = 1;

        uint16_t val = __get_valid_uint16( p_content );
        if ( val )
            (p_block->count).base = val;
        else
            return 0;
    }

    return 1;
}
