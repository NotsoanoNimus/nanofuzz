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



// A ranging mechanism used in the pattern blocks to determine the amount of times, if set,
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
static inline void __bracket_parse_range( fuzz_pattern_block_t* p_block, const char* p_content, int comma );
static List_t* __parse_pattern( const struct _fuzz_ctx_t* p_ctx, const char* p_pattern );



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
static inline const struct _fuzz_ctx_t* __Context__new() {
    struct _fuzz_ctx_t* p_ctx = (struct _fuzz_ctx_t*)calloc( 1, sizeof(struct _fuzz_ctx_t) );

    p_ctx->p_nest_tracker = (fuzz_pattern_block_t**)calloc(
        FUZZ_MAX_NESTING_COMPLEXITY, sizeof(fuzz_pattern_block_t*) );
    p_ctx->nest_level = 0;

    return (const struct _fuzz_ctx_t*)p_ctx;
}

// Destroy a context. For now, this simply frees the context and tracker.
static void __Context__delete( const struct _fuzz_ctx_t* p ) {
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

    // Move data into the blob.
    ListNode_t* y = List__get_head( p_list );
    while ( NULL != y ) {
        memcpy( scroll, y->node, sizeof(fuzz_pattern_block_t) );
        scroll += sizeof(fuzz_pattern_block_t);
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

    // Iterate the factory nodes and explain each.
    for ( size_t i = 0; i < p_fact->count; i++ ) {

    }
}



// Build the fuzz factory. Since this is only intended to run as part of the
//   wind-up cycle, optimization is not an essential concern here.
fuzz_factory_t* PatternFactory__new( const char* p_pattern_str ) {
    clear_fuzz_error();

    const struct _fuzz_ctx_t* p_ctx = __Context__new();
    List_t* p_the_sequence = __parse_pattern( p_ctx, p_pattern_str );
    __Context__delete( p_ctx );

    return __compress_List_to_factory( p_the_sequence );
}


// Define a set of functional or syntactically special characters.
static const char special_chars[] = "$\\[{(";
// Internal, recursive pattern parsing. This is called recursively generally
//   when the nesting level () changes.
static List_t* __parse_pattern( const struct _fuzz_ctx_t* p_ctx, const char* p_pattern ) {
    size_t len, nest_level;
    const char* p;
    List_t* p_seq;
    fuzz_pattern_block_t** p_nest_tracker;

    len = strnlen( p_pattern, (FUZZ_MAX_PATTERN_LENGTH-1) );
    nest_level = p_ctx->nest_level;

    p = p_pattern;
    p_seq = List__new( FUZZ_MAX_PATTERN_LENGTH );

    p_nest_tracker = p_ctx->p_nest_tracker;

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


            case '{': {
                // The current block ptr cannot be NULL.
                if ( NULL == *p_nest_tracker ) {
                    set_fuzz_error( FUZZ_ERROR_INVALID_SYNTAX,
                        "The repetition statement '{}' must follow a valid string or other pattern." );
                    goto __err_exit;
                }

                // Make sure a closing brace is found.
                const char* end = __seek_marker_end( p, '}' );
                if ( NULL == end ) {
                    set_fuzz_error( FUZZ_ERROR_INVALID_SYNTAX,
                        "Pattern contains unclosed or empty repetition statement '{}'" );
                    goto __err_exit;
                }

                // Character check. Limit commas to only one occurrence.
                int comma = 0;
                for ( const char* x = (p+1); x < end; x++ ) {
                    if (  ( (*x != ',') || (',' == *x && comma) ) && !isdigit( (int)*x )  ) {
                        set_fuzz_error( FUZZ_ERROR_INVALID_SYNTAX,
                            "Repetition '{}' statements can only contain digits and a single comma" );
                        goto __err_exit;
                    } else if ( (',' == *x) )  comma = 1;
                }

                // A final outer check that the only char inside the brackets is NOT just a comma.
                if ( 1 == (end-1-p) && comma ) {
                    set_fuzz_error( FUZZ_ERROR_INVALID_SYNTAX,
                        "Repetition '{}' statements cannot consist of a single comma only" );
                    goto __err_exit;
                }

                // Parse the field data and set the range information on the current block pointer.
                const char* t = strndup( p+1, (end-1)-p );
                __bracket_parse_range( *p_nest_tracker, t, comma );
                free( (void*)t );

                // Set 'p' to end. It will increment to the character after '}' once the for-loop continues.
                p = end;
                break;
            }


            case '(':
                // Find the matching ')' and if found: trim, increment the nest level, and recurse.
                if ( nest_level >= FUZZ_MAX_NESTING_COMPLEXITY ) {
                    // TODO: Fix the static string here!
                    set_fuzz_error( FUZZ_ERROR_TOO_MUCH_NESTING,
                        "Subsequence '()' statements can only be nested up to 5 times. Consider simplifying your pattern." );
                    goto __err_exit;
                }
                break;


            default : {
                p_new_block = NEW_PATTERN_BLOCK;

                int bracket = 0;
                // Move 'p' along until it encounters a special char or the end.
                const char* start = p;
                while( *p ) {
printf( "statstrch = %c\n", *p );
                    for ( int j = 0; special_chars[j]; j++ ) {
                        if ( *p == special_chars[j] ) {
printf( "--- FOUND %c\n", *p );
                            // If the coming special char is a '{' we need to back the pointer out just one more step.
                            //   Consider the sample string '1234{8}56' -- only '4' should be replicated 8 times here.
                            if ( '{' == *p )  bracket = 1;
                            p--;   //need to back-step by one
                            goto __static_string_stop;
                        }
                    }

                    p++;
                }

                // Code that reaches here either encountered the end of the pattern string
                //   or the iterator encountered a special character.
                __static_string_stop:
                    if ( bracket )  p--;
                    if ( p > start ) {
                        *(p_nest_tracker+nest_level) = p_new_block;
                        char* z = (char*)strndup( start, (p-start) );
                        p_new_block->type = string;
                        p_new_block->data = z;
                    } else  free ( p_new_block );
                    if ( bracket ) {
                        // If coming special character is a bracket then two new blocks need to be created.
                        //   First, add the most recently-created node. Then update the pointer for its reuse further on.
                        List__add_node( p_seq, p_new_block );

                        p++;   //step forward again to the pre-bracket char

                        // Create the next static character.
                        fuzz_pattern_block_t* p_pre_bracket_char = NEW_PATTERN_BLOCK;
                        p_new_block = p_pre_bracket_char;   //see above

                        unsigned char* z = (unsigned char*)calloc( 2, sizeof(unsigned char) );
                        z[0] = (unsigned char)(*p);
                        z[1] = (unsigned char)'\0';

                        p_pre_bracket_char->type = string;
                        p_pre_bracket_char->data = z;

                        // Set the new head of the nest.
                        *(p_nest_tracker+nest_level) = p_pre_bracket_char;
                    }

               break;
            }
        }

        // Add the (hopefully-)populated node onto the list and continue;
        List__add_node( p_seq, p_new_block );
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



// $1 - Block to set range; $2 - Range's inner text content; v$3 - >0 if a comma is present to split the range.
static inline void __bracket_parse_range( fuzz_pattern_block_t* p_block, const char* p_content, int comma ) {

}
