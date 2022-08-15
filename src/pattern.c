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
    // Context-dependent pattern error handler.
    fuzz_error_t* p_err;
    // Context-dependent list of varname-to-pattern-block associations.
};



// Some [important] local static functions.
static inline int __bracket_parse_range( fuzz_pattern_block_t* p_block, const char* p_content, int comma );
static inline int __range_parse_range( fuzz_pattern_block_t* const p_pattern_block, const char* const p_content );
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
    p_ctx->p_err = Error__new();

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
    x->count = ( List__get_count( p_list ) + 1 );   // +1 for 'end' node
    x->_list = p_list;

    // Create the new blob and start filling it out.
    unsigned char* scroll = (unsigned char*)calloc( x->count, sizeof(fuzz_pattern_block_t) );

    // Assign the node sequence to the created heap blob.
    x->node_seq = scroll;

    // Move data into the blob. Since the linked list implementation inserts the data like a stack,
    //   the list HEAD actually contains the final element. Therefore, the insertion into adjacent
    //   memory cells needs to happen in reverse.
    scroll += ( x->count * sizeof(fuzz_pattern_block_t) );

    // One final element on the blob needs to be an 'end' node so the generator can be CERTAIN
    //   it encountered a terminal point. Scroll backwards one element, set it, and add it.
    scroll -= sizeof(fuzz_pattern_block_t);
    fuzz_pattern_block_t* p_end = (fuzz_pattern_block_t*)scroll;
    p_end->type = end;
    p_end->data = NULL;   // count and label don't matter, just the 'end' type

    // Now insert from the list.
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

            case reference: {
                // The first char in the 'reference' label string should always be one of the three types:
                //   '@' - paste pre-generated content; '#' - get the LENGTH of the pre-gen content; '%' - regenerate/shuffle
                //   Additionally, to avoid confusion, '$' is a NAMED DECLARATION for a subseq and is not a block on its own.
                const char* p_reftype;
                switch ( *((const char*)(p->data)) ) {
                    case '@': {  p_reftype = "Paste pre-generated";  }
                    case '#': {  p_reftype = "Output the length of the";  }
                    case '%': {  p_reftype = "Shuffle or regenerate";  }
                    default : {  fprintf( fp_stream, "~~~~~ Misunderstood reference type. This is a problem!\n" ); continue;  }
                }

                fprintf( fp_stream, "%s stored subsequence with name '%s' (%s times)\n",
                    p_reftype, (const char*)((p->data)+1), p_range_str );
                break;
            }

            case string: {
                fprintf( fp_stream, "Output static string: '%s' (%s times)\n",
                    (const char*)(p->data), p_range_str );
                break;
            }

            case range: {
                const char* p_range_expl = 0;

                fprintf( fp_stream, "Output some character in the range %s (%s times)\n",
                    p_range_expl, p_range_str );
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

            case end: {
                fprintf( fp_stream, "!!! Stream end block (termination).\n" );
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
fuzz_factory_t* PatternFactory__new( const char* p_pattern_str, fuzz_error_t* p_err ) {
    if ( NULL == p_err )  p_err = Error__new();

    // Create a new pattern context.
    struct _fuzz_ctx_t* const p_ctx = __Context__new();
    // Free and override the default err_ctx if one's provided. This will always run
    //   but that's not really a big deal right now. ---TODO---
    if ( p_err ) {
        if ( p_ctx->p_err )  free( p_ctx->p_err );
        p_ctx->p_err = p_err;
    }

    // Parse the pattern and manufacture the factory (meta). MAGIC!
    List_t* p_the_sequence = __parse_pattern( p_ctx, p_pattern_str );
    fuzz_factory_t* p_ff = __compress_List_to_factory( p_the_sequence );

    // Discard the context since a pointer to the err ctx is available.
    __Context__delete( p_ctx );
    // If the factory returned OK and there are no warnings/errors, just destroy the err ctx.
    if ( p_ff && p_err && List__get_count( Error__get_fragments(p_err) ) < 1 )
        Error__delete( p_err );

    return p_ff;
}


// Define a set of functional or syntactically special characters.
static const char special_chars[] = "\\[{(<>)}]";
// Macro to register a fuzz error inside a fuzz_ctx (the pattern_parse func mainly).
// TODO: get rid of useless error codes (might need them later for stats?)
#define FUZZ_ERR_IN_CTX(errstr) { \
    Error__add( p_ctx->p_err, p_ctx->nest_level, (p-p_pattern), FUZZ_ERROR_INVALID_SYNTAX, errstr ); \
    goto __err_exit; \
}
#define BAD_CLOSING_CHAR(x) { \
    FUZZ_ERR_IN_CTX( "Unexpected '"x"'. Please escape this character ('\\"x"')" ); \
    break; \
}
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
printf( "READ: %02x\n", *p );
        fuzz_pattern_block_t* p_new_block = NULL;

//TODO: Spaghetti. Need to refactor quite a few things here once the application is operational.
        switch ( *p ) {

            // None of these will ever be hit directly unless the character is _actually_ unexpected.
            case '>': BAD_CLOSING_CHAR(">");
            case ']': BAD_CLOSING_CHAR("]");
            case '}': BAD_CLOSING_CHAR("}");
            case ')': BAD_CLOSING_CHAR(")");

            // ********** ESCAPES **********
            case '\\': {
                // This should be pretty simple: get the char being escaped and enter it as a static str block.
                char esc = *(p+1);
                char esclow = esc;
                char final;

                if ( !esc ) {  FUZZ_ERR_IN_CTX( "The escaped character could not be understood" );  }

                if ( (int)esc >= 0x41 && (int)esc <= 0x5A )  esclow += 0x20;   // upper to lower case

                // Get special types and convert them as needed.
                switch ( esclow ) {
                    case 'b' : {  final = (char)0x08; break;  }
                    case 't' : {  final = (char)0x09; break;  }
                    case 'n' : {  final = (char)0x0A; break;  }
                    case 'f' : {  final = (char)0x0C; break;  }
                    case 'r' : {  final = (char)0x0D; break;  }
                    case 's' : {  final = ' '; break;  }
                    default  : {  final = esc; break;  }
                }

                p_new_block = NEW_PATTERN_BLOCK;
                *((p_ctx->p_nest_tracker)+nest_level) = p_new_block;
                p_new_block->type = string;
                (p_new_block->count).single = 1;
                (p_new_block->count).base = 1;
                p_new_block->data = (char*)calloc( 2, sizeof(char) );
                *((char*)(p_new_block->data)) = final;
                *((char*)(p_new_block->data)+1) = '\0';

                p++;   //skips over the character being escaped since it's been handled
                break;
            }

            // ********** VARIABLES/REFERENCES **********
            case '<': {
                // Make sure a closing angle-bracket is found.
                const char* end = __seek_marker_end( p, '>' );
                if ( NULL == end ) {
                    FUZZ_ERR_IN_CTX( "Pattern contains unclosed or empty variable statement '<>'" );
                }

                // Spin up the new block.
                p_new_block = NEW_PATTERN_BLOCK;

                // The length of the inner content must be upper-case and consist of:
                //   + Operation specifier (1 char)
                //   + Upper-case Label (1-8 chars)
                // Format: <[$@#%]NAMENAME>
                const char* start = p+1;
                switch ( *start ) {

                    case '$': {
                        // When defining a NEW variable label, the previous node MUST be a 'ret' type, indicating
                        //   that the program had just finished parsing a subsequence.
                        if ( NULL == *((p_ctx->p_nest_tracker)+nest_level)
                            || sub != (*((p_ctx->p_nest_tracker)+nest_level))->type )
                        {
                            free( p_new_block );
                            FUZZ_ERR_IN_CTX( "Labels '<$...>' can only be applied to subsequence '()' mechanisms" );
                        }

                        

                        break;
                    }

                    case '@': {
                        break;
                    }

                    case '#': {
                        break;
                    }

                    case '%': {
                        break;
                    }

                    default : {
                        free( p_new_block );
                        FUZZ_ERR_IN_CTX( "Unrecognized variable '<>' statement type. Valid options are $, @, #, or %" );
                        break;
                    }
                }

                // Make sure the variable name referenced is 1-8 chars.
                start++;
                if ( (end-start) > 8 ) {
                    FUZZ_ERR_IN_CTX( "Variable '<>' names cannot be longer than 8 characters" );
                } else if ( end-start < 1 ) {
                    FUZZ_ERR_IN_CTX( "Variable '<>' names must be at least 1 character in length" );
                }

                // Set 'p' to end. It will increment to the next character after the for-loop continues.
                p = end;
                break;
            }

            // ********** RANGES **********
            case '[': {
                // Find the end of the bracket.
                const char* end = __seek_marker_end( p, ']' );
                if ( NULL == end ) {
                    FUZZ_ERR_IN_CTX( "Pattern contains unclosed or empty range '[]'" );
                }

                // Get the content between the brackets and parse it.
                const char* t = strndup( p+1, (end-1)-p );
                p_new_block = NEW_PATTERN_BLOCK;
                p_new_block->type = range;
                (p_new_block->count).single = 1;
                (p_new_block->count).base = 1;
                *((p_ctx->p_nest_tracker)+nest_level) = p_new_block;

                int res = __range_parse_range( p_new_block, t );
                free( (void*)t );

                if ( 0 == res ) {
                    FUZZ_ERR_IN_CTX( "Range '[]' statement syntax is not valid; please refer to the pattern documentation" );
                }

                // Set 'p' to end. It will increment to the character after ']' once the for-loop continues.
                p = end;
                break;
            }

            // ********** REPETITIONS **********
            case '{': {
                // The current block ptr cannot be NULL.
                if ( NULL == *((p_ctx->p_nest_tracker)+nest_level) ) {
                    FUZZ_ERR_IN_CTX( "The repetition statement '{}' must follow a valid string or other pattern" )
                }

                // Make sure a closing brace is found.
                const char* end = __seek_marker_end( p, '}' );
                if ( NULL == end ) {
                    FUZZ_ERR_IN_CTX( "Pattern contains unclosed or empty repetition statement '{}'" );
                }

                // Character check. Limit commas to only one occurrence.
                int comma = 0;
                for ( const char* x = (p+1); x < end; x++ ) {
                    if (  ( (*x != ',') || (',' == *x && comma) ) && !isdigit( (int)*x )  ) {
                        FUZZ_ERR_IN_CTX( "Repetition '{}' statements can only contain digits and a single comma" );
                    } else if ( (',' == *x) )  comma = 1;
                }

                // A final outer check that the only char inside the brackets is NOT just a comma.
                if ( 1 == (end-1-p) && comma ) {
                    FUZZ_ERR_IN_CTX( "Repetition '{}' statements cannot consist of a single comma only" );
                }

                // Parse the field data and set the range information on the current block pointer.
                const char* t = strndup( p+1, (end-1)-p );
                int res = __bracket_parse_range( *((p_ctx->p_nest_tracker)+nest_level), t, comma );
                free( (void*)t );

                if ( 0 == res ) {
                    FUZZ_ERR_IN_CTX( "Repetition '{}' statement has an invalid range; please refer to the pattern documentation" );
                }

                // Set 'p' to end. It will increment to the character after '}' once the for-loop continues.
                p = end;
                break;
            }

            // ********** SUBSEQUENCES (NESTS) **********
            case '(': {
                // Play nicely. 1 is added here since the FUZZ_.. def is NOT 0-based, it's 1-based :)
                if ( (nest_level+1) >= FUZZ_MAX_NESTING_COMPLEXITY ) {
                    // TODO: Fix the static string here!
                    FUZZ_ERR_IN_CTX( "Subsequence '()' statements can only be nested up to 5 times."
                        " Consider simplifying your pattern" );
                }

                // Find the next closing parenthesis according to the coming nest level.
                //   Essentially what this does is look ahead in the string to find the matching
                //   end of the opening nest, regardless of () nests between.
                size_t pres = (nest_level+1);
                const char* p_seek = (p+1);
                for ( ; (*p_seek) && pres > nest_level; p_seek++ ) {
                    pres += (  ((*p_seek == '(')*1) + ((*p_seek == ')')*-1)  );
                    if ( pres > FUZZ_MAX_NESTING_COMPLEXITY ) {
                         FUZZ_ERR_IN_CTX( "Subsequence '()' statements can only be nested up to 5 times."
                            " Consider simplifying your pattern" );
                    }
                }

                p_seek--;   // back out by 1

                // If the nest level didn't shift around properly
                if ( pres > nest_level ) {
                    FUZZ_ERR_IN_CTX( "Subsequence '()' statements are not closed properly" );
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
printf( "SUB: |%s|\n", p_sub );
                (p_ctx->nest_level)++;   // increase the nest level and enter
                List_t* p_pre = __parse_pattern( p_ctx, p_sub );
                (p_ctx->nest_level)--;   // ... and now leave the nest
                free( p_sub );

                // Make sure the returned list has some nodes. If not, problem.
                if ( !p_pre || List__get_count( p_pre ) < 1 ) {
                    FUZZ_ERR_IN_CTX( "Invalid, empty, or NULL branch inside Subsequence '()' statement" );
                }

                // At this point, essentially linearly staple the output of the sub in memory.
                List_t* x = List__reverse( p_pre );
                for ( ListNode_t* y = List__get_head( x ); y; y = y->next )
                    List__add_node( p_seq, y->node );


                // Create the ret node and point it back to 'p_new_block'.
                fuzz_pattern_block_t* p_ret = NEW_PATTERN_BLOCK;
                // *(p_nest_tracker+nest_level) = p_new_block; //<- DO NOT
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

            // ********** STATIC STRINGS **********
            default : {
                // Move 'p' along until it encounters a special char or the end.
                const char* start = p;

                while ( *p ) {
                    for ( int j = 0; special_chars[j]; j++ ) {
                        if ( *p == special_chars[j] ) {
                            p--;   // need to back-step by one ; TODO when outermost for-loop no long auto-incs 'p'
                            goto __static_str_break;
                        }
                    }
                    p++;
                }

                __static_str_break:
                // Rewind another character if there's more than 1 static str char; e.g. '123{8}45' vs. '1{4}'.
                //   Effectively, the next iteration of the switch-case will parse this lone-dupe itself.
                //   But if the static string that's incoming is only one character, this does it now.
                if ( (p-start) > 1 && ('{' == *(p+1)) )  p--;

                // Catalog the static string.
                p_new_block = NEW_PATTERN_BLOCK;
                *((p_ctx->p_nest_tracker)+nest_level) = p_new_block;
                char* z = (char*)strndup( start, (p-start+1) );
                p_new_block->type = string;
                p_new_block->data = z;
                (p_new_block->count).single = 1;
                (p_new_block->count).base = 1;

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
//printf( "List elements: %lu\n", List__get_count( p_seq ) );
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



// Parse content in a range between two square brackets. Valid formats look something like:
//   [0,12-17,128-255]
//   [35]
//   [^0-31,127-255]
// In all cases, the pattern searcher/parser here is going to seek the initial '^' for negation
//   as well as any commas which may indicate multiple ranges.
// TODO: Consider expanding the lexer to allow simple ascii character ranges, e.g. 'a-z'. Maybe...
// Params are: $1 - Pattern Block to fill; $2 - String to parse (between brackets)
static inline int __range_parse_range( fuzz_pattern_block_t* const p_pattern_block, const char* const p_content ) {
    if ( !p_pattern_block || !p_content )  return 0;

    return 1;
}
