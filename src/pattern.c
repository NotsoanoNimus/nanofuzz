/*
 * pattern.h
 *
 * Pattern syntax parsing.
 *
 */

#include "pattern.h"
#include "generator.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>



// Represents a single contiguous block of memory which all of the block items get joined into.
//   This is what nanofuzz will actually use in generating content.
struct _fuzz_factory_t {
    // Pointer to the blob of nodes...
    void* node_seq;
    // ... of size count, each = sizeof(fuzz_pattern_block_t)
    size_t count;
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

// A sub-structure which holds reference/variable information.
struct _fuzz_reference_t {
    // The sub-type for the reference.
    reference_type type;
    // This label is the name of the variable assigned to the block when type is
    //   a declaration, the reference name otherwise.
    const char label[FUZZ_MAX_PATTERN_LABEL_NAME_LENGTH];
    // The generator context to use when shuffling the variable or initializing it.
    //   Since this stands on its own apart from the primary factory and generator,
    //   a special process is required to 'free' this when the outer factory is
    //   being deleted and this instance's type is a 'declaration'.
    fuzz_gen_ctx_t* p_gen_ctx;
};



// Some [important] local static functions.
static inline int __bracket_parse_range( fuzz_pattern_block_t* const p_block, const char* p_content, int comma );
static inline int __range_parse_range( fuzz_pattern_block_t* const p_pattern_block, const char** pp_content );
static List_t* __parse_pattern( struct _fuzz_ctx_t* const p_ctx, const char* p_pattern );



// Seek the closest closing marker character in a pattern string.
//   Returns NULL if the target character isn't found, or if the target is only ONE char ahead
//   of the start of the input string.
static const char* __seek_marker_end( const char* start, char const target ) {
    const char* end = start;
    while( *(++end) ) {
        if ( '\\' == *end && (end+1) <= (start+strlen(start)) )  {
            end++;
            continue;   // always skip escaped chars
        }
        if ( *end == target ) {
            if ( (end-start) > 1 )  return end;
            else break;
        }
    }
    return NULL;
}



// Get the mapped value of something which has been escaped in an input string.
static char __escape_to_value( char esc ) {
    char final;

    if ( (int)esc >= 0x41 && (int)esc <= 0x5A )  esc += 0x20;   // upper to lower case

    // Get special types and convert them as needed.
    switch ( esc ) {
        case 'a' : {  final = (char)0x07; break;  }
        case 'b' : {  final = (char)0x08; break;  }
        case 't' : {  final = (char)0x09; break;  }
        case 'n' : {  final = (char)0x0A; break;  }
        case 'v' : {  final = (char)0x0B; break;  }
        case 'f' : {  final = (char)0x0C; break;  }
        case 'r' : {  final = (char)0x0D; break;  }
        case 's' : {  final = ' '; break;  }
        default  : {  final = esc; break;  }
    }

    return final;
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

// Destroy a context. This frees the context, error handler (if no errors), & tracker.
static inline void __Context__delete( struct _fuzz_ctx_t* const p ) {
    if ( p ) {
        if ( p->p_nest_tracker )  free( p->p_nest_tracker );

        if (  p->p_err && 0 == Error__has_error( p->p_err )  )
            Error__delete( p->p_err );

        free( (void*)p );
    }
}



// Compress the contents of a pattern block list into a single calloc and set it in the factory.
static fuzz_factory_t* __compress_List_to_factory( List_t* p_list ) {
    if ( NULL == p_list || List__get_count( p_list ) < 1 )  return NULL;

    // Fetch the list items count, calloc, set each cell, and create the factory.
    fuzz_factory_t* x = (fuzz_factory_t*)calloc( 1, sizeof(fuzz_factory_t) );
    x->count = ( List__get_count( p_list ) + 1 );   // +1 for 'end' node

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

    // Now insert from the list. This follows the list node pointer and raw-ly copies data.
    //   Effectively, this means the list can be wholly discarded once this is done.
    ListNode_t* y = List__get_head( p_list );
    while ( NULL != y && scroll >= (unsigned char*)(x->node_seq) ) {
        scroll -= sizeof(fuzz_pattern_block_t);
        memcpy( scroll, y->node, sizeof(fuzz_pattern_block_t) );
        y = y->next;
    }

    // Return the built factory.
    List__delete( p_list );
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


// Get the attached factory count of blobbed pattern blocks.
size_t PatternFactory__get_count( fuzz_factory_t* p_fact ) {
    return p_fact->count;
}



// Frees space used by a pattern factory by destroying it and its nodes' datas from the heap.
void PatternFactory__delete( fuzz_factory_t* p_fact ) {
    if ( NULL == p_fact )  return;

    // We assume that any nodes/blocks in the node sequence have free-able memory in their
    //   data voidptr, so long as the value != null (such as 'end' blocks).
    fuzz_pattern_block_t* p_base_block = (fuzz_pattern_block_t*)(p_fact->node_seq);
    for ( size_t i = 0; i < p_fact->count; i++ ) {
        fuzz_pattern_block_t* x = (p_base_block + i);

        if ( NULL != x && x->data ) {
            // However, there is one exception for ref.ref_declaration blocks specifically,
            //   since the sub-generator-context needs to be nuked.
            if ( reference == x->type ) {

                fuzz_reference_t* p_ref = (fuzz_reference_t*)(x->data);
                if ( ref_declaration == p_ref->type && p_ref->p_gen_ctx )
                    Generator__delete_context( p_ref->p_gen_ctx );

            }

            free( x->data );
        }
    }

    // Free the pattern_block blob.
    if ( NULL != p_fact->node_seq )  free( p_fact->node_seq );

    // And free the factory itself.
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
                // The message will change based on the type of reference.
                //   NOTE: ref_declaration types will never show up here, since they don't
                //         create pattern blocks to use and this is an explanation thereof.
                const char* p_reftype;
                fuzz_reference_t* p_ref = (fuzz_reference_t*)(p->data);

                switch ( p_ref->type ) {
                    case ref_reference: {  p_reftype = "Paste pre-generated"; break;  }
                    case ref_count    : {  p_reftype = "Output the length of the"; break;  }
                    case ref_shuffle  : {  p_reftype = "Regenerate"; break;  }
                    default : {
                        fprintf( fp_stream, "~~~~~ Misunderstood reference type. This is a problem!\n" );
                        goto __explain_ref_unknown;
                    }
                }

                fprintf( fp_stream, "%s stored subsequence with name '%s' (%s times)\n",
                    p_reftype, p_ref->label, p_range_str );

                __explain_ref_unknown:
                    break;
            }

            case string: {
                fprintf( fp_stream, "Output static string: '%s' (%s times)\n",
                    (const char*)(p->data), p_range_str );
                break;
            }

            case range: {
                // Ranges have a touch of complexity about them to explain since they're dynamic mechanisms.
                fuzz_range_t* p_range = (fuzz_range_t*)(p->data);
                if ( !p_range || !(p_range->amount) ) {
                    fprintf( fp_stream, "~~~~~ Misunderstood or empty range. Problem!\n" );
                    break;
                }

                char* p_range_expl = (char*)calloc( p_range->amount, 13 ); //13 chars each x the max amount of rep objs
                char* scroll = p_range_expl;

                for ( size_t i = 0; i < p_range->amount; i++ ) {
                    snprintf( scroll, 13, "%3d to %3d, ", (p_range->fragments[i]).base, (p_range->fragments[i]).high );
                    scroll += 12;
                }
                *(scroll - 2) = '\0';

                fprintf( fp_stream, "Output some character in the range [%s] (%s times)\n",
                    p_range_expl, p_range_str );

                free( (void*)p_range_expl );
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
fuzz_factory_t* PatternFactory__new( const char* p_pattern_str, fuzz_error_t** pp_err ) {

    // Create a new pattern context.
    struct _fuzz_ctx_t* const p_ctx = __Context__new();

    // If a pointer to capture the error handler is given, point it properly.
    if ( pp_err && NULL == *pp_err )
        *pp_err = p_ctx->p_err;

    // Parse the pattern and manufacture the factory (meta). MAGIC!
    List_t* p_the_sequence = __parse_pattern( p_ctx, p_pattern_str );
    fuzz_factory_t* p_ff = __compress_List_to_factory( p_the_sequence );

    // Discard the context since a pointer to the err ctx is available.
    __Context__delete( p_ctx );

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
//printf( "Parsing %lu bytes of input.\n", len );
    for ( ; p < (p_pattern+len) && (*p); p++ ) {
//printf( "READ: %02x\n", *p );
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
                char final;

                if ( !esc ) {  FUZZ_ERR_IN_CTX( "The escaped character could not be understood" );  }
                final = __escape_to_value( esc );

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

                int res = __range_parse_range( p_new_block, &t );
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
                for ( ; pres > nest_level && p_seek < (p_pattern+len) && (*p_seek); p_seek++ ) {
                    if ( '\\' == *p_seek ) {
                        if ( (p_seek+1) > (p_pattern+len) ) {
                            FUZZ_ERR_IN_CTX( "Subsequence '()' mechanism contains an invalid escape" );
                        } else {
                            p_seek++;   //ignore the escaped character
                            continue;
                        }
                    }

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

                size_t* p_lvl = (size_t*)calloc( 1, sizeof(size_t) );
                *p_lvl = nest_level;
                p_new_block->data = p_lvl;

                (p_new_block->count).single = 1;
                (p_new_block->count).base = 1;
                List__add_node( p_seq, p_new_block );
                p_new_block = NULL;   //this should be done to prevent double-frees


                //// RECURSION: Prepare a new substring and parse it anew.
                char* p_sub = (char*)strndup( (p+1), (p_seek-1-p) );
//printf( "SUB: |%s|\n", p_sub );
                (p_ctx->nest_level)++;   // increase the nest level and enter
                List_t* p_pre = __parse_pattern( p_ctx, p_sub );
                (p_ctx->nest_level)--;   // ... and now leave the nest
                free( p_sub );

                // Make sure the returned list has some nodes. If not, problem.
                if ( !p_pre || List__get_count( p_pre ) < 1 ) {
                    FUZZ_ERR_IN_CTX( "Invalid, empty, or NULL branch inside Subsequence '()' statement" );
                }

                // At this point, essentially linearly staple the output of the sub in memory.
                //   Since this list is only used for reversing, be sure to delete it later.
                List_t* x = List__reverse( p_pre );
                for ( ListNode_t* y = List__get_head( x ); y; y = y->next )
                    List__add_node( p_seq, y->node );

                size_t rev_size = List__get_count( x );
                List__clear( x );
                free( x );

                // Create the ret node and point it back to 'p_new_block'.
                fuzz_pattern_block_t* p_ret = NEW_PATTERN_BLOCK;
                // *(p_nest_tracker+nest_level) = p_new_block; //<- DO NOT
                p_ret->type = ret;

                size_t* p_sz = (size_t*)calloc( 1, sizeof(size_t) );
                *p_sz = rev_size;   //how many nodes to wade backward through
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
                if ( (p-start) > 0 && p < (p_pattern+len) && ('{' == *(p+1)) )  p--;

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
        if ( p_new_block )
            List__add_node( p_seq, p_new_block );

        continue;


        __err_exit:
            if ( p_new_block )  free( p_new_block );

            // Even on crashes, collate the list so its contents can be deleted properly.
            fuzz_factory_t* x = __compress_List_to_factory( p_seq );
            PatternFactory__delete( x );

            return NULL;
    }

    // Return the linked list representing the sequence of generation.
    if ( List__get_count( p_seq ) > 0 ) {
        return p_seq;
    } else {
        List__delete( p_seq );
        return NULL;
    }
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
static inline int __bracket_parse_range( fuzz_pattern_block_t* const p_block, const char* p_content, int comma ) {
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



// Helper method.
static int __range_parse_token( const char* p_token, uint8_t* char_code ) {

    // Edge cases for "\-".
    if ( '\\' == *p_token && 1 == strlen(p_token) ) {
        *char_code = (uint8_t)'-';

    // Escaped commas. TODO: necessary??
    } else if ( 0 == strcmp( p_token, "\\," ) ) {
        *char_code = ',';

    // Some type of escape character or code, by itself or of one of the three bases.
    } else if ( '\\' == *p_token ) {
        // TODO: Cleanup
        if ( 'x' == (*(p_token+1) | 32) ) {
            errno = 0;
            *char_code = (uint8_t)(strtol((p_token+2),NULL,16) & (long int)0xFF);
            if ( errno )  return 0;
        } else if ( 'd' == (*(p_token+1) | 32) ) {
            errno = 0;
            *char_code = (uint8_t)(strtol((p_token+2),NULL,10) & (long int)0xFF);
            if ( errno )  return 0;
        } else if ( 'o' == (*(p_token+1) | 32) ) {
            errno = 0;
            *char_code = (uint8_t)(strtol((p_token+2),NULL,8) & (long int)0xFF);
            if ( errno )  return 0;
        } else {
            *char_code = __escape_to_value( *(p_token+1) );
        }

    // Single character.
    } else if ( 1 == strlen(p_token) ) {
        *char_code = (uint8_t)(*p_token);

    } else  return 0;

    // OK.
    return 1;
}

// Parse content in a range between two square brackets. Valid formats look something like:
//   [0,12-17,128-255]
//   [35]
//   [^0-31,127-255]
// In all cases, the pattern searcher/parser here is going to seek the initial '^' for negation
//   as well as any commas which may indicate multiple ranges.
// TODO: Consider expanding the lexer to allow simple ascii character ranges, e.g. 'a-z'. Maybe...
// Another TODO: Add the context here, so errors can be appeneded and made more specific.
// Params are: $1 - Pattern Block to fill; $2 - String to parse (between brackets)
static inline int __range_parse_range( fuzz_pattern_block_t* const p_pattern_block, const char** pp_content ) {
    if ( !p_pattern_block || !pp_content || !(*pp_content) || strnlen(*pp_content,3) < 1 )  return 0;

    const char* p_content = *pp_content;


    // Set the flag if true and advance.
    int negated = ('^' == *p_content);
    if ( negated ) {
        p_content++;
        if ( strnlen(p_content,3) < 1 )  return 0;   //another check
    }

    // Initial syntax check.
    int was_grammar = 1; // whether the previous character is grammatical or a number
    // ^ set to 1 by default to prevent ranges from starting with a grammatical character
    int is_grammar = 0; // current character
    for ( const char* x = p_content; (*x); x++ ) {
        is_grammar = (',' == *x || '-' == *x);

        if ( '\\' == *x ) {
            if ( !(*(x+1)) )  return 0;   //paranoia; shouldn't really be possible but w/e
            x++;
            was_grammar = 0;   //allows escaping grammatical chars , and -
            continue;
        }

        if ( !(*x) || ( was_grammar && is_grammar ) )  return 0;

        was_grammar = is_grammar;
    }

    // Commas or dashes cannot be the first or the last characters under any circumstances
    if ( is_grammar )  return 0;

    // IMPORTANT: Convert any escaped commas to their hex equivalents.
    const char* t = p_content;
    size_t occurs = 0;
    while ( (t+1) < (p_content+strlen(p_content)) ) {
        if ( ('\\' == *t) && (',' == *(t+1)) )
            occurs++;
        t++;
    }

    // However many times the string occurs, '\,' must convert to '\x2C' (2 => 4).
    //   Formula would then be newstrlen = strlen + (2*occurs)
    if ( occurs ) {
        char* p_new = (char*)calloc( (strlen(p_content)+(2*occurs)+1), sizeof(char) );
        char* p_new_save = p_new;

        const char* p_x = p_content;
        const char* p_save_x = p_content;

        while ( p_x < (p_content+strlen(p_content)) && (*p_x) ) {
            if ( '\\' == *p_x && ',' == *(p_x+1) ) {

                if ( (p_x - p_save_x) > 0 ) {
                    snprintf( p_new_save, (p_x - p_save_x + 1), "%s", p_save_x );
                    p_new_save += (p_x - p_save_x);
                }

                snprintf( p_new_save, (4 + 1), "\\x2C" );
                p_new_save += 4;

                p_x += 2;
                p_save_x = p_x;

            } else {
                p_x++;
            }
        }

        // Append any remaining content as applicable.
        if ( (p_x - p_save_x) > 0 )
            sprintf( p_new_save, "%s", p_save_x );

        p_new[(strlen(p_content)+(2*occurs))] = '\0';   // paranoia
        free( (void*)p_content );
        *pp_content = p_content = p_new;
    }
printf( "CURRENT: |%s|\n", p_content );


    // --- By this point the content should be grammatically verified.
    // Create the range and populate it.
    fuzz_range_t* p_range = (fuzz_range_t*)calloc( 1, sizeof(fuzz_range_t) );
    fuzz_repetition_t frag = {0,0,0};

    char *p_sep_save, *p_range_save, *sep_token, *range_token;
    size_t amount = 0;

    sep_token = strtok_r( (char*)p_content, ",", &p_sep_save );


    // Iterate through each range, one loop per set of them, and enter them into the struct.
    do {

        if ( strlen(sep_token) < 1 )  continue;

        memset( &frag, 0, sizeof(fuzz_repetition_t) );

        range_token = NULL;
        p_range_save = NULL;

        amount++;   // inc and check
        if ( amount > FUZZ_MAX_PATTERN_RANGE_FRAGMENTS )
            goto __range_parse_error;

printf("SEP: |%s|\n", sep_token );

        range_token = strtok_r( sep_token, "-", &p_range_save );
        if ( strlen(range_token) < 1 )  goto __range_parse_error;

        // Get the first character.
        uint8_t low = 0;
        if ( 0 == strcmp(sep_token, "\\--") ) {
            low = (uint8_t)'-';
        } else if ( !__range_parse_token( range_token, &low ) ) {
            goto __range_parse_error;
        }
printf("-- LOW: |%d|\n", low );
        frag.base = low;

        // Parse the high value (if present), ensuring it's in-bounds and greater than low.
        if (  NULL != (range_token = strtok_r( NULL, "-", &p_range_save ))  ) {
            uint8_t high = 0;
            if ( !__range_parse_token( range_token, &high ) ) {
                goto __range_parse_error;
            }

            if ( high > low && high < 256 ) {
                frag.single = 0;
                frag.high = high;
            } else {
                goto __range_parse_error;
            }
printf("-- HIGH: |%d|\n", high );

            // Cannot have more than two tokens found inside a single separated range.
            if (  NULL != (range_token = strtok_r( NULL, "-", &p_range_save ))  ) {
                goto __range_parse_error;
            }

        } else {
            // Mark the block 'single' and set 'high' to 'low' too for the below comparison.
printf("-- SINGLE.\n" );
            frag.single = 1;
            frag.high = frag.base;
        }

        // Finally, ranges should not step on each other or overlap otherwise. [1-2,3-4,5-6] is
        //   perfectly valid if someone is masochistic enough, but not [1-2,2-3,3-4,...]
        for ( size_t i = 0; i < (amount-1); i++ ) {
            fuzz_repetition_t* p_shard = &(p_range->fragments[i]);
            if ( !p_shard )  continue;
printf( "-- SHARD: |%d|-|%d|\n\tFRAG: |%d|-|%d|\n", p_shard->base, p_shard->high, frag.base, frag.high );

            if (
                   ( p_shard->single && frag.single && p_shard->base == frag.base )
                || ( p_shard->base <= frag.high && frag.base <= p_shard->high )
            ) {  goto __range_parse_error;  }
        }

        // Store the fragment and move to the next range fragment.
        memcpy(
            (  ((fuzz_repetition_t*)&(p_range->fragments)) + amount - 1  ),
            &frag,
            sizeof(fuzz_repetition_t)
        );

    } while (  NULL != (sep_token = strtok_r( NULL, ",", &p_sep_save ))  );


    // If the entire range is being negated, then each valid fragment must be iterated.
    if ( negated ) {
        // Order the elements. They're already limited to not overlap so use selection sorting.
        size_t i, j, min_idx;
        for ( i = 0; i < (amount-1); i++ ) {
            min_idx = i;
            for ( j = i+1; j < amount; j++ ) {
                // --- if ( frag[j].base < frag[min_idx].base )
                if ( p_range->fragments[j].base < p_range->fragments[min_idx].base )
                    min_idx = j;
            }

            // Simply swapping stuff around.
            // --- obj = frag[min_idx]
            fuzz_repetition_t obj = p_range->fragments[min_idx];
            // --- frag[min_idx] = frag[i]
            p_range->fragments[min_idx] = p_range->fragments[i];
            // --- frag[i] = obj
            p_range->fragments[i] = obj;
        }

        // Now create the inverse of the sequence.
        fuzz_repetition_t* p_inv = (fuzz_repetition_t*)calloc(
            FUZZ_MAX_PATTERN_RANGE_FRAGMENTS, sizeof(fuzz_repetition_t) );

        // Slide from left-to-right on the ordered nodes and get the gaps.
        fuzz_repetition_t *p, *prev, *p_new;
        size_t new_amount;
        for (
            new_amount = 0,
                prev = NULL,
                p_new = p_inv,
                p = &(p_range->fragments[0]);

            p < (((fuzz_repetition_t*)&(p_range->fragments[0])) + amount);

            prev = p,
                p++
        ) {

            // Don't do anything if the base char is 0.
            if ( 0 == p->base )  continue;
            // If this block's base is equal to prev's high +1, it's a sequential list ([^1,2,3,...]).
            else if ( prev && p->base == ((prev->high)+1) )  continue;

            // Bounds check.
            if ( (p_new - p_inv) >= (FUZZ_MAX_PATTERN_RANGE_FRAGMENTS * sizeof(fuzz_repetition_t)) )
                goto __range_parse_error;

            // Add the new object details to the slow and increment counters/pointers.
            p_new->base = (prev ? (prev->high + 1) : 0);
            p_new->high = ((p->base > 1) ? (p->base - 1) : 0);
            p_new->single = (p_new->base == p_new->high);

            p_new++;
            new_amount++;
        }

        // If the final node was not capped at 255, add the last bit.
        p--;
        if ( 255 != p->high ) {
            if ( (p_new - p_inv) >= (FUZZ_MAX_PATTERN_RANGE_FRAGMENTS * sizeof(fuzz_repetition_t)) )
                goto __range_parse_error;

            p_new->base = (p->high + 1);
            p_new->high = 255;
            p_new->single = (255 == p_new->base);
            new_amount++;
        }

        // Set the new amount, copy the new set, and clean up.
        amount = new_amount;
        memcpy( &(p_range->fragments[0]), p_inv, (new_amount*sizeof(fuzz_repetition_t)) );
        free( (void*)p_inv );
    }


    // Set the amount. This should be it for the range.
    if ( amount <= 0 )  goto __range_parse_error;
    p_range->amount = amount;
printf( "+++ GOT '%lu' RANGES.\n", amount );
for ( size_t i = 0; i < amount; i++ ) {
    fuzz_repetition_t* p_shard = &(p_range->fragments[i]);
    if ( !p_shard )  continue;
    printf( "-- SHARD: (%d) |%d|-|%d|\n", p_shard->single, p_shard->base, p_shard->high );
}

    // Assign the range to the pattern block's data and return "OK".
    p_pattern_block->data = (void*)p_range;
    return 1;


    // Called when there's a problem beyond the range calloc for any reason.
    __range_parse_error:
        if ( p_range )  free( (void*)p_range );
        return 0;
}
