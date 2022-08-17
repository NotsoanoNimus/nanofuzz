/*
 * fuzz_error.h
 *
 * Maintains and tracks various project and module error states
 *   for the fuzzer's pattern parser and generator.
 *
 */

#include "fuzz_error.h"

#include <stdlib.h>
#include <string.h>



// Define a simple wrapper type which holds a linked list of internal 'fragment' objects.
//   Each fragment represents a different error in a sort of pseudo-stack-trace.
typedef struct _fuzz_error_t {
    List_t* p_fragments;
} fuzz_error_t;

// A fragment is a pairing of a string and its representative error type.
struct _fuzz_error_fragment_t {
    fuzz_error_code err_code;
    char* p_msg;
};



// Gets whether the list actually has any errors by checking the length of the err list.
int Error__has_error( fuzz_error_t* p_err ) {
    return ( p_err && p_err->p_fragments && List__get_count( p_err->p_fragments ) > 0 );
}


// This is a _deep_ free on the Array List of error information.
void Error__delete( fuzz_error_t* p_err ) {
    if ( p_err ) {
        if ( p_err->p_fragments ) {
            ListNode_t* x = List__get_head( p_err->p_fragments );
            while ( NULL != x ) {
                if ( x->node ) {
                    if ( ((struct _fuzz_error_fragment_t*)(x->node))->p_msg ) {
                        free( ((struct _fuzz_error_fragment_t*)(x->node))->p_msg );
                    }
                    free( x->node );
                }
                x = x->next;
            }
            // Don't do a delete here (the deep delete happens above(^)); just clear node-set.
            List__clear( p_err->p_fragments );
            free( p_err->p_fragments );
        }
        free( p_err );
    }
}


void Error__print( fuzz_error_t* p_err, FILE* fp_to ) {
    if ( NULL == fp_to )  fp_to = stdout;

    if (  0 != Error__has_error( p_err )  ) {
        if ( NULL != p_err && NULL != p_err->p_fragments ) {
            fprintf( fp_to, "\n[FUZZ PATTERN ERROR: TRACE] Most Recent First\n" );

            p_err->p_fragments = List__reverse( p_err->p_fragments );

            ListNode_t* x = List__get_head( p_err->p_fragments );
            while ( NULL != x ) {
                fprintf( fp_to, "\t%s\n", ((struct _fuzz_error_fragment_t*)(x->node))->p_msg );
                x = x->next;
            }

            fprintf( fp_to, "\n\n" );

        } else  fprintf( fp_to, "\n[FUZZER ERROR] Unspecified problem.\n\n" );
    } else fprintf( fp_to, "\nNo errors were found.\n\n" );

    // Wipe away the error details after printing.
    Error__delete( p_err );
}


// Create a new error context/list.
fuzz_error_t* Error__new() {
    fuzz_error_t* p_err = (fuzz_error_t*)calloc( 1, sizeof(fuzz_error_t) );
    p_err->p_fragments = List__new( FUZZ_ERROR_MAX_NODES );

    return p_err;
}


// Adds onto a pattern context's error trace.
void Error__add( fuzz_error_t* p_err, size_t nest_level,
    size_t pointer_loc, fuzz_error_code code, const char* p_msg )
{
    // Init if necessary.
    if ( NULL == p_err )  p_err = Error__new();

    // Don't do anything if the pseudo-stack-trace seems to be overflowing.
    if ( List__get_count( p_err->p_fragments ) >= FUZZ_ERROR_MAX_NODES )  return;

    // Allocate a new fragment to hold the error details.
    struct _fuzz_error_fragment_t* p_frag =
        (struct _fuzz_error_fragment_t*)calloc( 1, sizeof(struct _fuzz_error_fragment_t) );
    p_frag->err_code = code;
    p_frag->p_msg = strndup( p_msg, (FUZZ_ERROR_MAX_STRLEN-1) );

    // gross TODO
    // Account for the maximum length of the static string, plus some extra possible integer
    //   spacing (up to: 14 for Index and 4 for Err), then also add on the message length.
    char* static_err = "[Err 1234] [Nest 1] [Index 12345678901234] ";
    char* p = (char*)calloc( (1+strlen(static_err)+strlen(p_msg)), sizeof(char) );
    snprintf( p, (strlen(static_err)+strlen(p_msg)), "[Err %2u] [Nest %lu] [Index %3lu] %s",
        code, nest_level, pointer_loc, p_msg );
    *(p+strlen(static_err)+strlen(p_msg)) = '\0';   //paranoia

    // Free the earlier dup'd string pointer to replace it with the full message in the buffer!
    free( p_frag->p_msg );
    p_frag->p_msg = p;

    // Finally, add the fragment onto the error stack trace.
    List__add_node( p_err->p_fragments, (void*)p_frag );

}


// Fetch the pointer to the fragments list.
List_t* Error__get_fragments( fuzz_error_t* p_err ) {
    return p_err->p_fragments;
}
