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



struct _fuzz_error_t {
    List_t* p_fragments;
};
struct _fuzz_error_fragment_t {
    fuzz_error_code err_code;
    char* p_msg;
};



// This is a _deep_ free on the Array List of error information.
void Error__delete( fuzz_error_t* p_err) {
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
            List__delete( p_err->p_fragments );
        }
        free( p_err );
    }
}


void Error__print( fuzz_error_t* p_err, FILE* fp_to ) {
    if ( NULL == fp_to )  fp_to = stdout;

    if ( NULL != p_err && NULL != p_err->p_fragments ) {
        fprintf( fp_to, "\n[FUZZ PATTERN ERROR: TRACE] Most Recent First\n" );

        p_err->p_fragments = List__reverse( p_err->p_fragments );

        ListNode_t* x = List__get_head( p_err->p_fragments );
        while ( NULL != x ) {
            fprintf( fp_to, "\t%s\n", ((struct _fuzz_error_fragment_t*)(x->node))->p_msg );
            x = x->next;
        }

        fprintf( fp_to, "\n\n" );

        // Wipe away the error details after printing.
        Error__delete( p_err );
    } else  fprintf( fp_to, "\n[FUZZER ERROR] Unspecified problem.\n\n" );
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
    char p[43+strlen(p_msg)];
    snprintf( p, (42+strlen(p_msg)), "[Err %2u] [Nest %lu] [Index %3lu] %s",
        code, nest_level, pointer_loc, p_msg );
    p[43+strlen(p_msg)] = '\0';   //paranoia

    // Free the earlier dup'd string pointer to replace it with the full message in the buffer!
    free( p_frag->p_msg );
    char* p2 = (char*)calloc( strnlen( p, (FUZZ_ERROR_MAX_STRLEN-1) ), sizeof(char) );
    memcpy(  p2,  p,  strnlen( p, (FUZZ_ERROR_MAX_STRLEN-1)*sizeof(char) )  );
    p_frag->p_msg = p2;

    // Finally, add the fragment onto the error stack trace.
    List__add_node( p_err->p_fragments, (void*)p_frag );

}


// Fetch the pointer to the fragments list.
List_t* Error__get_fragments( fuzz_error_t* p_err ) {
    return p_err->p_fragments;
}