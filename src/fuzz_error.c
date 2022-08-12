/*
 * fuzz_error.h
 *
 * Maintains and tracks various project and module error states
 *   for the fuzzer's pattern parser and generator.
 *
 */

#include "fuzz_error.h"
#include "list.h"

#include <stdlib.h>
#include <string.h>



struct _fuzz_error_t {
    List_t* p_fragments;
};
struct _fuzz_error_fragment_t {
    fuzz_error_code err_code;
    char* p_msg;
};

// Static variable. TODO: Make this thread-safe.
static fuzz_error_t* p_fuzz_error = NULL;



const char* get_fuzz_error_str() {
//    if ( p_fuzz_error )  return p_fuzz_error->p_msg;
//    else  return NULL;
return NULL;
}


// This is a _deep_ free on the array.
void clear_fuzz_error() {
    if ( p_fuzz_error ) {
        if ( p_fuzz_error->p_fragments ) {
            ListNode_t* x = List__get_head( p_fuzz_error->p_fragments );
            while ( NULL != x ) {
                if ( x->node ) {
                    if ( ((struct _fuzz_error_fragment_t*)(x->node))->p_msg )
                        free( ((struct _fuzz_error_fragment_t*)(x->node))->p_msg );
                    free( x->node );
                }
                x = x->next;
            }
            List__delete( p_fuzz_error->p_fragments );
        }
        free( p_fuzz_error );
    }
}


void print_fuzz_error() {
    if ( NULL != p_fuzz_error && NULL != p_fuzz_error->p_fragments ) {
        printf( "\n[FUZZER ERROR: TRACE]\n" );
        ListNode_t* x = List__get_head( p_fuzz_error->p_fragments );
        while ( NULL != x ) {
            printf( "\t%s\n", ((struct _fuzz_error_fragment_t*)(x->node))->p_msg );
            x = x->next;
        }
        printf( "\n\n" );

        // Wipe away the error details after printing.
        clear_fuzz_error();
    } else  printf( "\n[FUZZER ERROR] Unspecified problem.\n\n" );
}


void set_fuzz_error( size_t nest_level, size_t pointer_loc, fuzz_error_code code, const char* p_msg ) {
    if ( NULL == p_fuzz_error ) {
        p_fuzz_error = (fuzz_error_t*)calloc( 1, sizeof(fuzz_error_t) );
        p_fuzz_error->p_fragments = List__new( FUZZ_ERROR_MAX_NODES );
    }

    if ( List__get_count( p_fuzz_error->p_fragments ) >= FUZZ_ERROR_MAX_NODES )  return;

    struct _fuzz_error_fragment_t* p_frag =
        (struct _fuzz_error_fragment_t*)calloc( 1, sizeof(struct _fuzz_error_fragment_t) );
    p_frag->err_code = code;
    p_frag->p_msg = strndup( p_msg, (FUZZ_ERROR_MAX_STRLEN-1) );

    // gross TODO
    char p[45+strlen(p_msg)];
    snprintf( p, (44+strlen(p_msg)), "[Err %4u] [Nest %lu] [Index %14lu] %s",
        code, nest_level, pointer_loc, p_msg );
    p[44+strlen(p_msg)] = '\0';

    free( p_frag->p_msg );
    char* p2 = (char*)calloc( strnlen( p, (FUZZ_ERROR_MAX_STRLEN-1) ), sizeof(char) );
    memcpy(  p2,  p,  strnlen( p, (FUZZ_ERROR_MAX_STRLEN-1)*sizeof(char) )  );
    p_frag->p_msg = p2;

    if ( strlen( p_frag->p_msg ) >= FUZZ_ERROR_MAX_STRLEN ) {
        free( p_frag->p_msg );
        free( p_frag );
        return;
    }

    List__add_node( p_fuzz_error->p_fragments, (void*)p_frag );
}
