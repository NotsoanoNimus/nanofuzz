/*
 * fuzz_error.h
 *
 * Maintains and tracks various project and module error states
 *   for the fuzzer's pattern parser and generator.
 *
 */

#include "fuzz_error.h"



struct _fuzz_error_t {
    fuzz_error_code err_code;
    const char* p_msg;
};



void clear_fuzz_error() {
    if ( p_fuzz_error )  free( p_fuzz_error );
}


void print_fuzz_error() {
    if ( p_fuzz_error != NULL && p_fuzz_error->p_msg != NULL )
        printf( "\n[FUZZER ERROR] %s\n\n", p_fuzz_error->p_msg );
    else
        printf( "\n[FUZZER ERROR] Unspecified problem.\n\n" );
}


void set_fuzz_error( fuzz_error_code code, const char* p_msg ) {
    clear_fuzz_error();

    p_fuzz_error = (fuzz_error_t*)calloc( 1, sizeof(fuzz_error_t) );
    p_fuzz_error->err_code = code;
    p_fuzz_error->p_msg = strdup( p_msg );
}
