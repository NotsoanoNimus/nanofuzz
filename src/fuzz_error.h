/*
 * fuzz_error.h
 *
 * Maintains and tracks various project and module error states
 *   for the fuzzer's pattern parser and generator.
 *
 */

#ifndef _FUZZ_FUZZ_ERROR_H
#define _FUZZ_FUZZ_ERROR_H

#include <stdio.h>
#include <stdlib.h>



typedef struct _fuzz_error_t fuzz_error_t;
typedef enum _fuzz_error_code {
    FUZZ_ERROR_INVALID_SYNTAX
} fuzz_error_code;



fuzz_error_t* p_fuzz_error;



void clear_fuzz_error();
void print_fuzz_error();
void set_fuzz_error( fuzz_error_code code, const char* p_msg );



#endif   /* _FUZZ_FUZZ_ERROR_H */
