/*
 * fuzz_error.h
 *
 * Maintains and tracks various project and module error states
 *   for the fuzzer's pattern parser and generator.
 *
 */

// TODO: Revisit and make this thread-safe
#ifndef _FUZZ_FUZZ_ERROR_H
#define _FUZZ_FUZZ_ERROR_H

#include <stdio.h>
#include <stdlib.h>

// Maximum string length of error fragments.
#define FUZZ_ERROR_MAX_STRLEN 512
// Maximum amount of fragments the error list can hold.
#define FUZZ_ERROR_MAX_NODES 16



typedef struct _fuzz_error_t fuzz_error_t;
typedef enum _fuzz_error_code {
    FUZZ_ERROR_INVALID_SYNTAX,
    FUZZ_ERROR_TOO_MUCH_NESTING
} fuzz_error_code;



fuzz_error_t* Error__new();
void Error__delete( fuzz_error_t* p_err );
void Error__print( fuzz_error_t* p_err, FILE* fp_to );
void Error__add( fuzz_error_t* p_err, size_t nest_level,
    size_t pointer_loc, fuzz_error_code code, const char* p_msg );



#endif   /* _FUZZ_FUZZ_ERROR_H */
