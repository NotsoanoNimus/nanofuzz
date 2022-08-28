/*
 * fuzz_error.h
 *
 * Maintains and tracks various project and module error states
 *   for the fuzzer's pattern parser and generator.
 *
 */

// TODO: Revisit and make this thread-safe
#ifndef NANOFUZZ_FUZZ_ERROR_H
#define NANOFUZZ_FUZZ_ERROR_H

#include <yallic.h>

#include <stdio.h>
#include <stdlib.h>

// Maximum string length of error fragments.
#define FUZZ_ERROR_MAX_STRLEN 512
// Maximum amount of fragments the error list can hold.
#define FUZZ_ERROR_MAX_NODES 16



// Define a simple wrapper type which holds a linked list of internal 'fragment' objects.
//   Each fragment represents a different error in a sort of pseudo-stack-trace.
typedef struct _fuzz_error_t fuzz_error_t;

// A list of different error codes in an enum for quick reference.
// TODO: Make better use of these.
typedef enum _fuzz_error_code {
    FUZZ_ERROR_INVALID_SYNTAX,
    FUZZ_ERROR_TOO_MUCH_NESTING
} fuzz_error_code;



// Gets whether the list actually has any errors by checking the length of the err list.
int Error__has_error( fuzz_error_t* p_err );
// Create a new errors list.
fuzz_error_t* Error__new();
// Destroy an errors list and its sub-elements.
void Error__delete( fuzz_error_t* p_err );
// Print and destroy an errors list.
void Error__print( fuzz_error_t* p_err, FILE* fp_to );
// Append another error message onto an errors list.
void Error__add( fuzz_error_t* p_err, size_t nest_level,
    size_t pointer_loc, fuzz_error_code code, const char* p_msg );
// Get the list of items associated with an errors list.
List_t* Error__get_fragments( fuzz_error_t* p_err );



#endif   /* NANOFUZZ_FUZZ_ERROR_H */
