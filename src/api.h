/*
 * api.h
 *
 * Main API hooks to publicly use with the static library fuzzer.
 *
 */

#ifndef NANOFUZZ_API_H
#define NANOFUZZ_API_H

#include "pattern.h"
#include "generator.h"
#include "fuzz_error.h"

#include <stdio.h>



// Instrumentation to catch code path changes.
#define NANOFUZZ_STATS_PRE \
void __nanofuzz_register_function_call( void* callee, void* caller ) \
    __attribute__((no_instrument_function)); \
void __cyg_profile_func_enter( void* callee, void* caller ) \
    __attribute__((no_instrument_function)); \
void __cyg_profile_func_exit( void* callee, void* caller ) \
    __attribute__((no_instrument_function));



// Alias some common or externally necessary structures.
//   Names beginning with 'nanofuzz' rather than 'fuzz' are assumed
//   to be used externally.
typedef fuzz_str_t nanofuzz_data_t;
typedef fuzz_error_t nanofuzz_error_t;

// Define a structure which encapsulates the parent factory and gen ctx.
// This type is the primary type for interaction with nanofuzz (and stats in the future).
typedef struct _fuzz_global_context_t nanofuzz_context_t;

// Create a structure that wraps a linked list, a chain type, and a thread mutex
//   to control asynchronous ouput generation.
typedef struct _fuzz_output_stack_t nanofuzz_output_stack_t;
typedef enum _fuzz_output_stack_type {
    oneshot = 1,    /**< Fills the output chain one time and does not interact with it anymore. */
    refill          /**< Asynchronously refills the output chain as items are popped. */
} nanofuzz_stack_type;



// Init function; uses the provided string to instantiate a new fuzzer and output stack.
nanofuzz_context_t* Nanofuzz__new(
    const char* p_pattern,
    size_t output_stack_size,
    nanofuzz_stack_type output_stack_type,
    nanofuzz_error_t** pp_err_ctx
);

// Destroy function to free all Nanofuzz context resources.
void Nanofuzz__delete( nanofuzz_context_t* p_ctx );

// Get a newly-generated item from the output stack of the context.
nanofuzz_data_t* Nanofuzz__get_next( nanofuzz_context_t* p_ctx );

// Free generated nanofuzz data. This is a simple wrspper and we leave leak tracking up
//   to the implementer of the API since DATA blobs are context-independent.
void Nanofuzz__delete_data( nanofuzz_context_t* p_ctx, nanofuzz_data_t* p_data );

// Pass-through/Wrapper function to explain what a fuzzer is doing step-by-step.
//   This isn't really necessary, but nice to keep the Nanofuzz 'namespace' on the method.
void Nanofuzz__PatternFactory__explain( FILE* fp_stream, nanofuzz_context_t* p_fuzz_ctx );



#endif   /* NANOFUZZ_API_H */
