/*
 * api.h
 *
 * Main API hooks to publicly use with the static library fuzzer.
 *
 */

#ifndef _NANOFUZZ_API_H
#define _NANOFUZZ_API_H

#include "pattern.h"
#include "generator.h"

#include <stdio.h>



// Alias some common or externally necessary structures.
//   Names beginning with 'nanofuzz' rather than 'fuzz' are assumed
//   to be used externally.
typedef fuzz_str_t nanofuzz_data_t;
typedef fuzz_error_t nanofuzz_error_t;
typedef gen_pool_type nanofuzz_pool_size;

// Define a structure which encapsulates the parent factory and gen ctx.
// This type is the primary type for interaction with nanofuzz (and stats in the future).
typedef struct _fuzz_global_context_t nanofuzz_context_t;



// Init function; uses the provided string to instantiate a new fuzzer.
nanofuzz_context_t* Nanofuzz__new( const char* p_pattern, nanofuzz_error_t** pp_err_ctx );
// Destroy function to free all Nanofuzz context resources.
void Nanofuzz__delete( nanofuzz_context_t* p_ctx );

// Get a newly-generated item.
nanofuzz_data_t* Nanofuzz__get_next( nanofuzz_context_t* p_ctx );

// Free generated nanofuzz data. This is a simple wrspper and we leave leak tracking up
//   to the implementer of the API since DATA blobs are context-independent.
void Nanofuzz__delete_data( nanofuzz_data_t* p_data );


// Pass-through/Wrapper function to explain what a fuzzer is doing step-by-step.
void Nanofuzz__PatternFactory__explain( FILE* fp_stream, nanofuzz_context_t* p_fuzz_ctx );



#endif   /* _NANOFUZZ_API_H */
