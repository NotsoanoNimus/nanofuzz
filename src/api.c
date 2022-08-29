/*
 * api.c
 *
 * Main API hooks to publicly use with the static library fuzzer.
 *
 */

#include "api.h"



// Define a structure which encapsulates the parent factory and gen ctx.
// This type is the primary type for interaction with nanofuzz's generator.
struct _fuzz_global_context_t {
    fuzz_factory_t* _p_parent_factory;
    fuzz_gen_ctx_t* _p_gen_ctx;
};



// Init function; uses the provided string to instantiate a new fuzzer.
nanofuzz_context_t* Nanofuzz__new( const char* p_pattern, nanofuzz_error_t** pp_err_ctx ) {
    if ( NULL == pp_err_ctx )  return NULL;

    // Create a new fuzzer context.
    nanofuzz_context_t* p_ctx = (nanofuzz_context_t*)calloc(
        1, sizeof(nanofuzz_context_t) );

    // Parse the pattern. On error, return NULL to indicate and error has occurred.
    p_ctx->_p_parent_factory = PatternFactory__new( p_pattern, pp_err_ctx );
    if ( NULL == p_ctx->_p_parent_factory ) {
        free( p_ctx );
        return NULL;
    }

    // Create a new generator context to prepare output generation.
    p_ctx->_p_gen_ctx = Generator__new_context(
        p_ctx->_p_parent_factory, FUZZ_GEN_DEFAULT_POOL_SIZE );

    // Return the allocated context.
    return p_ctx;
}


// Destroy function to free all Nanofuzz context resources.
void Nanofuzz__delete( nanofuzz_context_t* p_ctx ) {
    if ( NULL != p_ctx ) {
        Generator__delete_context( p_ctx->_p_gen_ctx );   //also deletes factory resources
        free( p_ctx );
    }
}


// Get a newly-generated item.
nanofuzz_data_t* Nanofuzz__get_next( nanofuzz_context_t* p_ctx ) {
    if ( NULL == p_ctx )  return NULL;

    return Generator__get_next( p_ctx->_p_gen_ctx );
}


// Free generated nanofuzz data. This is a simple wrspper and we leave leak tracking up
//   to the implementer of the API since DATA blobs are context-independent.
void Nanofuzz__delete_data( nanofuzz_context_t* p_ctx, nanofuzz_data_t* p_data ) {
    if ( NULL != p_data ) {
        if ( NULL != p_data->output ) {
            free( (void*)p_data->output );
            p_data->output = NULL;
        }

        // Prevent dangling pointers on the context where applicable.
        if (
               NULL != p_ctx
            && NULL != p_ctx->_p_gen_ctx
            && p_data == Generator__get_most_recent( p_ctx->_p_gen_ctx )  )
            Generator__flush_most_recent( p_ctx->_p_gen_ctx );

        free( p_data );
    }
}



// Pass-through/Wrapper function to explain what a fuzzer is doing step-by-step.
void Nanofuzz__PatternFactory__explain( FILE* fp_stream, nanofuzz_context_t* p_fuzz_ctx ) {
    if ( fp_stream && p_fuzz_ctx && p_fuzz_ctx->_p_parent_factory )
        PatternFactory__explain( fp_stream, p_fuzz_ctx->_p_parent_factory );
}
