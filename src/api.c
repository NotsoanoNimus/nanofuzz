/*
 * api.c
 *
 * Main API hooks to publicly use with the static library fuzzer.
 *
 */

#include "api.h"

#include <pthread.h>
#include <string.h>
#include <unistd.h>



// Create a structure that wraps a simple stack, a stack type, and a thread mutex
//   to control asynchronous stack operations.
struct _fuzz_output_stack_t {
    void* p_base;
    size_t size;
    size_t data_size;
    size_t count;
    nanofuzz_stack_type type;
    pthread_mutex_t mutex;
    size_t is_error;
};

// Define a structure which encapsulates the parent factory and gen ctx.
// This type is the primary type for interaction with nanofuzz's generator.
struct _fuzz_global_context_t {
    fuzz_factory_t* _p_parent_factory;
    fuzz_gen_ctx_t* _p_gen_ctx;
    nanofuzz_output_stack_t _stack;
    pthread_t _generator;
};



////////////////////////////////////////////////////////////////////////////////////
// Thread and stack functions for output chains (see bottom).
static void* Nanofuzz__thread_refresh_context( void* _p_ctx );   //worker thread function.
static int Nanofuzz__output_stack_push( nanofuzz_output_stack_t* p_stack, nanofuzz_data_t* p_data );
static nanofuzz_data_t* Nanofuzz__output_stack_pop( nanofuzz_output_stack_t* p_stack );
////////////////////////////////////////////////////////////////////////////////////



// Init function; uses the provided string to instantiate a new fuzzer.
nanofuzz_context_t* Nanofuzz__new(
    const char* p_pattern,
    size_t output_stack_size,
    nanofuzz_stack_type output_stack_type,
    nanofuzz_error_t** pp_err_ctx
) {
    // Quick param check.
    if (
           NULL == pp_err_ctx
        || 0 == output_stack_size
        || (nanofuzz_stack_type)NULL == output_stack_type
    )  goto __context_new_err;

    // Create a new fuzzer context.
    nanofuzz_context_t* p_ctx = (nanofuzz_context_t*)calloc( 1, sizeof(nanofuzz_context_t) );
    if ( NULL == p_ctx )
        goto __context_new_err;

    // Parse the pattern. On error, return NULL to indicate and error has occurred.
    p_ctx->_p_parent_factory = PatternFactory__new( p_pattern, pp_err_ctx );
    if ( NULL == p_ctx->_p_parent_factory )
        goto __context_new_err;

    // Create a new generator context to prepare output generation.
    p_ctx->_p_gen_ctx = Generator__new_context(
        p_ctx->_p_parent_factory, FUZZ_GEN_DEFAULT_POOL_SIZE );

    // Allocate and set up the stack. The size is sizeof(data)*output_stack_size.
    nanofuzz_output_stack_t* p_stack = &(p_ctx->_stack);

    pthread_mutex_init( &(p_stack->mutex), NULL );

    p_stack->type = output_stack_type;
    p_stack->count = 0;
    p_stack->size = output_stack_size;
    p_stack->is_error = 0;
    p_stack->data_size = (sizeof(nanofuzz_data_t) * output_stack_size);

    p_stack->p_base = calloc( 1, p_stack->data_size );
    if ( NULL == p_stack->p_base )
        goto __context_new_err;

    // Spin up the new pthread (detached) and start it immediately.
    pthread_attr_t tattr;
    pthread_attr_init( &tattr );
    pthread_attr_setdetachstate( &tattr, 1 );

    int rc = pthread_create( &(p_ctx->_generator), &tattr,
        Nanofuzz__thread_refresh_context, p_ctx );
    if ( rc )
        goto __context_new_err;

    // Temporarily wait until the generator is done.
    volatile unsigned long long int x = 0;
    while ( x < 0xFFFFFFFFFFFFFFF0 && p_stack->count < p_stack->size ) {
        usleep( 100 );
        x++;
    }

    // Check for error conditions (such as generator overflow).

    // Return the allocated context.
    return p_ctx;

    // Jumped to on any error init'ing the ctx.
    __context_new_err:
        Nanofuzz__delete( p_ctx );
        return NULL;
}


// Destroy function to free all Nanofuzz context resources.
void Nanofuzz__delete( nanofuzz_context_t* p_ctx ) {
    if ( NULL != p_ctx ) {
        free( (p_ctx->_stack).p_base );
        (p_ctx->_stack).p_base = NULL;

        Generator__delete_context( p_ctx->_p_gen_ctx );   //also deletes factory resources
    }

    free( p_ctx );
}


// Get a newly-generated item.
nanofuzz_data_t* Nanofuzz__get_next( nanofuzz_context_t* p_ctx ) {
    if ( NULL == p_ctx )  return NULL;

    return Nanofuzz__output_stack_pop( &(p_ctx->_stack) );
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
            && p_data == Generator__get_most_recent( p_ctx->_p_gen_ctx )
        )
            Generator__flush_most_recent( p_ctx->_p_gen_ctx );

        free( p_data );
    }
}



// Pass-through/Wrapper function to explain what a fuzzer is doing step-by-step.
void Nanofuzz__PatternFactory__explain( FILE* fp_stream, nanofuzz_context_t* p_fuzz_ctx ) {
    if ( fp_stream && p_fuzz_ctx && p_fuzz_ctx->_p_parent_factory )
        PatternFactory__explain( fp_stream, p_fuzz_ctx->_p_parent_factory );
}




////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////

// Main thread loop to initally populate a stack and/or continue refilling it.
static void* Nanofuzz__thread_refresh_context( void* _p_ctx ) {
    nanofuzz_context_t* p_ctx = (nanofuzz_context_t*)_p_ctx;
    nanofuzz_output_stack_t* p_stack = &(p_ctx->_stack);

    // For 'oneshot' stack types, fill the data stack and quit.
    if ( oneshot == p_stack->type ) {
        size_t generated = 0;

        while ( generated < p_stack->size ) {
            nanofuzz_data_t* p_data = Generator__get_next( p_ctx->_p_gen_ctx );

            Nanofuzz__output_stack_push( p_stack, p_data );

            free( p_data );   //this data is memcpy'd, so the outer ptr can be freed
            generated++;
        }

        return;
    }

    // 'Refill' types keep the thread alive to replenish the stack as items are taken.
    while ( 1 ) {
        // If there's nothing to generate, keep waiting.
        if ( p_stack->count >= p_stack->size ) {
            usleep( 10000 );
            continue;
        }

        // Generate and push to stack.
        nanofuzz_data_t* p_data = Generator__get_next( p_ctx->_p_gen_ctx );
        if ( NULL == p_data ) {
            p_stack->is_error = 1;
            return;
        }

        Nanofuzz__output_stack_push( p_stack, p_data );

        free( p_data );
    }
}


// Push a data pointer onto the stack.
static int Nanofuzz__output_stack_push(
    nanofuzz_output_stack_t* p_stack,
    nanofuzz_data_t* p_data
) {
    if ( p_stack->count >= p_stack->size )
        return 0;

    pthread_mutex_lock( &(p_stack->mutex) );

    memcpy(
        (p_stack->p_base + (sizeof(nanofuzz_data_t)*(p_stack->count))),
        p_data,
        sizeof(nanofuzz_data_t)
    );
    p_stack->count++;

    pthread_mutex_unlock( &(p_stack->mutex) );

    return 1;
}


// Pop the most recent stack item.
static nanofuzz_data_t* Nanofuzz__output_stack_pop( nanofuzz_output_stack_t* p_stack ) {
    if ( !(p_stack->count) )  return NULL;

    pthread_mutex_lock( &(p_stack->mutex) );

    nanofuzz_data_t* p_data = (p_stack->p_base + (sizeof(nanofuzz_data_t)*(p_stack->count)));
    p_stack->count--;

    nanofuzz_data_t* p_data_copy = (nanofuzz_data_t*)calloc( 1, sizeof(nanofuzz_data_t) );
    memcpy( p_data_copy, p_data, sizeof(nanofuzz_data_t) );

    pthread_mutex_unlock( &(p_stack->mutex) );

    return p_data;
}

////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////
