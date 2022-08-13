/*
 * generator.c
 *
 * Includes fuzzing generation implementations using structures created
 *   from the 'pattern' code. This means mainly a fuzz_factory and some
 *   extra object-internal data structures are used to achieve this goal.
 *
 */

#include "generator.h"
#include "xoroshiro.h"

#include <time.h>



// Define a counter object which serves to track a nest or other looping
//   type mechanism's generation count.
typedef struct _fuzz_generator_counter_t {
    unsigned short how_many;   // how many (chosen randomly within range)
    unsigned short generated;   // count of items already iterated/generated
    void* p_goto;   // the pointer to reference when iterating
    // ^ it doesn't matter if this points to a sub or a string, the type controls
    //   exactly what is done with it
} __attribute__((__packed__)) counter_t;

// Use a quantitative state vector/context when generating new fuzzer strings.
//   These are disposable structures used only during active string generation.
typedef struct _fuzz_generator_state_vector_t {
    // Array of pointers to counters tracking each nest/subsequence level.
    counter_t* counter[FUZZ_MAX_NESTING_COMPLEXITY];
    void* p_fuzz_factory_base;   // base ptr to the fuzz factory's blob data
} __attribute__((__packed__)) state_t;

// This struct is used to 'prime' the generator by directly providing a pre-
//   allocated context to re/use for 'get_next' operations. Sharing this context
//   does NOT affect the randomness of the sequences.
struct _fuzz_generator_context_t {
    state_t state;
    gen_pool_type type;
    fuzz_factory_t* p_factory;
    xoroshiro256p_state_t* p_prng;
    unsigned char* p_data_pool;
    unsigned char* p_pool_end;
};



// Create a new generator context for re/use to make string generation faster.
fuzz_gen_ctx_t* Generator__new_context( fuzz_factory_t* p_factory, gen_pool_type type ) {
    if ( NULL == p_factory )  return NULL;
    if ( (gen_pool_type)NULL == type )  type = normal;

    // Create the context and return it.
    fuzz_gen_ctx_t* x = (fuzz_gen_ctx_t*)calloc( 1, sizeof(fuzz_gen_ctx_t) );
    (x->state).p_fuzz_factory_base = PatternFactory__get_data( p_factory );
    x->type = type;
    x->p_factory = p_factory;
    x->p_prng = xoroshiro__new( time(NULL) );
    x->p_data_pool = (unsigned char*)calloc( 1,
        (((size_t)type)*FUZZ_GEN_CTX_POOL_MULTIPLIER*sizeof(unsigned char)) );
    x->p_pool_end = 1 + (x->p_data_pool)
        + (((size_t)type)*FUZZ_GEN_CTX_POOL_MULTIPLIER*sizeof(unsigned char));

    return x;
}


// Deletes any allocated gen ctx resources.
void Generator__delete_context( fuzz_gen_ctx_t* p_ctx ) {
    if ( p_ctx ) {
        if ( p_ctx->p_prng )  free( (void*)(p_ctx->p_prng) );
        free( p_ctx );
    }
}



// Generate a new fuzzer output string.
//   In this function, SPEED IS ESSENTIAL to maximize throughput.
const char* Generator__get_next( fuzz_gen_ctx_t* p_ctx ) {
    if ( NULL == p_ctx )  return NULL;

    fuzz_pattern_block_t* pip;   // aka "pseudo-instruction-pointer"
    unsigned char* p_current;

    pip = (fuzz_pattern_block_t*)((p_ctx->state).p_fuzz_factory_base);
    p_current = p_ctx->p_data_pool;

    // Zero string buffer. TODO: Should time be wasted on this, or should the ctx hold the len of the last str
    //   and clear to JUST that??
    memset( p_current, 0, ((p_ctx->type)*FUZZ_GEN_CTX_POOL_MULTIPLIER*sizeof(unsigned char)) );

    // Let's do it
    while ( pip && end != pip->type ) {
        if ( NULL == pip )  return NULL;   // TODO: should this be here?

        size_t processed = 0;

        // The number of iterations selected will either be a single value,
        //   or a number from a range of values. Hold onto your pants...
        size_t iters =
            (  ((pip->count).single > 0) * (pip->count).base  )
            + (
                ((pip->count).single < 1)
                * ( xoroshiro__get_bounded( p_ctx->p_prng, (pip->count).base, (pip->count).high ) )
            );
//printf( "%lu iters\n", iters );

        switch ( pip->type ) {

            case variable : {
                break;
            }

            case reference : {
                break;
            }

            case string : {
                // Catalog the length of the incoming static string.
                size_t z = strlen( (char*)(pip->data) );

                // Mindful of overflows.
                if ( ((sizeof(char)*iters*z)+p_current) >= p_ctx->p_pool_end )  goto __gen_overflow;

                // Write the string.
                for ( ; processed < iters; processed++ ) {
                    memcpy( p_current, (char*)(pip->data), z );
                    p_current += z;
                }

                // Move to the next block.
                pip++;
                break;
            }

            case sub : {
                

                break;
            }

            case ret : {
                break;
            }

            case end : {   // paranoia (see loop condition)
                goto __gen_end;
                break;
            }

            default : {
                return NULL;   // TODO: should this be here?
                break;
            }

        }
    }

    __gen_end:
        // Return the "completed" string.
        return (const char*)(p_ctx->p_data_pool);

    __gen_overflow:
        // When a buffer is going to overflow, STOP and RESET!
        memset( p_ctx->p_data_pool, 0, ((p_ctx->type)*FUZZ_GEN_CTX_POOL_MULTIPLIER*sizeof(unsigned char)) );
        return NULL;
}


// Write the output the an I/O stream directly.
void Generator__get_next_to_stream( fuzz_gen_ctx_t* p_ctx, FILE* fp_to ) {
    const char* const p_tmp = Generator__get_next( p_ctx );
    fprintf( fp_to, "%s", p_tmp );
    free( (void*)p_tmp );
}
