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
    fuzz_factory_t* p_factory;
    const xoroshiro256p_state_t* p_prng;
};



// Create a new generator context for re/use to make string generation faster.
fuzz_gen_ctx_t* Generator__new_context( fuzz_factory_t* p_factory ) {
    if ( NULL == p_factory )  return NULL;

    // Create the context and return it.
    fuzz_gen_ctx_t* x = (fuzz_gen_ctx_t*)calloc( 1, sizeof(fuzz_gen_ctx_t) );
    (x->state).p_fuzz_factory_base = PatternFactory__get_data( p_factory );
    x->p_factory = p_factory;
    x->p_prng = xoroshiro__new( time(NULL) );

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
    return NULL;
}


// Write the output the an I/O stream directly.
void Generator__get_next_to_stream( fuzz_gen_ctx_t* p_ctx, FILE* fp_to ) {
    const char* const p_tmp = Generator__get_next( p_ctx );
    fprintf( fp_to, "%s", p_tmp );
    free( (void*)p_tmp );
}
