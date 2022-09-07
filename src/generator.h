/*
 * generator.c
 *
 * Includes fuzzing generation implementations using structures created
 *   from the 'pattern' code. This means mainly a fuzz_factory and some
 *   extra object-internal data structures are used to achieve this goal.
 *
 */

#ifndef NANOFUZZ_GENERATOR_H
#define NANOFUZZ_GENERATOR_H

#include "pattern.h"
#include "tinymt64.h"

#include <stdio.h>



// This struct is used to 'prime' the generator by directly providing a pre-
//   allocated context to re/use for 'get_next' operations. Sharing this context
//   does NOT affect the randomness of the sequences.
typedef struct _fuzz_generator_counter_t {
    unsigned short how_many;   // how many (chosen randomly within range)
    unsigned short generated;   // count of items already iterated/generated
} fuzz_gen_ctx_counter_t;

typedef struct _fuzz_generator_state_vector_t {
    size_t nest_level;   // tracks the current index into ^
    fuzz_gen_ctx_counter_t counter[FUZZ_MAX_NESTING_COMPLEXITY];   // counters for tracking sub-related repetitions
} fuzz_gen_ctx_state_t;

typedef struct _fuzz_generator_context_t {
    fuzz_gen_ctx_state_t state;                   // see above; context state
    fuzz_factory_t* p_factory;       // core of the context: constructed factory
    unsigned char* p_data_pool;      // stores generated data
    unsigned char* p_pool_end;       // marks the end of the data pool in memory
} fuzz_gen_ctx_t;

// Define the structure of generated data. This is simply a void-ptr to a blob, with a strict length.
typedef struct _fuzz_str_t {
    const void* output;
    unsigned long long int length;
} fuzz_str_t;



// Create a new generator context with a factory to 'prime' generation a bit.
fuzz_gen_ctx_t* Generator__new_context( fuzz_factory_t* p_factory );
// Deletes an allocated generator context and its PRNG.
void Generator__delete_context( fuzz_gen_ctx_t* p_ctx );

// Generate more data using the given factory.
//   NOTE: The return value resides on the heap and must be freed by the caller.
fuzz_str_t* Generator__get_next( fuzz_gen_ctx_t* p_ctx );
// Instead of returning heap data, manages the memory for the caller and
//   writes the generated content directly to the given I/O stream.
void Generator__get_next_to_stream( fuzz_gen_ctx_t* p_ctx, FILE* fp_to );

// Return the factory used by a gen ctx.
fuzz_factory_t* Generator__get_context_factory( fuzz_gen_ctx_t* p_ctx );



#endif   /* NANOFUZZ_GENERATOR_H */
