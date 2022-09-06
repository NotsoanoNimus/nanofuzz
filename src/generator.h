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

// WARNING: Change these at your own risk!
// --- 1 MiB default multiplier for the generator context/pool type.
#define FUZZ_GEN_CTX_POOL_MULTIPLIER (1 * 1024 * 1024)
// --- The default genctx pool size.
#define FUZZ_GEN_DEFAULT_POOL_SIZE normal
// --- The default type associated with variable-based genctx declarations.
// ---   This is for all <> variable mechanisms.
#define FUZZ_GEN_DEFAULT_REF_CTX_TYPE small



// This enum is for multiplying the base pool size of a generator context.
typedef enum _fuzz_gen_ctx_pool_type_t {
    //   When memory is really tight, allocate only 1 MiB (which still is pretty large)
    tiny = (1 << 0),
    //   4 MiB "small" string pooling
    small = (1 << 2),
    //   By default, "normal" contexts generate strings up to 16 MiB apiece.
    normal = (1 << 4),
    //   "Large" pools gobble 128 MiB...
    large = (1 << 7),
    //   And 'extreme' binary pools allocate 1GB! Be careful!
    extreme = (1 << 10)
} gen_pool_type;



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
    gen_pool_type type;              // controls the size of the alloc'd data pool
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
fuzz_gen_ctx_t* Generator__new_context( fuzz_factory_t* p_factory, gen_pool_type type );
// Deletes an allocated generator context and its PRNG.
void Generator__delete_context( fuzz_gen_ctx_t* p_ctx );

// Generate more data using the given factory.
//   NOTE: The return value resides on the heap and must be freed by the caller.
fuzz_str_t* Generator__get_next( fuzz_gen_ctx_t* p_ctx );
// Instead of returning heap data, manages the memory for the caller and
//   writes the generated content directly to the given I/O stream.
void Generator__get_next_to_stream( fuzz_gen_ctx_t* p_ctx, FILE* fp_to );

// Resize a generator's data pool to the new ctx type.
void Generator__resize_context( fuzz_gen_ctx_t* p_ctx, gen_pool_type type );
// Get the pointer of the most recently generated data-stream for a context.
fuzz_str_t* Generator__get_most_recent( fuzz_gen_ctx_t* p_ctx );
// Flush the pointer of the most recently generated data-stream (to NULL) for a context.
void Generator__flush_most_recent( fuzz_gen_ctx_t* p_ctx );

// Return the factory used by a gen ctx.
fuzz_factory_t* Generator__get_context_factory( fuzz_gen_ctx_t* p_ctx );



#endif   /* NANOFUZZ_GENERATOR_H */
