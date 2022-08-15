/*
 * generator.c
 *
 * Includes fuzzing generation implementations using structures created
 *   from the 'pattern' code. This means mainly a fuzz_factory and some
 *   extra object-internal data structures are used to achieve this goal.
 *
 */

#ifndef _FUZZ_GENERATOR_H
#define _FUZZ_GENERATOR_H

#include "pattern.h"

#include <stdio.h>

// WARNING: Change these at your own risk!
#define FUZZ_GEN_CTX_POOL_MULTIPLIER (1 * 1024 * 1024)



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



// Define a generator context to use, which must be associated with a factory.
typedef struct _fuzz_generator_context_t fuzz_gen_ctx_t;
// Define the structure of generated data. This is simply a void-ptr to a blob, with a strict length.
typedef struct _fuzz_str_t {
    const void* output;
    size_t length;
} fuzz_str_t;



// Create a new generator context with a factory to 'prime' generation a bit.
fuzz_gen_ctx_t* Generator__new_context( fuzz_factory_t* p_factory, gen_pool_type type );
// Deletes an allocated generator context and its PRNG.
void Generator__delete_context( fuzz_gen_ctx_t* p_ctx );

// Generate more data using the given factory.
//   NOTE: The return value resides on the heap and must be freed when
fuzz_str_t* Generator__get_next( fuzz_gen_ctx_t* p_ctx );
// Instead of returning heap data, manages the memory for the caller and
//   writes the generated content directly to the given I/O stream.
void Generator__get_next_to_stream( fuzz_gen_ctx_t* p_ctx, FILE* fp_to );



#endif   /* _FUZZ_GENERATOR_H */
