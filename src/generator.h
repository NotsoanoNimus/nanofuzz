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



// Define a generator context to use, which must be associated with a factory.
typedef struct _fuzz_generator_context_t fuzz_gen_ctx_t;



// Create a new generator context with a factory to 'prime' generation a bit.
fuzz_gen_ctx_t* Generator__new_context( fuzz_factory_t* p_factory );

// Generate more data using the given factory.
//   NOTE: The return value resides on the heap and must be freed when
const char* Generator__get_next( fuzz_gen_ctx_t* p_ctx );
// Instead of returning heap data, manages the memory for the caller and
//   writes the generated content to the given I/O stream.
void Generator__get_next_to_stream( fuzz_gen_ctx_t* p_ctx, FILE* fp_to );



#endif   /* _FUZZ_GENERATOR_H */
