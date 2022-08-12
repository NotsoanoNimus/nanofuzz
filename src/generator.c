/*
 * generator.c
 *
 * Includes fuzzing generation implementations using structures created
 *   from the 'pattern' code. This means mainly a fuzz_factory and some
 *   extra object-internal data structures are used to achieve this goal.
 *
 */

#include "generator.h"



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



// Generate a new fuzzer output string.
const char* Generator__next( fuzz_factory_t* p_factory ) {
}
