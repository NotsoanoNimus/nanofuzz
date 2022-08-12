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



// Generste more data using the given factory.
const char* Generator__next( fuzz_factory_t* p_factory );



#endif   /* _FUZZ_GENERATOR_H */
