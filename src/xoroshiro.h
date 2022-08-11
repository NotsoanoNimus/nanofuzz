/*
 * xoroshiro.h
 *
 * Extremely fast PRNG implementation in C.
 *   According to the papers, only the top 53 bits of 64-bit numbers should be used.
 *
 */

#ifndef _FUZZ_XOROSHIRO_H
#define _FUZZ_XOROSHIRO_H

#include <stdint.h>
#include <stdlib.h>



typedef volatile struct _xoroshiro256p_state_t xoroshiro256p_state_t;



xoroshiro256p_state_t* xoroshiro__new( uint64_t seed_value );
uint64_t xoroshiro__get_next( xoroshiro256p_state_t* p_state );
uint8_t xoroshiro__get_byte( xoroshiro256p_state_t* p_state );
uint8_t xoroshiro__get_bounded_byte( xoroshiro256p_state_t* p_state, uint8_t low, uint8_t high );



#endif   /* _FUZZ_XOROSHIRO_H */
