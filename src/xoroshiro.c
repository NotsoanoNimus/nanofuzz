/*
 * xoroshiro.h
 *
 * Extremely fast PRNG implementation in C.
 *   According to the papers, only the top 53 bits of 64-bit numbers should be used.
 *
 * Code in this file is MOSTLY attributed to the implementation at the following URL, with slight modifications:
 *   https://en.wikipedia.org/wiki/Xorshift#xoshiro256+
 *
 */

#include "xoroshiro.h"
#include "tinymt64.h"



struct _xoroshiro256p_state_t {
    union state {
        uint64_t ras;
        uint32_t eas[2];
        uint16_t as[4];
    } s[4];
};



static inline uint64_t __rol64( uint64_t x, int k ) {
    return ( (x << k) | (x >> (64-k)) );
}



static inline uint64_t __xoroshiro256p__next( xoroshiro256p_state_t* p_state ) {
    uint64_t* s = (uint64_t*)&(p_state->s[0]);
    uint64_t const result = *(s+0) + *(s+3);

    uint64_t const t = ( *(s+1) << 17 );

    // Mutations
    *(s+2) ^= *(s+0);
    *(s+3) ^= *(s+1);
    *(s+1) ^= *(s+2);
    *(s+0) ^= *(s+3);

    *(s+2) ^= t;
    *(s+3) = __rol64( *(s+3), 45 );

    return result;
}



xoroshiro256p_state_t* xoroshiro__new( uint64_t seed_value ) {
    // Seed the four values in the xoroshiro state with a single 64-bit integer,
    //   which seeds a tinyMT64, which helps start the state of the vector.
    int i;
    tinymt64_t* p_prng_init;
    xoroshiro256p_state_t* state;

    state = (xoroshiro256p_state_t*)calloc( 1, sizeof(xoroshiro256p_state_t) );

    p_prng_init = (tinymt64_t*)calloc( 1, sizeof(tinymt64_t) );
    tinymt64_init( p_prng_init, seed_value );

    for ( i = 0; i < 4; i++ )
        (state->s[i]).ras = tinymt64_generate_uint64( p_prng_init );

    __xoroshiro256p__next( state );
    return state;
}



uint64_t xoroshiro__get_next( xoroshiro256p_state_t* p_state ) {
    return __xoroshiro256p__next( p_state );
}

uint64_t xoroshiro__get_bounded( xoroshiro256p_state_t* p_state, uint64_t low, uint64_t high ) {
    // muh branchless - the boolean condition prevents the modulo from dividing by 0 (same below)
    return (
        ( high > low )
        * (
            (
                xoroshiro__get_next( p_state )
                % (
                    (
                        ( ( (1 + high - low) == 0 ) * 1 )
                        + (1 + high - low)
                    )
                )
            )
            + low
        )
    );
}


uint8_t xoroshiro__get_byte( xoroshiro256p_state_t* p_state ) {
    return (uint8_t)__rol64( (__xoroshiro256p__next( p_state ) & 0x0000FF0000000000), 24 );
}

uint8_t xoroshiro__get_bounded_byte( xoroshiro256p_state_t* p_state, uint8_t low, uint8_t high ) {
    // im sorry mom
    return (
        ( high > low )
        * (
            (
                xoroshiro__get_byte( p_state )
                % (
                    (
                        ( ( (1 + high - low) == 0 ) * 1 )
                        + (1 + high - low)
                    )
                )
            )
            + low
        )
    );
}
