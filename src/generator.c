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
    size_t nest_level;   // tracks the current index into ^
    void* p_fuzz_factory_base;   // base ptr to the fuzz factory's blob data
} __attribute__((__packed__)) state_t;

// This struct is used to 'prime' the generator by directly providing a pre-
//   allocated context to re/use for 'get_next' operations. Sharing this context
//   does NOT affect the randomness of the sequences.
struct _fuzz_generator_context_t {
    state_t state;                   // see above; context state
    gen_pool_type type;              // controls the size of the alloc'd data pool
    fuzz_factory_t* p_factory;       // core of the context: constructed factory
    xoroshiro256p_state_t* p_prng;   // PRNG structure (TODO: move to state vec?)
    unsigned char* p_data_pool;      // stores generated data
    unsigned char* p_pool_end;       // marks the end of the data pool in memory
};



// Create a new generator context for re/use to make string generation faster.
fuzz_gen_ctx_t* Generator__new_context( fuzz_factory_t* p_factory, gen_pool_type type ) {
    if ( NULL == p_factory )  return NULL;
    if ( (gen_pool_type)NULL == type )  type = normal;

    // Create the context and return it.
    fuzz_gen_ctx_t* x = (fuzz_gen_ctx_t*)calloc( 1, sizeof(fuzz_gen_ctx_t) );
    x->type = type;
    x->p_factory = p_factory;
    x->p_prng = xoroshiro__new( time(NULL) );
    x->p_data_pool = (unsigned char*)calloc( 1,
        (((size_t)type)*FUZZ_GEN_CTX_POOL_MULTIPLIER*sizeof(unsigned char)) );
    x->p_pool_end = (
        1
        + (x->p_data_pool)
        + (((size_t)type)*FUZZ_GEN_CTX_POOL_MULTIPLIER*sizeof(unsigned char))
    );

    // Allocate initial state vector values.
    for ( size_t o = 0; o < FUZZ_MAX_NESTING_COMPLEXITY; o++ )
        *(((x->state).counter)+o) = (counter_t*)calloc( 1, sizeof(counter_t) );
    (x->state).nest_level = 0;
    (x->state).p_fuzz_factory_base = PatternFactory__get_data( p_factory );

    return x;
}


// Deletes any allocated gen ctx resources, but not 'deeply'.
void Generator__delete_context( fuzz_gen_ctx_t* p_ctx ) {
    if ( p_ctx ) {
        if ( p_ctx->p_prng )  free( (void*)(p_ctx->p_prng) );

        if ( p_ctx->p_data_pool )  free( p_ctx->p_data_pool );

        for ( size_t u = 0; u < FUZZ_MAX_NESTING_COMPLEXITY; u++ )
            if ( ((p_ctx->state).counter + u) )
                free( *((p_ctx->state).counter + u) );

        free( p_ctx );
    }
}



// Generate a new fuzzer output string.
//   In this function, SPEED IS ESSENTIAL to maximize throughput.
fuzz_str_t* Generator__get_next( fuzz_gen_ctx_t* p_ctx ) {
    if ( NULL == p_ctx )  return NULL;

    fuzz_pattern_block_t* pip;   // aka "pseudo-instruction-pointer"
    unsigned char* p_current;
    counter_t* p_nullified = NULL;   // tracks subsequences with 0 iters--nullifies all inside contents

    pip = (fuzz_pattern_block_t*)((p_ctx->state).p_fuzz_factory_base);
    p_current = p_ctx->p_data_pool;

    // Zero string buffer. TODO: Should time be wasted on this, or should the ctx hold the len of the last str
    //   and clear to JUST that??
    memset( p_current, 0, ((p_ctx->type)*FUZZ_GEN_CTX_POOL_MULTIPLIER*sizeof(unsigned char)) );

    // Let's do it
//printf( "\n=== [Nest] [Null?] [Type] [Count] ===\n" );
    while ( pip && end != pip->type ) {
        if ( NULL == pip )  return NULL;   // TODO: should this be here?

        // If the current state has a nullified pointer set and the type isn't a ret or sub, keep moving.
        if (  sub != pip->type && ret != pip->type && NULL != p_nullified  ) {
//printf("\t[%u] wenull\n",pip->type);
            pip++;
            continue;
        }

        size_t processed = 0;

        // The number of iterations selected will either be a single value,
        //   or a number from a range of values. Hold onto your pants...
        size_t iters =
            (  ((pip->count).single > 0) * (pip->count).base  )
            + (
                ((pip->count).single < 1)
                * ( xoroshiro__get_bounded( p_ctx->p_prng, (pip->count).base, (pip->count).high ) )
            );

        // Helpful debugging information.
//printf( "[N: %lu] [X: %u] [T: %u] [C: %5lu]\n", (p_ctx->state).nest_level, (NULL != p_nullified), pip->type, iters );

        // The block type must determine the next behavior used in pattern generation.
        switch ( pip->type ) {

            case reference : {
                break;
            }

            case string : {
                // Catalog the length of the incoming static string. NOTE: \x00 are NOT allowed in static
                //   string block types (only ranges), so using a strxyz function is valid.
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

            case range : {
                // Overflow check boi
                if ( ((sizeof(char)*iters)+p_current) >= p_ctx->p_pool_end )  goto __gen_overflow;

                // Get the range object.
                fuzz_range_t* p_range = ((fuzz_range_t*)(pip->data));

                // If the range has useable fragments, use the PRNG to get a character from one of them.
                if ( p_range && p_range->amount > 0 ) {
                    fuzz_repetition_t* p_frag = &(p_range->fragments[0]);
                    fuzz_repetition_t* p_select;

                    // Loop over the range to get a random byte <iters> times.
                    for ( ; processed < iters; processed++ ) {
                        uint8_t frag_select = xoroshiro__get_bounded_byte( p_ctx->p_prng, 0, ((p_range->amount)-1) );

                        p_select = (p_frag + frag_select);

                        uint8_t char_select;
                        if ( p_frag->single )
                            char_select = p_select->base;
                        else
                            char_select = xoroshiro__get_bounded_byte( p_ctx->p_prng, p_select->base, p_select->high );
//printf( "RANGE: fragment %d/%lu; char %d\n", (frag_select+1), p_range->amount, char_select );

                        // Copy the selected character onto the output pool and increment.
                        *(p_current) = (unsigned char)char_select;
                        p_current++;
                    }
                }

                // Move to the next block.
                pip++;
                break;
            }

            case sub : {
                // Get the pointer to the counter for the current nest level.
                size_t* lvl = &((p_ctx->state).nest_level);
                counter_t* p_ctr = *((p_ctx->state).counter + *lvl);

                // Set the amount to generate and zero out the 'generated' counter.
                memset( p_ctr, 0, sizeof(counter_t) );
                p_ctr->how_many = iters;
                p_ctr->generated = 0;

                // If the iters count for this sub is 0, everything proceeds as normal, but a '0'
                //   count subsequence will kill everything inside the nest for this iteration.
                //   So, this is the method used to do so quickly.
                //   Also note, if nullified is already set, do NOT set it again.
                if ( !iters && NULL == p_nullified )  p_nullified = p_ctr;

                // Increase the nest level and move to the next block.
                *lvl = (*lvl)+1;
                pip++;
                break;
            }

            case ret : {
                // Get the pointer to the counter for the __PREVIOUS__ (outer) nest level.
                size_t* lvl = &((p_ctx->state).nest_level);
                counter_t* p_ctr = *((p_ctx->state).counter + *lvl - 1);

                // If 'nullified' is set, check the p_ctr address to see if it matches. If so,
                //   unset the nullification and break out of the null'd sub. Regardless, don't
                //   follow repeats/counts and just break out of the nullified inner sub.
                if ( p_nullified ) {
//printf( "Nullified ptr: %p   /// Counter ptr: %p\n", p_nullified, p_ctr );
                    if ( p_ctr == p_nullified ) {
                        p_nullified = NULL;
                        p_ctr->how_many = 0;
                        p_ctr->generated = 1;
                    }
                    goto __gen_ret_step_out;
                }

                // The counter should ALWAYS be ticked up when a 'ret' is encountered,
                //   BEFORE the conditional.
                (p_ctr->generated)++;

                if ( p_ctr->generated < p_ctr->how_many ) {
                    // Back the pip back to where it needs to be (we blindly trust it)
                    //   and increase the generator count.
                    pip -= *((size_t*)(pip->data));
                } else {
                    // The sub is over. Decrease the nest level and continue.
                    __gen_ret_step_out:
                    *lvl = (*lvl)-1;
//printf( "Step out to %lu\n", *lvl);
                    pip++;
                }
                break;
            }

            default : {
                return NULL;   // TODO: should this be here?
                break;
            }

        }
    }

    // Allocate a COPY of the return data and return the struct ptr.
    fuzz_str_t* p_ret = (fuzz_str_t*)calloc( 1, sizeof(fuzz_str_t) );
    p_ret->length = (p_current - p_ctx->p_data_pool);

    if ( p_ret->length ) {
        p_ret->output = (const void*)calloc( (p_ret->length + 1), sizeof(char) );
        memcpy( (void*)p_ret->output, p_ctx->p_data_pool, (p_ret->length)*sizeof(char) );
        *((char*)(p_ret->output + p_ret->length)) = '\0';   //paranoia, necessary if 'output' will be printed
    } else {
        p_ret->output = NULL;
    }

    return p_ret;


    __gen_overflow:
        // When a buffer is going to overflow, STOP and RESET!
        memset( p_ctx->p_data_pool, 0, ((p_ctx->type)*FUZZ_GEN_CTX_POOL_MULTIPLIER*sizeof(unsigned char)) );
        return NULL;
}


// Write the output the an I/O stream directly.
void Generator__get_next_to_stream( fuzz_gen_ctx_t* p_ctx, FILE* fp_to ) {

    if (  !fp_to || ferror( fp_to )  )  return;

    const fuzz_str_t* const p_tmp = Generator__get_next( p_ctx );
    if ( !p_tmp )  return;

    // Write raw data to the output stream.
    size_t bytes = fwrite( p_tmp->output, sizeof(char), p_tmp->length, fp_to );
    if (  !bytes || ferror( fp_to )  )
        fprintf( stderr, "Problem writing raw fuzzer output to the selected stream.\n" );

    // Free the resource.
    free( (void*)(p_tmp->output) );
    free( (void*)p_tmp );
}



// Resize a generator's data pool to the new ctx type.
//   WARNING: This zeroes out the current data pool (and thus the most recently-
//   generated fuzz_str_t stream).
void Generator__resize_context( fuzz_gen_ctx_t* p_ctx, gen_pool_type type ) {
    if ( !p_ctx )  return;

    if ( p_ctx->p_data_pool )  free( p_ctx->p_data_pool );

    p_ctx->type = type;
    p_ctx->p_data_pool = (unsigned char*)calloc( 1,
        (((size_t)type)*FUZZ_GEN_CTX_POOL_MULTIPLIER*sizeof(unsigned char)) );
    p_ctx->p_pool_end = (
        1
        + (p_ctx->p_data_pool)
        + (((size_t)type)*FUZZ_GEN_CTX_POOL_MULTIPLIER*sizeof(unsigned char))
    );
}
