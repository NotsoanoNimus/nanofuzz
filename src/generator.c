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
    fuzz_str_t* p_most_recent;       // points to the most recently-generated stream
    unsigned char* p_data_pool;      // stores generated data
    unsigned char* p_pool_end;       // marks the end of the data pool in memory
};



// Inline method to look up a string as a hashtable value.
static inline fuzz_gen_ctx_t* __Generator__subcontext_for_label( fuzz_factory_t* p_ff, char* p_label ) {
    // Using the 'djb2' hashing algorithm.
//char* p_preserve = p_label;
    unsigned long hash = 5381;
    int c;
    while ( (c = *p_label++) )
        hash = ( (hash << 5) + hash ) + c;   // hash * 33 + c
//printf( "HASH (%lu) for LABEL '%s'\n", hash, p_preserve );

    // Search the index opaquely for the hash. If found, return the pointer. Else, NULL.
    void* p_scroll;
    size_t i;
    size_t struct_size = (sizeof(unsigned long)+sizeof(fuzz_gen_ctx_t*));
    for (
        p_scroll = PatternFactory__get_shard_index_ptr( p_ff ), i = 0;
        i < FUZZ_MAX_VARIABLES;
        i++
    ) {
//printf("SCROLLGENGEN: (%p) (%lu) (%lu:%p)\n", p_scroll, struct_size, *((unsigned long*)(p_scroll + (i*struct_size))), *((fuzz_gen_ctx_t**)(p_scroll + (i*struct_size) + sizeof(unsigned long))) );
        if (
            0 == memcmp(
                (p_scroll + (i*struct_size)),
                &hash,
                sizeof(unsigned long)
            )
        ) {
            // The value inside the private struct is a pointer, this is a pointer to that.
            //   Thus, a double-pointer is needed to dereference the genctx fully.
            return *(
                (fuzz_gen_ctx_t**)(
                    p_scroll
                    + (i*struct_size)
                    + sizeof(unsigned long)
                )
            );
        }
    }

    return NULL;
}



// Create a new generator context for re/use to make string generation faster.
fuzz_gen_ctx_t* Generator__new_context( fuzz_factory_t* p_factory, gen_pool_type type ) {
    if ( NULL == p_factory )  return NULL;
    if ( (gen_pool_type)NULL == type )  type = normal;

    // Create the context and return it.
    fuzz_gen_ctx_t* x = (fuzz_gen_ctx_t*)calloc( 1, sizeof(fuzz_gen_ctx_t) );
    x->type = type;
    x->p_factory = p_factory;
    x->p_prng = xoroshiro__new();
    x->p_most_recent = NULL;
    x->p_data_pool = (unsigned char*)calloc( 1,
        (((size_t)type)*FUZZ_GEN_CTX_POOL_MULTIPLIER*sizeof(unsigned char)) );
    x->p_pool_end = (
        1
        + (x->p_data_pool)
        + (((size_t)type)*FUZZ_GEN_CTX_POOL_MULTIPLIER*sizeof(unsigned char))
    );

    // Allocate initial state vector values.
    for ( size_t o = 0; o < FUZZ_MAX_NESTING_COMPLEXITY; o++ ) {
        *(((x->state).counter)+o) = (counter_t*)calloc( 1, sizeof(counter_t) );
    }
    (x->state).nest_level = 0;
    (x->state).p_fuzz_factory_base = PatternFactory__get_data( p_factory );

    return x;
}


// Deletes any allocated gen ctx resources, but not 'deeply'.
//   The factory is deleted separate from the genctx
//   ^ TODO: Reconsider this since the generator and factory are technically not separate entities.
void Generator__delete_context( fuzz_gen_ctx_t* p_ctx ) {
    if ( p_ctx ) {
        if ( p_ctx->p_prng )  free( (void*)(p_ctx->p_prng) );

        if ( p_ctx->p_data_pool )  free( p_ctx->p_data_pool );

        for ( size_t u = 0; u < FUZZ_MAX_NESTING_COMPLEXITY; u++ )
            if ( ((p_ctx->state).counter + u) )
                free( *((p_ctx->state).counter + u) );

        // TODO: Experimental.
        if ( p_ctx->p_factory )
            PatternFactory__delete( p_ctx->p_factory );

        free( p_ctx );
    }
}



// Generate a new fuzzer output string.
//   In this function, SPEED IS ESSENTIAL to maximize throughput.
// TODO: At the end of gen, check the shards list contexts and free all current fuzz_str_t objects from each.
//   This must only apply to sub-factories and not the parent context since the fuzz_str_t from the parent
//   might be used anywhere and needs to be freed by the implementer.
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

    // Let's do it, but play nicely.
//printf( "\n=== [Nest] [Null?] [Type] [Count] ===\n" );
    void* p_instruction_limit =
        (void*)pip + (
            PatternFactory__get_count( p_ctx->p_factory )
            * PatternFactory__sizeof()
        )
    ;
    while ( pip && end != pip->type && (void*)pip < p_instruction_limit ) {
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
                fuzz_reference_t* p_ref = (fuzz_reference_t*)(pip->data);
//printf( "GENREF '%s'\n", p_ref->label );
                fuzz_gen_ctx_t* p_gctx =
                    __Generator__subcontext_for_label( p_ctx->p_factory, &(p_ref->label[0]) );
//printf( "GENCTX: |%p|%p|%p|%d|\n", p_gctx, p_gctx->p_factory, p_gctx->p_prng, p_gctx->type );

                // If the gen ctx couldn't be found for the label, break out. This would be a big problem.
                if ( NULL == p_gctx )  goto __gen_overflow;

                // Either get the most recent or generate if there is no most-recent.
                int was_regen = 0;
                fuzz_str_t* p_str = p_gctx->p_most_recent;
                if ( NULL == p_str ) {
                    // Hasn't been shuffled yet; generate the first item in the sub-factory.
                    p_str = Generator__get_next( p_gctx );
                    was_regen = 1;
                }

                switch ( p_ref->type ) {

                    case ref_reference : {
                        // Basically mimic what the static string stuff below does but DO NOT
                        //   utilize any strxyz methods since null bytes can exist in this buffer.
                        size_t z = p_str->length;

                        // Mindful of overflows.
                        if ( ((sizeof(char)*iters*z)+p_current) >= p_ctx->p_pool_end )
                            goto __gen_overflow;

                        // Write the stream.
                        for ( ; processed < iters; processed++ ) {
                            memcpy( p_current, p_str->output, z );
                            p_current += z;
                        }

                        break;
                    }

                    // TODO: It would be nice to also be able to output lens in binary instead of a string.
                    //    This could help make stuff like data structure fuzzing more viable with this.
//                    case ref_count_binary :
                    case ref_count_nullterm :
                    case ref_count : {
                        size_t len = p_str->length + (1*(ref_count_nullterm == p_ref->type));
                        char* p_len = (char*)calloc( 32, sizeof(char) );

                        snprintf ( p_len, 32, "%lx", len );
                        *(p_len+31) = '\0';   //paranoia

                        // Muh overflow.
                        if ( ((sizeof(char)*iters*strlen(p_len))+p_current) >= p_ctx->p_pool_end )
                            goto __gen_overflow;

                        for ( ; processed < iters; processed++ ) {
                            memcpy( p_current, p_len, strlen(p_len) );
                            p_current += strlen(p_len);
                        }

                        free( p_len );
                        break;
                    }

                    case ref_shuffle : {
                        // When regenerating the pattern, make sure to free the old subfactory resource.
                        //   If this is already a fresh shuffle, don't do anything (saves time).
                        // NOTE: This ignores the 'iters' value to save time. Only one shuffle at a time.
                        if ( !was_regen ) {
                            free( (void*)p_str->output ); free( p_str );
                            Generator__get_next( p_gctx );
                        }
                        break;
                    }

                    default : break;   // if this somehow happens, do nothing; just move on
                }

                // Move to the next block. References do not loop.
                pip++;
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
                        if ( 0 != p_select->single ) {
                            char_select = p_select->base;
                        } else {
                            char_select = xoroshiro__get_bounded_byte( p_ctx->p_prng, p_select->base, p_select->high );
                        }
//printf( "RANGE: fragment %d/%lu; char %d (%d/%d-%d)\n", (frag_select+1), p_range->amount, char_select, p_select->single, p_select->base, p_select->high );

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

            case branch_root : {
                // Randomly select one of the available branches from the structure.
                fuzz_branch_root_t* p_root = (fuzz_branch_root_t*)(pip->data);

                // If for some reason the root is null, proceed to the next instruction
                //   so the branch falls back to the first choice on error.
                if ( NULL == p_root ) {
                    pip++;
                    break;
                }

                // Get the random index into the steps table and select it.
                size_t select = xoroshiro__get_bounded( p_ctx->p_prng, 0, p_root->amount );

                unsigned short incr = p_root->steps[select];
                pip += (incr ? incr : 1);   //always move by at least 1
                break;
            }
            case branch_jmp : {
                // Blindly follow the jump, moving the pseudo instruction ptr (PIP) forward.
                size_t jmp = *((size_t*)(pip->data));
                pip += (jmp ? jmp : 1);   //by at least 1 so it doesn't get stuck
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

    // Save the pool information to the current generator context.
    p_ctx->p_most_recent = p_ret;

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



// Return the factory used by a gen ctx.
fuzz_factory_t* Generator__get_context_factory( fuzz_gen_ctx_t* p_ctx ) {
    return p_ctx->p_factory;
}
