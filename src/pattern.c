/*
 * pattern.h
 *
 * Pattern syntax parsing.
 *
 */

#include "pattern.h"



// A ranging mechanism used in the pattern blocks to determine the amount of times, if set,
//   to repeat a block of pattern data.
struct _fuzz_range_t {
    uint8_t single;   // If non-zero, the 'base' value is the static amount to generate; no ranging.
    unsigned short base;
    unsigned short high;
} __attribute__((__packed__));

// A single unit of the fuzz factory used to generate fuzzer output.
struct _fuzz_pattern_block_t {
    // The type of pattern block being constructed: string, variable, reference, range, sub, etc.
    pattern_block_type type;
    // This label is the name of the variable assigned to the block, if any.
    const char label[FUZZ_MAX_PATTERN_LABEL_NAME_LENGTH];
    // Represents a pointer to the node's data.
    //   This could point to a string, another List, etc. depending on the type.
    const void* data;
    // How many times to produce this specific node's data. Defaults to 1.
    fuzz_range_t count;
} __attribute__((__packed__));

// Represents a single contiguous block of memory which all of the block items get joined into.
//   This is what nanofuzz will actually use in generating content.
struct _fuzz_factory_t {
    // Pointer to the blob of nodes...
    void* node_seq;
    // ... of size count, each = sizeof(fuzz_pattern_block_t)
    size_t count;
};



// Seek the closest closing marker character in a pattern string.
//   Returns NULL if the target character isn't found, or if the target is only ONE char ahead
//   of the start of the input string.
static const char* __seek_marker_end( const char* start, char const target ) {
    const char* end = start;
    while( *(++end) ) {
        if ( *end == target ) {
            if ( (end-start) > 1 )  return end;
            else break;
        }
    }
    return NULL;
}



// Compress the contents of a pattern block list into a single calloc and set it in the factory.
static inline fuzz_factory_t* __compress_List_to_factory( List_t* p_list ) {
    if ( NULL == p_list || List__get_count( p_list ) < 1 )  return NULL;

    // Fetch the list items count, calloc, set each cell, and create the factory.
    fuzz_factory_t* x = (fuzz_factory_t*)calloc( 1, sizeof(fuzz_factory_t) );
    x->count = List__get_count( p_list );

    // Create the new blob and start filling it out.
    unsigned char* scroll = (unsigned char*)calloc( x->count, sizeof(fuzz_pattern_block_t) );

    // Assign the node sequence to the created heap blob.
    x->node_seq = scroll;

    // Move data into the blob.
    ListNode_t* y = List__get_head( p_list );
    while ( NULL != y ) {
        memcpy( scroll, y->node, sizeof(fuzz_pattern_block_t) );
        scroll += sizeof(fuzz_pattern_block_t);
        y = y->next;
    }

    // Destroy the list and return the factory.
    List__delete( p_list );
    return x;
}



// Get the blob data from the given fuzz factory struct.
void* PatternFactory__get_data( fuzz_factory_t* p_fact ) {
    return p_fact->node_seq;
}



// Get the size of the pattern factory's data blob.
size_t PatternFactory__get_data_size( fuzz_factory_t* p_fact ) {
    return (size_t)(p_fact->count * sizeof(fuzz_pattern_block_t));
}



// Frees space used by a pattern factory by destroying it and its nodes' datas from the heap.
void PatternFactory__delete( fuzz_factory_t* p_fact ) {
    if ( NULL == p_fact )  return;

    fuzz_pattern_block_t* x = (fuzz_pattern_block_t*)&(p_fact->node_seq);
    for ( size_t i = 0; i < p_fact->count; i++ ) {
        if ( NULL != x && x->data )  free( x->data );
        x++;
    }

    if ( NULL != p_fact->node_seq )  free( p_fact->node_seq );

    free( p_fact );
}



// Define a set of functional or syntactically special characters.
static const char special_chars[] = "$\\[{(";
// Build the fuzz factory. Since this is only intended to run as part of the
//   wind-up cycle, optimization is not an essential concern here.
fuzz_factory_t* PatternFactory__new( const char* p_pattern_str ) {
    const char* p;
    size_t len, nest_level;
    fuzz_pattern_block_t** p_nest_tracker;

    List_t* p_seq;
    p_seq = List__new( FUZZ_MAX_PATTERN_LENGTH );

    len = strnlen( p_pattern_str, (FUZZ_MAX_PATTERN_LENGTH-1) );
    nest_level = 0;

    p_nest_tracker = (fuzz_pattern_block_t**)calloc(
        FUZZ_MAX_NESTING_COMPLEXITY, sizeof(fuzz_pattern_block_t*) );

    clear_fuzz_error();

    // Let's go!
    for ( p = p_pattern_str; (*p) && p < (p+len); p++ ) {
        printf( "READ: %c\n", *p );
        fuzz_pattern_block_t* p_new_block = NULL;

        switch( *p ) {

            case '$':
                break;

            case '\\':
                break;

            case '[':
                break;

            case '{': {
                // The current block ptr cannot be NULL.
                if ( NULL == *p_nest_tracker ) {
                    set_fuzz_error( FUZZ_ERROR_INVALID_SYNTAX,
                        "The repetition statement '{}' must follow a valid string or other pattern." );
                    goto __err_exit;
                }

                // Make sure a closing brace is found.
                const char* end = __seek_marker_end( p, '}' );
                if ( NULL == end ) {
                    set_fuzz_error( FUZZ_ERROR_INVALID_SYNTAX,
                        "Pattern contains unclosed or empty repetition statement '{}'" );
                    goto __err_exit;
                }

                // Character check. Limit commas to only one occurrence.
                int comma = 0;
                for ( const char* x = (p+1); x < end; x++ ) {
                    if (  ( (*x != ',') || (',' == *x && comma) ) && !isdigit( (int)*x )  ) {
                        set_fuzz_error( FUZZ_ERROR_INVALID_SYNTAX,
                            "Repetition '{}' statements can only contain digits and a single comma" );
                        goto __err_exit;
                    } else if ( (',' == *x) )  comma = 1;
                }

                // Parse the field data and set the range information on the current block pointer.

                // Set 'p' to end. It will increment to the character after '}' once the for-loop continues.
                p = end;
                break;
            }

            case '(':
                break;

            default : {
                p_new_block = NEW_PATTERN_BLOCK;

                // Move 'p' along until it encounters a special char or the end.
                const char* start = p;
                while( *p ) {
printf( "statstrch = %c\n", *p );
                    for ( int j = 0; special_chars[j]; j++ ) {
                        if ( *p == special_chars[j] ) {
printf( "--- FOUND %c\n", *p );
                            p--;   //need to back-step by one
                            goto __static_string_stop;
                        }
                    }
                    p++;
                }

                // Code that reaches here either encountered the end of the pattern string
                //   or the iterator encountered a special character.
                __static_string_stop:
                    *(p_nest_tracker+nest_level) = &p_new_block;
                    p_new_block->type = string;
                    p_new_block->data = strndup( start, (p-start) );

               break;
            }
        }

        // Add the (hopefully-)populated node onto the list and continue;
        List__add_node( p_seq, p_new_block );
        continue;

        __err_exit:
            if ( p_new_block )  free( p_new_block );
            if ( p_nest_tracker ) free( p_nest_tracker );
            List__delete( p_seq );
            return NULL;
    }

    // Assign the list to the factory with its pre-fetched count and return.
printf( "List elements: %lu\n", List__get_count( p_seq ) );
    if ( p_nest_tracker )  free( p_nest_tracker );
    return __compress_List_to_factory( p_seq );
    //fuzz_factory_t* p_factory = __compress_List_to_factory( p_seq );
    //return p_factory;
}
