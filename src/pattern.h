/*
 * pattern.h
 *
 * Pattern syntax parsing.
 *
 */

#ifndef _FUZZ_PATTERN_H
#define _FUZZ_PATTERN_H

#include "fuzz_error.h"
#include "list.h"
#include "api.h"

#define NEW_PATTERN_BLOCK (fuzz_pattern_block_t*)calloc( 1, sizeof(fuzz_pattern_block_t) );



// A finalized, contiguous stream of blocks which is used to construct fuzzer output.
typedef struct _fuzz_factory_t fuzz_factory_t;

// A ranging structure used in the pattern blocks to determine the amount of times, if set,
//   to repeat a block of pattern data.
// Used in the pattern blocks to determine the range of times to output the block.
typedef struct _fuzz_range_t {
    unsigned char single;   // If non-zero, the 'base' value is the static amount to generate; no ranging.
    unsigned short base;
    unsigned short high;
} __attribute__((__packed__)) fuzz_range_t;

// Represents the different types of possible pattern blocks which can
//   be added to the fuzz factory.
typedef enum _pattern_block_type {
    reference = 1,
    string,
    range,
    sub,
    ret,
    end
} pattern_block_type;

// A block (or "piece") of an interpreted part of the input pattern information.
typedef struct _fuzz_pattern_block_t {
    // The type of pattern block being constructed: string, reference, sub, etc.
    pattern_block_type type;
    // Represents a pointer to the node's data.
    //   This could point to a string, another List, etc. depending on the type.
    void* data;
    // How many times to produce this specific node's data. Defaults to 1.
    fuzz_range_t count;
    // This label is the name of the variable assigned to the block, if any.
    const char label[FUZZ_MAX_PATTERN_LABEL_NAME_LENGTH];
} fuzz_pattern_block_t;



// Get the blob data from the given fuzz factory struct.
void* PatternFactory__get_data( fuzz_factory_t* p_fact );
// Get the size of the data pool for a given factory.
size_t PatternFactory__get_data_size( fuzz_factory_t* p_fact );
// Frees space used by a pattern factory by destroying it and its nodes' datas from the heap.
void PatternFactory__delete( fuzz_factory_t* p_fact );
// Explain the procedural string generation process, outputting to the given stream/file.
void PatternFactory__explain( FILE* p_stream, fuzz_factory_t* p_fact );
// Generate a pattern factory from an input pattern string.
//   This method is wrapped in the API calls.
fuzz_factory_t* PatternFactory__new( const char* p_pattern_str, fuzz_error_t* p_err );



#endif   /* _FUZZ_PATTERN_H */
