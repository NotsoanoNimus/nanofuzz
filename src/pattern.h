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

// Different types of variable/reference related actions.
typedef enum _reference_type {
    ref_declaration = 1,    // declare a named variable & shuffle
    ref_reference,          // reference/paste a variable
    ref_count,              // output a number repr. a var's length
    ref_shuffle             // shuffle (get_next) a variable output
} reference_type;


// A finalized, contiguous stream of blocks which is used to construct fuzzer output.
typedef struct _fuzz_factory_t fuzz_factory_t;

// A sub-structure which holds reference/variable information.
typedef struct _fuzz_reference_t fuzz_reference_t;

// A ranging structure used in the pattern blocks to determine the amount of times, if set,
//   to repeat a block of pattern data. This is populated by the 'repetition' mechanism.
// Interestingly, this same struct is used in the 'range' mechanism to apply restrictions.
typedef struct _fuzz_repetition_t {
    unsigned char single;   // If non-zero, 'base' value is amount to generate; no ranging.
    unsigned short base;
    unsigned short high;
} __attribute__((__packed__)) fuzz_repetition_t;

// A structure populated by the lexer's parsing of the 'range' mechanism.
typedef struct _fuzz_range_t {
    // A linked list might be too slow here because when using the ranges, one
    //   would need to scan the array to 'randomly' select one of the possible
    //   constraining ranges. Instead, set a limit, and each instance of this
    //   struct will be limited to a max (customizable) ranges amount.
    fuzz_repetition_t fragments[FUZZ_MAX_PATTERN_RANGE_FRAGMENTS];
    size_t amount;
} __attribute__((__packed__)) fuzz_range_t;

// A block (or "piece") of an interpreted part of the input pattern information.
typedef struct _fuzz_pattern_block_t {
    // The type of pattern block being constructed: string, reference, sub, etc.
    pattern_block_type type;
    // Represents a pointer to the node's data.
    //   This could point to a string, another List, etc. depending on the type.
    //   If this pointer is NOT NULL, it is assumed the referenced data is free-able.
    void* data;
    // How many times to produce this specific node's data. Defaults to 1.
    fuzz_repetition_t count;
} __attribute__((__packed__)) fuzz_pattern_block_t;



// Get the blob data from the given fuzz factory struct.
void* PatternFactory__get_data( fuzz_factory_t* p_fact );
// Get the size of the data pool for a given factory.
size_t PatternFactory__get_data_size( fuzz_factory_t* p_fact );
// Get the attached factory count of blobbed pattern blocks.
size_t PatternFactory__get_count( fuzz_factory_t* p_fact );
// Frees space used by a pattern factory by destroying it and its nodes' datas from the heap.
void PatternFactory__delete( fuzz_factory_t* p_fact );
// Explain the procedural string generation process, outputting to the given stream/file.
void PatternFactory__explain( FILE* p_stream, fuzz_factory_t* p_fact );
// Generate a pattern factory from an input pattern string.
//   This method is wrapped in the API calls.
fuzz_factory_t* PatternFactory__new( const char* p_pattern_str, fuzz_error_t** p_err );



#endif   /* _FUZZ_PATTERN_H */
