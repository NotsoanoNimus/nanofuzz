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

#define NEW_PATTERN_BLOCK (fuzz_pattern_block_t*)calloc( 1, sizeof(fuzz_pattern_block_t) );

// 16MB max pattern length. TODO: Reconsider as the project matures.
#define FUZZ_MAX_PATTERN_LENGTH (1 << 24)
// Maximum length (including the null terminator) for a label's name in a pattern schema.
#define FUZZ_MAX_PATTERN_LABEL_NAME_LENGTH 9
// Pattern nesting cannot exceed 5 layers of complexity.
//   WARNING: Change this at your own peril.
#define FUZZ_MAX_NESTING_COMPLEXITY 5
// Maximum amount of separate items in a single 'range' mechanism (i.e. [1-2,3-4,5-6,...]).
#define FUZZ_MAX_PATTERN_RANGE_FRAGMENTS 16
// Max amount of ref shards allowed per fuzz_factory_t context.
#define FUZZ_MAX_VARIABLES 16
// Max amount of different conditions which can be OR'd together with the '|' mechanism.
#define FUZZ_MAX_STEPS 32



// Represents the different types of possible pattern blocks which can
//   be added to the fuzz factory.
typedef enum _pattern_block_type {
    reference = 1,
    string,
    range,
    sub,
    ret,
    branch_root,
    branch_jmp,
    end
} pattern_block_type;

// Different types of variable/reference related actions.
typedef enum _reference_type {
    ref_declaration = 1,    // declare a named variable & shuffle
    ref_reference,          // reference/paste a variable
    ref_count,              // output a number repr. a var's length
    ref_count_nullterm,     // same as above, +1
    ref_shuffle             // shuffle (get_next) a variable output
} reference_type;


// A finalized, contiguous stream of blocks which is used to construct fuzzer output.
typedef struct _fuzz_factory_t fuzz_factory_t;

// A sub-structure which holds reference/variable information inside the final
//   factory node_seq.
typedef struct _fuzz_reference_t {
    // This label is the name of the variable assigned to the block when type is
    //   a declaration, the reference name otherwise. It's the 'glue' to the context.
    char label[FUZZ_MAX_PATTERN_LABEL_NAME_LENGTH];
    // The sub-type for the reference.
    reference_type type;
} fuzz_reference_t;

// A ranging structure used in the pattern blocks to determine the amount of times, if set,
//   to repeat a block of pattern data. This is populated by the 'repetition' mechanism.
// Interestingly, this same struct is used in the 'range' mechanism to apply restrictions.
typedef struct _fuzz_repetition_t {
    unsigned char single;   // If non-zero, 'base' value is amount to generate; no ranging.
    unsigned short base;
    unsigned short high;
} fuzz_repetition_t;

// A structure populated by the lexer's parsing of the 'range' mechanism.
typedef struct _fuzz_range_t {
    // A linked list might be too slow here because when using the ranges, one
    //   would need to scan the array to 'randomly' select one of the possible
    //   constraining ranges. Instead, set a limit, and each instance of this
    //   struct will be limited to a max (customizable) ranges amount.
    fuzz_repetition_t fragments[FUZZ_MAX_PATTERN_RANGE_FRAGMENTS];
    size_t amount;
} fuzz_range_t;

// Used in branch ROOT mechanisms to elect a forward-path in the node sequence.
typedef struct _fuzz_branch_root_t {
    unsigned short steps[FUZZ_MAX_STEPS];   // the different forward-step counts available
    size_t amount;   // how many steps are defined to choose from
} fuzz_branch_root_t;

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
} fuzz_pattern_block_t;



// Return the private size of the fuzz factory structure.
size_t PatternFactory__sizeof(void);
// Get the blob data from the given fuzz factory struct.
void* PatternFactory__get_data( fuzz_factory_t* p_fact );
// Get the size of the data pool for a given factory.
size_t PatternFactory__get_data_size( fuzz_factory_t* p_fact );
// Get the attached factory count of blobbed pattern blocks.
size_t PatternFactory__get_count( fuzz_factory_t* p_fact );
// Get the shard index pointer for the factory.
void* PatternFactory__get_shard_index_ptr( fuzz_factory_t* p_fact );
// Frees space used by a pattern factory by destroying it and its nodes' datas from the heap.
void PatternFactory__delete( fuzz_factory_t* p_fact );
// Explain the procedural string generation process, outputting to the given stream/file.
void PatternFactory__explain( FILE* p_stream, fuzz_factory_t* p_fact );
// Generate a pattern factory from an input pattern string.
//   This method is wrapped in the API calls.
fuzz_factory_t* PatternFactory__new( const char* p_pattern_str, fuzz_error_t** p_err );

// Extra function for sizeof private type. TODO: Necessary?
size_t FuzzHash__sizeof( void );



#endif   /* _FUZZ_PATTERN_H */
