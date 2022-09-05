/*
 * pattern.h
 *
 * Pattern syntax parsing.
 *
 */

#ifndef NANOFUZZ_PATTERN_H
#define NANOFUZZ_PATTERN_H

#include "fuzz_error.h"

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
// Max amount of subcontexts allowed per fuzz_factory_t context.
#define FUZZ_MAX_SUBCONTEXTS 32
// Max amount of different conditions which can be OR'd together with the '|' mechanism.
#define FUZZ_MAX_STEPS 32
// Max length of data a pattern is allowed to output in a single iteration.
//   This also controls the generator context's output size.
#define FUZZ_MAX_OUTPUT_SIZE ((1UL << 32) - 1)



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
    ref_shuffle             // shuffle (get_next) a variable output
} reference_type;



// Simple structure to maintain hash-to-generator-context values for factory subcontexts.
typedef struct _fuzz_subcontext_reference_t {
    unsigned long hash;    //the hash for the reference name (using 'djb2')
    // The string used in declaring the name of the variable/subcontext.
    char label[FUZZ_MAX_PATTERN_LABEL_NAME_LENGTH];
    // The generator context to use when shuffling the variable or initializing it.
    void* p_gen_ctx;   // this pointer is a 'void' type to avoid circular dependencies...
    // Maintain the most recently-generated subcontext data. This is never accessed outside
    //   the parent factory's generator through variable references.
    void* p_most_recent;   // same here
} fuzz_subcontext_t;


// Represents a single contiguous block of memory which all of the block items get joined into.
//   This is what nanofuzz will actually use in generating content.
typedef struct _fuzz_factory_t {
    // Pointer to the blob of nodes...
    void* node_seq;
    // ... of size count, each = sizeof(fuzz_pattern_block_t)
    size_t count;
    // Size needed for an associated generator context to allocate in its data pool.
    //   Represents the combined possible data output size.
    size_t max_output_size;
    // List of references attached to this factory as sub-factories by variable name.
    fuzz_subcontext_t subcontexts[FUZZ_MAX_SUBCONTEXTS];
    // Amount of subcontexts currently attached.
    size_t subcontexts_count;
} fuzz_factory_t;



// Holds information about a length-type reference and associated types.
typedef enum _fuzz_ref_len_type {
    // Raw types:
    raw_little = 1,
    raw_big,
    // ASCII string types:
    binary,
    decimal,
    hexadecimal,
    hex_upper,
    octal
} reference_length_type;

typedef struct _fuzz_reference_lenopts_t {
    reference_length_type type;   /**< The type of reference length to output. */
    unsigned short width;   /**< The width of the variable field in the output binary/string. */
    long long int add;   /**< The amount to add/subtract with the length of the generated variable. */
} fuzz_reference_length_options_t;

// A sub-structure which holds reference/variable information inside the final
//   factory node_seq.
typedef struct _fuzz_reference_t {
    // This label is the name of the variable assigned to the block when type is
    //   a declaration, the reference name otherwise. It's the 'glue' to the context.
    char label[FUZZ_MAX_PATTERN_LABEL_NAME_LENGTH];
    // The hash of the label name.
    unsigned long hash;
    // The sub-type for the reference.
    reference_type type;
    // The following OPTIONAL fields are only used (at the moment) for length references.
    fuzz_reference_length_options_t lenopts;
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
    // Represents a pointer to the node's data.
    //   This could point to a string, another List, etc. depending on the type.
    //   If this pointer is NOT NULL, it is assumed the referenced data is free-able.
    // TODO: Turn this into a union of all possible reference types, further reducing the
    //        need for including unsafe and scattered void ptrs in the final factory.
    void* data;
    // How many times to produce this specific node's data. Defaults to 1.
    fuzz_repetition_t count;
    // The type of pattern block being constructed: string, reference, sub, etc.
    pattern_block_type type;
} fuzz_pattern_block_t;



// Generate a pattern factory from an input pattern string.
//   This method is wrapped in the API calls.
fuzz_factory_t* PatternFactory__new( const char* p_pattern_str, fuzz_error_t** p_err );

// Frees space used by a pattern factory by destroying it and its nodes' datas from the heap.
void PatternFactory__delete( fuzz_factory_t* p_fact );

// Explain the procedural string generation process, outputting to the given stream/file.
void PatternFactory__explain( FILE* p_stream, fuzz_factory_t* p_fact );

// Return the pointer to a generator context attached to a pattern factory as a subcontext.
fuzz_subcontext_t* PatternFactory__get_subcontext( fuzz_factory_t* p_factory, char* p_label );



#endif   /* NANOFUZZ_PATTERN_H */
