/*
 * api.h
 *
 * Main API hooks to publicly use with the static library fuzzer.
 *
 */

#ifndef _FUZZ_API_H
#define _FUZZ_API_H

#include <stdint.h>

#include "fuzz_error.h"

// 16MB max pattern length. TODO: Reconsider as the project matures.
#define FUZZ_MAX_PATTERN_LENGTH (1 << 24)
// Maximum length (including the null terminator) for a label's name in a pattern schema.
#define FUZZ_MAX_PATTERN_LABEL_NAME_LENGTH 9
// Pattern nesting cannot exceed 5 layers of complexity.
//   WARNING: Change this at your own peril.
#define FUZZ_MAX_NESTING_COMPLEXITY 5


#endif   /* _FUZZ_API_H */
