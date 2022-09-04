/*
 * pattern_tests.c
 *
 * Tests nanofuzz pattern parsing and content generation.
 *   Note that this really only tests the parser's ability to interpret and
 *   generate fuzzer content without segfaults or crashes otherwise. It also
 *   conveniently tests intentional crashes to make sure bad parser input is
 *   never accepted.
 *
 * The actual check of conformance and consistency to expectations of a regex is
 *   done in the adjacent python 'compliance' script.
 *
 */

#include <stdio.h>
#include <signal.h>
#include <criterion/criterion.h>

#include "../src/api.h"


// Test patterns which should NOT form a valid fuzzer context.
//   The keyword 'dead' is used to avoid confusion between VALID and INVALID terms.
#define TEST_DEAD(name,thepattern) \
    Test(dead_pattern,name) { \
        const char* p_str = thepattern; \
        nanofuzz_context_t* p_ctx = Nanofuzz__new( p_str, 1, oneshot, &p_err_ctx ); \
        cr_assert( NULL == p_ctx, "The nanofuzz context must be invalid for this input." ); \
    }

// Test for conditions where the generator overflows or otherwise dies.
#define TEST_OVERFLOW(name,thepattern) \
    Test(dead_pattern,name) { \
        const char* p_str = thepattern; \
        nanofuzz_context_t* p_ctx = Nanofuzz__new( p_str, 1, oneshot, &p_err_ctx ); \
        cr_assert( NULL != p_ctx, "The nanofuzz context is not valid for this input." ); \
        nanofuzz_data_t* p_data = Nanofuzz__get_next( p_ctx ); \
        cr_assert( NULL == p_data, "Generator must crash for this test." ); \
        Nanofuzz__delete_data( p_ctx, p_data ); \
        Nanofuzz__delete( p_ctx ); \
    }

// Test patterns which should generate valid data and a valid fuzzer context.
#define TEST_VALID(name,thepattern) \
    Test(valid_pattern,name) { \
        const char* p_str = thepattern; \
        nanofuzz_context_t* p_ctx = Nanofuzz__new( p_str, 100, oneshot, &p_err_ctx ); \
        cr_assert( NULL != p_ctx, "The nanofuzz context is not valid for this input." ); \
        for ( int i = 0; i < 100; i++ ) {\
            nanofuzz_data_t* p_data = Nanofuzz__get_next( p_ctx ); \
            cr_assert( NULL != p_data, "Generated fuzzer data cannot be NULL." ); \
        } \
        Nanofuzz__delete( p_ctx ); \
    }



// Define test-suite-level configuration for each VALID pattern test.
//   This will print error information from the test to possibly help with why it failed.
nanofuzz_error_t* p_err_ctx;
void _pattern_setup(void) {
    p_err_ctx = NULL;
}
void _pattern_teardown(void) {
    if (  Error__has_error( p_err_ctx )  ) {
        Error__print( p_err_ctx, stdout );
    }
    p_err_ctx = NULL;
}
TestSuite(valid_pattern, .init = _pattern_setup, .fini = _pattern_teardown);


// These dummy tests should NEVER fail and are here to verify Criterion is OK.
//   Don't need many.
Test(dummytests, intval) {
    int i = 5;
    cr_expect( i == 5, "i should equal 5" );
}
Test(dummytests, segfault, .signal = SIGSEGV) {
    int* p = NULL;
    *p = 7;
}



//////////////////////////////////////////////////////////////////////////////////////////
// TESTS FOR VALID PATTERNS.
//////////////////////////////////////////////////////////////////////////////////////////

// Static strings & escapes.
TEST_VALID(staticstr1, "aaaaa");
TEST_VALID(staticstr2, "\\r\\n\\x37\\f\\x2f\\s234");
TEST_VALID(staticstr3, "a\\<\\[A-Z\\]\\]");
TEST_VALID(staticstr4, "aaa\\{aa");
TEST_VALID(staticstr5, "aa\\r\\n\\r\\n\\b\\xff\\v\\t\\0raaa\\\\");

// Repetition mechanisms.
TEST_VALID(repetition1,  "a{1,3}bcd");
TEST_VALID(repetition2,  "a{,3}bcd");
TEST_VALID(repetition3,  "a{0,}bcd");
TEST_VALID(repetition4,  "a{65534,65535}bcd");
TEST_VALID(repetition5,  "a{1,}bcd");
TEST_VALID(repetition6,  "a{0,1}bcd");
TEST_VALID(repetition7,  "a{001,73}bcd");
TEST_VALID(repetition8,  "abcd{1,3}");
TEST_VALID(repetition9,  "abcd{0,}");
TEST_VALID(repetition10, "abcd{,1}");







//////////////////////////////////////////////////////////////////////////////////////////
// TESTS FOR DEAD (INVALID) PATTERNS OR OTHER MISC PROBLEM CONDITIONS.
//////////////////////////////////////////////////////////////////////////////////////////

// Misc & overflow failures.
TEST_OVERFLOW(overflow1, "(abc(def(ghi(jkl){65535}){65535}){65535}){65535}");

// Unexpected characters.
TEST_DEAD(unexpected1,  "a(bcd))");
TEST_DEAD(unexpected2,  "a(b((cd);)oo))---");
TEST_DEAD(unexpected3,  "a)bcd");
TEST_DEAD(unexpected4,  "a>bcd");
TEST_DEAD(unexpected5,  "a]bcd");
TEST_DEAD(unexpected6,  "a}bcd");
TEST_DEAD(unexpected7,  ")abcd");
TEST_DEAD(unexpected8,  ">abcd");
TEST_DEAD(unexpected9,  "]abcd");
TEST_DEAD(unexpected10, "}abcd");

// Repetition mechanisms.
TEST_DEAD(repetition1, "a{3,bcd");
TEST_DEAD(repetition2, "a{,0}bcd");
TEST_DEAD(repetition3, "a{3,a}bcd");
TEST_DEAD(repetition4, "a{a,3}bcd");
TEST_DEAD(repetition5, "a{a,a}bcd");
TEST_DEAD(repetition6, "a{3,5\\}}bcd");
TEST_DEAD(repetition7, "a\\{3,5}bcd");


// Subsequence mechanisms and nesting.
TEST_DEAD(subsequence1, "a(bcd");

// Range mechanisms.
TEST_DEAD(range1, "123[A-Z456");
