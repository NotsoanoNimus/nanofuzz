/*
 * pattern_tests.c
 *
 * Tests nanofuzz pattern parsing and content generation.
 *
 */

#include <criterion/criterion.h>



Test(dummytests, basedummy) {
    int i = 5;
    cr_expect( i == 5, "i should equal 5" );
}
