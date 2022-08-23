#!/usr/bin/python3
#
# compliance.py
# [COPYRIGHT]
#
# Reads patterns from input text files, inputs them into the nanofuzz CLI,
#   and processes whether the generated strings conform to the input pattern.
#
# This happens through an intelligent process of converting nanofuzz inputs
#   into regular expressions for which the generated outputs should be tested.
#
# Input text files for this tester reside under the 'compliance' folder with
#   '.txt' extensions; generated output streams are sent to a corresponding
#   '.gen' file for compliance testing.
#
# Ideally, this script's startup/teardown should be run at minimum TEN times
#   when doing unit-testing, since sometimes generated content may not have
#   taken all possible branches or permutations otherwise. An actual mark of
#   'confidence' in nanofuzz output should be warranted when 500 calls to this
#   script can generate compliant output, regardless of pattern complexity.
#
# Be warned: some input patterns are exceedingly complex and since this test
#   script is using regex validation, running extensive tests should be
#   reserved for a 'make' call of its own, perhaps in the 'make release' path.
#
#

print( "========== NANOFUZZ COMPLIANCE TESTING ==========\n" )
