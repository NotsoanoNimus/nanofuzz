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


import sys, os, re

def usage():
    print( "USAGE: " + sys.argv[0] + " {iterations}" )
    sys.exit(1)


# Terminal colors for our delight (thank you, StackOverflow).
RED    = "\033[1;31m"
BLUE   = "\033[1;34m"
CYAN   = "\033[1;36m"
PURPLE = "\033[1;35m" #or "magenta"
GREEN  = "\033[0;32m"
WHITE  = "\033[1;37m"
YELLOW = "\033[1;33m"
RESET  = "\033[0;0m"
BOLD   = "\033[;1m"

def color_print( msg, color = WHITE, is_bold = False, is_newline = True ):
    if is_bold is True:
        print( BOLD, end="" )

    if is_newline is True:
        print( color + msg + RESET )
    else:
        print( color + msg + RESET, end="" )


# Nanofuzz input pattern to regex string conversion.
def pattern_to_regex( pattern ):


    # Finally, test the regex 'compile' function on this. If the regex
    #   is not valid, this will throw an exception.
    re.compile( _regex )
    return _regex



color_print( "========== NANOFUZZ COMPLIANCE TESTING ==========", is_bold=True )

# Get CLI options and arguments.
if len(sys.argv) < 2:
    usage()

iters = 0
try:
    iters = int( sys.argv[1] )
except:
    usage()

print( " `----> ", end="" )
color_print( str(iters), color=CYAN, is_bold=True, is_newline=False )
print( " iterations for each pattern." )


# Preliminary setup.
myfullpath = os.path.dirname( os.path.realpath(__file__) )
whitespaces = ['\x09', '\x0A', '\x0B', '\x0C', '\x0D', '\x20']
tested_file_count = 0
failed = 0
succeeded = 0

for file in os.listdir( myfullpath + "/compliance/" ):
    # Setup.
    success = False
    tested_file_count += 1

    # Only process .txt files.
    if not file.endswith( ".txt" ):
        # If a .gen file is encountered, nuke it from orbit.
        if file.endswith( ".gen" ):
            os.remove( myfullpath+"/compliance/"+file )
        # Carry on.
        failed += 1
        continue
    else:
        print( "\nPattern file: " + file )

    # Read the file's content as a string.
    content = None
    with open( myfullpath+"/compliance/"+file ) as hfile:
        content = hfile.read()

    # Replace any possible whitespace characters in the input.
    for x in whitespaces:
        content = content.replace( x, "" ) if content is not None else None

    # If the content couldn't be read, exit. Otherwise, strip out all whitespace.
    if content is None or len(content.strip()) < 1:
        print( "~~~~~ Failed to read file content." )
        failed += 1
        continue
    else:
        print( "Content: ", end="" )
        color_print( content, PURPLE )

    # Translate the content into a corresponding regex to use for validating the generation.
    try:
        regex = pattern_to_regex( content )
    except:
        color_print( "Failed to transform the content string into a "
            + "parseable regular expression.", RED, is_bold=True )
        failed += 1
        continue

    # Begin tester iterations.
    call_ec = os.system( myfullpath + "../bin/nanofuzz -f " + myfullpath+"/compliance/"+file
        + " -l " + str(iters) + " -o " + myfullpath+"/compliance/"
        + re.sub(r'(?i)\.txt$', '', file) + "*.gen" )

    call_ec >>= 8
    if call_ec != 0:
        color_print( "Failed to call nanofuzz for the input pattern.", RED, is_bold=True )

    # Simple tracking.
    if success is True:
        succeeded += 1
    else:
        failed += 1


# Print a summary of the tests. TODO: Clean up.
color_print( "\n\n\tTested ", is_bold=True, is_newline=False )
color_print( str(tested_file_count), YELLOW, is_bold=True, is_newline=False )
color_print( " Files; ", is_bold=True, is_newline=False )
color_print( str(succeeded), GREEN, is_bold=True, is_newline=False )
color_print( " Successes; ", is_bold=True, is_newline=False )
color_print( str(failed), RED, is_bold=True, is_newline=False )
color_print( " Failures\n\n", is_bold=True, is_newline=False )
