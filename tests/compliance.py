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


import sys, os, re, traceback, timeit

def usage():
    print( "USAGE: " + sys.argv[0] + " {iterations}" )
    sys.exit(1)


# Simple progress bar.
def __progress_bar( files, total_files ):
    if total_files == 0:
        return
    print( "\r\tParsing [", end="" )
    hashes = ""
    max_hashes = 40
    hashes_count = int( (files/total_files) * max_hashes )
    for x in range(hashes_count):
        hashes += "■"
    for x in range(max_hashes-hashes_count):
        hashes += " "
    color_print( hashes, BLUE, is_newline=False )
    print( "] (" + str(files) + "/" + str(total_files) + ")", end="" )


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


# Remove all .gen files created by the fuzzer.
def clean_gen_files():
    for file in os.listdir( myfullpath + "/compliance/" ):
        if file.endswith( ".gen" ):
            os.remove( myfullpath+"/compliance/"+file )



# Nanofuzz input pattern to regex string conversion.
def pattern_to_regex( pattern ):
    _regex = pattern

    # Fix special chars that aren't always escaped in nanofuzz inputs.
    _regex = re.sub( r'([^<\[\\])([+\^\$\.])', r'\1\\\2', _regex )
    _regex = re.sub( r'^([+\^\$\.])', r'\\\1', _regex )


    # Fix repetitions and make them more explicit.
    _regex = re.sub( r'([^\\]){,', r'\1{0,', _regex )
    _regex = re.sub( r',}', ',65535}', _regex )


    # Fix other repetition or range shortcut aliases.
    _regex = re.sub( r'\*', '[\\x00-\\xFF]', _regex )


    # Fix ranges. Get rid of unescaped commas and convert decimal escapes to hex.
    def dec_to_hex( matchobj ):
        try:
            x = int( matchobj.group(2) )
            return '[' + matchobj.group(1) + '\\x' + str( hex(x) ).split('x')[-1] + matchobj.group(3) + ']'
        except:
            return '[' + matchobj.group(1) + matchobj.group(2) + matchobj.group(3) + ']'

    for x in range( 64 ):
        _regex = re.sub( r'\[([^\]]*?)\\d([0-9]+)([^\]]*?)\]', dec_to_hex, _regex )

    #   Next, remove commas from ranges. This is hacky but it works OK since
    #   ranges are limited by nanofuzz to being something like 16 or 32 items in number.
    for x in range( 32 ):
        _regex = re.sub( r'\[([^\]]*?)([^\\]),([^\]]*?)\]', r'[\1\2\3]', _regex )


    # Scrub variables and expand where included.
    #   Remove shuffle operators for vars, but be careful not to destroy any existing branches.
    #   Ex: 'a|b|<%VAR>|c|d' --> 'a|b|(.{0})|c|d'   /// 'a|b|c|d|<%VAR>' --> 'a|b|c|d|(.{0})'
    _regex = re.sub( r'<%[A-Za-z0-9]+>', '(.{0})', _regex )

    # Replace variable length types with a simple regex.
    _regex = re.sub( r'<#d.*?:[0-9A-Z]+?>', '([0-9]+?)', _regex )
    _regex = re.sub( r'<#x.*?:[0-9A-Z]+?>', '([0-9A-Fa-f]+?)', _regex )
    _regex = re.sub( r'<#o.*?:[0-9A-Z]+?>', '([0-7]+?)', _regex )
    _regex = re.sub( r'<#b.*?:[0-9A-Z]+?>', '([01]+?)', _regex )
    _regex = re.sub( r'<#[rgl]([0-9]).*?:[0-9A-Z]+?>', r'([\x00-\xFF]{1,\1}?)', _regex )

    # Find variable declarations and expand their occurrences.
    try:
        while True:   #keep going until no more ")<$" instances (declarations)
            loc = _regex.index( ")<$" )
            # Scan backward until the right '(' is found.
            rev = _regex[(loc-1)::-1]
            rev = re.sub( r'[()]\\', "__", rev )
            nest = 1
            start_paren = 0
            for x in rev:
                if x == ')':
                    nest += 1
                elif x == '(':
                    nest -= 1

                if nest == 0:
                    break
                else:
                    start_paren += 1

            statement = _regex[(loc-1-start_paren):(loc+1)]
            #print("VAR IS: |"+statement+"|")

            varname = ""
            for x in _regex[(loc+1):(loc+12)]:
                if x == '>':
                    break
                elif x == '<' or x == '$':
                    continue
                varname += x

            #print( "--- NAME is |"+varname+"|")
            # Replace occurrences in the original string.
            _regex = _regex.replace( (statement + "<$" + varname + ">"), "" )
            #print( "\t\tReplacing '{}' vars with '({})'".format( varname, statement ) )
            _regex = _regex.replace( ("<@" + varname + ">"), statement )
    except:
        pass   #exit loop

    # Fix branches which are not wrapped in parens. This is pretty sloppy and broken honestly.
    #   Ex: a|b|(cde)|g|(hij) --> (a|b|(cde)|g|(hij)) TODO
    #   NOTE: By this point, ALL variable expressions have been translated. The only things
    #       allowed in an enclosed branch are (1) static and possibly-escaped characters, and
    #       subsequences.
    # TODO: Right now I'm not able to exactly model the nanofuzz ambiguity of '123a|b|c456'
    #       which apparently the py regex module wants to explicitly see as '123(a|b|c)456'.
    #       This is a gap in my knowledge: I always thought re automatically assumed the latter.
    """
    cpy = _regex
    def _search_sub( matchobj ):
        for match in matchobj:
            tgt = match[3]
            _exp = ""
            for x in range( 32 ):
                _exp_s = _exp
                _exp = re.sub( r'((\\?[^\|]\|)+)(\\?[^\|])', r'(\1\3)', tgt )
                if _exp_s == _exp:
                    break
            cpy = _regex.replace( '('+tgt+')', '('+_exp+')' )

    _search_sub(  re.findall( r'(?!\((([^\|\\]\|)+([^\|\\]))\))\(([^\(\)\|]+\|[^\(\)]+)\)', cpy )  )
    """

    #_regex = re.sub( r'\|(\\?[^\\\(\|])([^\|])', r'|\1)\2', _regex )
    #_regex = re.sub( r'([^\|])(\\?[^\)\|])\|', r'\1(\2|', _regex )

    # Finally, test the regex 'compile' function on this. If the regex
    #   is not valid, this will throw an exception.
    #print( "\tCompiling: |" + _regex + "|" )
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
    clean_gen_files()

    # Only process .txt files.
    if not file.endswith( ".txt" ):
        continue
    else:
        print( "\nPattern file: " + file )
        tested_file_count += 1

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
    regex = ""
    regex_obj = None
    try:
        regex = pattern_to_regex( content )
        regex_obj = re.compile(  bytes( regex, encoding = 'utf8' ), flags = re.MULTILINE  )
        if regex_obj is None or regex is None or len(regex) < 1:
            raise Exception( "invalid expression" )
    except:
        color_print( "Failed to transform the content string into a "
            + "parseable regular expression.", RED, is_bold=True )
        #traceback.print_exc()
        failed += 1
        continue

    print( "Regex  : ", end="" )
    color_print( regex, PURPLE )


    # Begin tester iterations and attempt to time them.
    print( "\tGenerating...    ", end="" )
    sys.stdout.flush()

    call_ec = 255
    fuzzer_call = ( myfullpath + "/../bin/nanofuzz -f " + myfullpath+"/compliance/"+file
        + " -l " + str(iters) + " -o " + myfullpath+"/compliance/"
        + re.sub(r'(?i)\.txt$', '', file) + "*.gen >&/dev/null" )

    gen_time = timeit.timeit( lambda: os.system(fuzzer_call), number=1 )

    call_ec >>= 8
    if call_ec != 0:
        color_print( "\rFailed to call nanofuzz for the input pattern.", RED, is_bold=True )
        failed += 1
        continue
    else:
        print( "Finished content generation in ", end="" )
        color_print( str(round(gen_time,3))+" seconds", WHITE, is_bold=True, is_newline=False )
        print( ".", end="" )


    # Compare the binary regex_obj against the binary gen-file contents.
    #   TODO: This is quite inefficient (probably don't care); total_files should == iters
    total_files = 0
    for genfile in os.listdir( myfullpath+'/compliance/' ):
        if genfile.endswith( ".gen" ):
            total_files += 1
    if total_files != iters:
        color_print( "\rFailed to call nanofuzz for the input pattern.               ",
            RED, is_bold=True )
        failed += 1
        continue
    else:
        print( "\n", end="" )

    files = 0
    reg_fail = 0
    for genfile in os.listdir( myfullpath+'/compliance/' ):
        if genfile.endswith( ".gen" ):
            with open( myfullpath+'/compliance/'+genfile, mode='rb' ) as genhnd:
                files += 1
                __progress_bar( files, total_files )
                file_content = genhnd.read()
                if re.fullmatch( regex_obj, file_content ) is None:
                    try:
                        os.rename( myfullpath+'/compliance/'+genfile, myfullpath+'/compliance/errors/'+genfile )
                    except:
                        pass
                    reg_fail += 1

    # Simple tracking.
    if reg_fail == 0:
        color_print( "\n\tSuccess for "+str(files)+" of "+str(files)+" files.", GREEN )
        succeeded += 1
    else:
        color_print( "\n\tFailed regex tests for "+str(reg_fail)+" of "+str(files)+" files.", RED )
        failed += 1


# Post-test clean-up.
clean_gen_files()



# Print a summary of the tests. TODO: Clean up.
color_print( "\n\n\tTested ", is_bold=True, is_newline=False )
color_print( str(tested_file_count), YELLOW, is_bold=True, is_newline=False )
color_print( " Files; ", is_bold=True, is_newline=False )
color_print( str(succeeded), GREEN, is_bold=True, is_newline=False )
color_print( " Successes; ", is_bold=True, is_newline=False )
color_print( str(failed), RED, is_bold=True, is_newline=False )
color_print( " Failures\n\n", is_bold=True, is_newline=False )
