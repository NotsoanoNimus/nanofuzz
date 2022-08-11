# nanofuzz - Minimal, Expedient, """Smart""", & Efficient Fuzzing

Nanofuzz is a simple C-based fuzzing tool designed for the sake of efficiency and ease-of-use for small- to medium-sized projects.
It is optimized to create and return conforming content strings as quickly as possible, while still being random enough
to be worth using.

Rather than ad-lib content generation and extrapolation of fuzzing data structures, nanofuzz follows a strictly-defined
_pattern_ of generation which is explicitly given by its caller (and can be dynamic at run-time).

For familiarity's sake, this 'pattern' schema loosely follows the well-defined characteristics of regular expression
strings for generating matches. Other so-called "smart" (rather, structured) fuzzers usually have some complex format
about content generation that's custom, for better or for worse. But if you know **Regular Expressions** already, you're
able to practically use nanofuzz from the moment you compile it.


## The Goal: A Summary

- Simple, flexible, performant, structured fuzzing.
- Utmost benchmarked speed via selection of efficient algorithms and branchless coding techniques (where it matters).
- Extensible and easily integrated without disruption into various applications.


## A Note Regarding Speed

If ***speed*** is the ultimate goal of your fuzzing operation, then the CLI tool isn't what you're looking for. See the
`Static Library` section below for hooking nanofuzz into your compiled applications.

The CLI tool certainly has some startup cost to it: the program has to be loaded into memory, everything gets set up, options
from the command-line are checked, files read as applicable, etc etc etc. This is to say that executions of the CLI tool
are nice to generate batches of test output files according to a schema, or to pipe generated strings somewhere else via IPC.


## CLI Usage

When run at a terminal or via script, nanofuzz accepts a regex-like pattern in its STDIN input (with the `-i` switch), or through the
command-line `-p` option. Ordinarily, the tool will only generate __one line of output per call__ matching the
given pattern, but the `-l count` option can be used to generate _count_ amount of lines (using `-1` as an alias for "infinity").

To generate 10 lines according an input pattern:
```
# Also shows an example of using printf's ability to provide raw hexidecimal inputs to nanofuzz.
[user@place ~]$ printf "\x31\x31\x31HEADER_MAGIC[65-90]{1,}" | nanofuzz -l 10
111HEADER_MAGICABXUIWEOIUWHEFOIERJOIEJROIRVJER
111HEADER_MAGICPOKPOKPEORGEOIOWHIUEORWEIRUOWYEOIFUHWOIEUFHWOIEUTYWYWTEFDTWRQAQATQRFDWUEYFGWIEUFHIWEU [...]
111HEADER_MAGICAAACBERI
[ ... ]
111HEADER_MAGICAAAAAAAAAAAAAA
[user@place ~]$
```

For more complex patterns, the `-f` option can be used to point the fuzzer to an input file.

If the `-n` switch is provided to the fuzzer, line-breaks inside the input pattern (regardless of its source) are ignored.
This makes building very complex pattern sequences easy as they won't have to be 'minified'.


## Static Library

***NOT YET IMPLEMENTED** Nanofuzz is also available as a static library for use with compiled applications for hook
placements and callback event handlers on certain code-path changes or application signals.

#### Ideas
```c
/**** .h ****/
typedef struct _fuzz_str_t FuzzStr;
typedef struct _fuzz_stats_t FuzzStats;

/**** .c ****/
struct _fuzz_str_t {
    ...
};
struct _fuzz_stats_t {
    ...
};
```


## Pattern Examples

As an example, consider the regex-like pattern:
```
StaticStr[^0-31,127]{4,16}Another
```

... will generate fuzzy inputs that include the terms `StaticStr` at the beginning and `Another` at the end of the
string, with 4 to 16 bytes in between that are _NOT_ in ASCII ranges 0 to 31 (decimal) and the ASCII char 127.

Some sample generated sequences from the string:
```
StaticStr.*%7hDhrt^{h-_34Another
StaticStr_l,>3)ooAnother
```

Consider another example:
```
?param1=static&param2=AB(%[48-57]{2}){1,32}&param3=[0,32-126,128-255]{1,64}
```

... will generate some URL-like strings for testing what's presumably a parser, throwing in any mixture of URL-encoded
characters in `param2`, and null-y inputs interspersed through valid text in `param3`.

See the project **PATTERNS** document for more information regarding the nanofuzz pattern parser and pattern syntax.


### Null Bytes

Null bytes are simple to generate within content. A single null byte in the pattern is represented by: `[0]`

This can be useful when creating test strings to Base64-encode for BASIC authentication types/schemes,
for example: `[a-z,A-Z,48-57,1-9]{1,32}[0][a-z,A-Z,48-57,1-9]{1,32}`


## TODOs
- [ ] Unicode or extended character supports for binary data outside of the standard ASCII byte-to-byte ranges.
- [ ] Threaded generation using pthread.
- [ ] Detection of changed code-paths, or others methods by which nanofuzz can be compiled into a binary,
similar to the well-known AFL tool.
