# Patterns - Syntax & Usage

Nanofuzz patterns are regex-like strings comprising sometimes-sophisticated fuzzing templates. These templates
are used to direct the generation of binary fuzzer output by the tool.


## Terminology

There are a few different terms which are outlined for patterns and the nanofuzz project. Some of these
may already be in active use; others might be tentative based on the progress of the project and its
planned features.

In the source code of the project and implementations thereof, the aim is to standardize how patterns are
referenced and described. These terms are present to help better define and standardize certain goals or
features, both now and later, when necessary.

| Term | Description |
| :--- | :--- |
| Pattern String | AKA a '_Pattern Schema_'. The primary input string used to guide the generation of output strings. |
| [Pattern] Block | An individual unit in the sequence of compiled instructions used to generate the fuzzer output from the input Pattern String. |
| Mechanism | A special character or segment in a pattern string which performs a special function or acts to further customize the generated outcome data. |
| Hook | A defined function used in instrumentation to gather statistics about code-path changes in a program based on fuzzer output. |
| Stats | A mutex'd position in memory which holds information about triggered Hooks and mutating fuzzer input states. |
| The Neophile | An optional, weak fuzzing algorithm that attempts to dynamically try slight mutations of a _Pattern Schema_ to probe different code paths. It has a _caustic affinity_ for trying new things. |


## Pattern Strings

Pattern Strings can be neatly organized with as much whitespace in them as desired. This allows some
human-readable formatting to be presented a la:
```
(
    (
        (static str[!,i,I]ng){1,3}
    ){2}
)
```

The whitespace from the input Pattern String will only be preserved in the command-line application
when using the `-w` (`--whitespace`) option.

You can review the `tests/compliance/` folder in the project for some sample Pattern Strings which
are thoroughly tested in every nanofuzz release build.

_Special Note_. All input Pattern Strings don't necessarily need to include only readable characters:
the command-line application using the `-f` switch to parse file data explicitly reads the input as
binary. Likewise, providing an input pattern _file_ along with the `-e` (`--evolve`) option
(___NOT YET IMPLEMENTED___) will use the binary data from the file as raw, static starting input from
which to try different fuzzing permutations.


## Mechanisms

The syntax for the different Mechanisms is very similar to [Regular Expression](https://regexr.com/ "The best regex site.")
syntax, with some slight modifications to gear the application more toward its explicit goal of _generating_
text rather than _parsing_ it of course.

As defined in the previous segment, a Mechanism represents a _basic unit_ of output string __complexity__ and
__variation__ that goes beyond simple static string generation. This section provides an overview of the
varying mechanisms used to create fuzzy outputs, and dives into examples for each in the following sub-sections.

| Mechanism | Symbol | Example | Brief Description |
| ---: | :---: | :--- | :--- |
| Static String | `any string` | `abcde` | The most basic unit, static strings never vary in fuzzer outputs and always generate how they're entered. |
| Escape Character | `\character` | `\n` | Causes the following character to be output as a literal value, or as something which can't be otherwise reperesented easily in the input Pattern String. |
| Repetition | `{...}` | `abc{,3}` | Changes the varying amount of times the previous Block will run. Can be a range from 0 to 65535. |
| Optional | `?` | `this\sis(\snot)?\sok` | Simple Repetition alias. The preceding Block will either appear once or not at all. Equivalent to `{0,1}`. |
| Range | `[...]` | `[^\x00,0-9,A-Z,\xF0-\xFF]{,4}` | Specifies a set of characters (or an inverse thereof) which could be randomly chosen as part of the output data. |
| Wildcard | `*` | `123abc*{3}` | Simple Range alias. Outputs any single character/byte from `0x00` to `0xFF`; therefore equivalent to `[\\x00-\\xFF]`. |
| Subsequence | `(...)` | `(abc(def){2,4}(ghi){1,3}jkl){1,2000}` | Creates a delimited subsegment of instructions in the output which can be treated as a single Block (unit) in output generation. |
| Branch | `...\|...` | `a\|b\|(cde)\|f` | Randomly elects to output one of the possible [single] Blocks with the pipe '\|' operator between them. |
| Variable | `<...>` | `((me,\s){4}me!{,3})<$VARNAME>` | Creates sub-patterns inside the primary generator which can be dynamically referenced, counted, reshuffled, etc. |


### Static Strings

Static strings are mostly-unchanging mechanisms that exist within any input Pattern. Writing a static
string into an input Pattern indicates that the output text shouldn't look any different unless the
mutation algorithm fuzzes it a bit (when enabled).

Static strings look like the following:
```
generate\sthis\sstatic\sstring\severy\stime
```

... where the `\s` is an escape character (see below) representing a single _space_. This will
consistently write the text `generate this static string every time` in the fuzzer output.


### Escape Characters

Much like static strings, escapes are mostly-unchanging and represent ASCII-style versions of special
character codes that are not easily represented otherwise. All escape characters are preceded by the
special `\\`. [Read more about them here](https://en.wikipedia.org/wiki/Escape_character).

While any character can be escaped, the following escape characters are interpreted by nanofuzz to
indicate a special character must be output:
```
\a ==> Code 0x07, BEL (bell) character
\b ==> Code 0x08, BS (backspace) character
\f ==> Code 0x0C, FF (form-feed) character
\n ==> Code 0x0A, LF (line-feed) character
\r ==> Code 0x0D, CR (carriage-return) character
\s ==> Code 0x20, SPACE character (a plain space)
\t ==> Code 0x09, TAB character
\v ==> Code 0x0B, VT (vertical tab) character
```

It's important to note that hexidecimal, decimal, and octal escape codes like `\xF3` are only available
__inside Range mechanisms__ at this time. See that section below for more information.


### Repetitions

Repetition mechanisms change the amount of times the preceding Block is run in the output generator. The
amount of times which a Block should/could be repeated can be specified as a single value or as a range
over values, in which case the generator will randomly pick a value in the range each time the Block is
encountered.

Repetition range values can go from `0` to `65535`, so they are essentially `unsigned short` values that
max out at 16 bits wide.

The syntax of a repetition appears as:
```
BLOCK{low,high}
  or
BLOCK{low}
  or
BLOCK{low,}
  or
BLOCK{,high}

BLOCK ==> Any mechanism which creates a Block for the generator to process. This could be a
            static string, a range, an entire subsequence, or a variable reference, for example.
low   ==> The lower bound of times to repeat the block. If this is on its own without a comma,
            the generator will explicitly generate the BLOCK 'low' times. If this appears with
            a comma but no 'high' value, 'high' is automatically assumed to be 65535.
high  ==> The upper bound of times to repeat the block. If following a blank 'low' count, the
            generator assumes 'low' is the value 0.
```

For example, `c{3,5}` will generate the static string `c` __3 to 5 times__ each time the generator
encounters that Block.

To take the concept a bit further, using a repeating subsequence like:
```
(abcd{5,10}e{,1}){2}
```
... has the chance to generate an output like `abcddddddeabcdddddddd`, where the "inner" part of the
subsequence mechanism (see below) is iterated twice (`{2}`) and the `d{5,10}` evaluated as "write `d`
5 to 10 times". The `e{,1}` is interpreted as "write `e` 0 to 1 times". This same sequence (`e{,1}`)
can be written as `e?` to accomplish the same goal more concisely.


### Ranges

Range mechanisms allow the choice of any random character in a given range (or inverse range) to be
written to the fuzzer output. Ranges can include single characters or a few different character
ranges.


### Subsequences




### Branches




### Variables

