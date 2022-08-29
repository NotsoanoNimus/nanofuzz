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
| Range | `[...]` | `[^\x00,0-9,A-Z,\xF0-\xFF]{,4}` | Specifies a set of characters (or an inverse thereof) which could be randomly chosen as part of the output data. |
| Subsequence | `(...)` | `(abc(def){2,4}(ghi){1,3}jkl){1,2000}` | Creates a delimited subsegment of instructions in the output which can be treated as a single Block (unit) in output generation. |
| Variable | `<...>` | `((mystring){1,5})<$VARNAME>` | Creates sub-patterns inside the primary generator which can be dynamically referenced, counted, reshuffled, etc. |
| Branch | `...\|...` | `a\|b\|(cde)\|f` | Randomly elects to output one of the possible [single] Blocks with the pipe '\|' operator between them. |
