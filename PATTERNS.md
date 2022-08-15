# Patterns - Syntax & Usage

Nanofuzz patterns are regex-like strings of sometimes-sophisticated fuzzing templates. These templates
are used to direct the generation of fuzzer output by the tool.


## Terminology

There are a few different terms which are outlined for patterns and the nanofuzz project. In the source code
of the project and implementations thereof, the aim is to standardized how patterns are referenced. These terms
are present to help better define and standardize certain goals or features, both now and later, when necessary:

- __Pattern String__ (aka 'Schema'): The primary input string used to guide the generation of output strings.
It is what this document and really the whole project itself is centered around.
- __Mechanism__: A mechanism is loosely defined as a special piece of syntax from the pattern string that
performs a special function or acts to further customize the desired outcome strings.


## Mechanisms

The syntax for the different mechanisms is very similar to
[Regular Expression](https://regexr.com/ "The best regex site.")
syntax, with some slight modifications to gear the application more toward its explicit goal of _generating_
text rather than _parsing_ it.

As defined in the previous segment, a mechanism represents a basic unit of output string complexity that
goes beyond simple static string generation.

Here are the different types available:

- 
