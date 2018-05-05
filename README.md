Strngr: Static analysis of static data comparisons
==================================================

Strngr is a rewrite of the research tool "Stringer" described in the following publication:

[Stringer: Measuring the Importance of Static Data Comparisons to Detect Backdoors and Undocumented Functionality](https://link.springer.com/chapter/10.1007%2F978-3-319-66399-9_28) by Sam L. Thomas, Tom Chothia and Flavio D. Garcia (University of Birmingham, UK).

Strngr provides an ordering of functions and the static data used in comparisons that influence their control-flow. This ordering is intended to serve as a starting point for manual analysis when attempting to locate backdoor-like and undocumented functionality triggered by comparison with hard-coded static data, e.g., hard-coded credentials.

For further information regarding the implementation of Strngr, please refer to the aforementioned publication and the project website: [link](http://badseed.re).

Implementation
==============

The current implementation supports ARM targets and requires IDA Pro 6.8+ as part of its binary loader. The original implementation of "Stringer" was written in OCaml and depended upon [BAP](https://github.com/BinaryAnalysisPlatform/bap); the intention of this reimplementation is to provide an open-source implementation that does not have any significant dependencies. In order to simplify some implementation details, Strngr depends upon a modified version of [capstone-rs](https://github.com/capstone-rust/capstone-rs) and [capstone-sys](https://github.com/capstone-rust/capstone-sys), to which we have added support for [capstone next branch](https://github.com/aquynh/capstone/tree/next), which, among other features, provides register read/write side-effect information for each instruction, which we make use of in our call-site analyses.

Both the heuristics for locating comparison functions and scoring metric used in Strngr differ from those described in the publication above, but have the same goal. The algorithms used in this implementation are a progression of those presented in that work.

To do
=====

- Complete prioritisation of static data comparison functions to avoid false-positives.
- Add support for MIPS and AArch64.

Usage
=====

```{.bash}
$ cargo run -- /path/to/binary
```

For use cases, see the project website.
