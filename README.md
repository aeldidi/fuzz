`github.com/aeldidi/fuzz`
=========================

`fuzz` is a library for fuzzing C code. Fuzz testing allows generating random
input in a specific structure which can be used as input to test some function,
possibly uncovering cases in code that a programmer didn't think of. When a
fuzz test fails, the library will generate simpler versions of the input, and
only report the simplest input which still failed the test. This is called
"shrinking the input" and is useful to help remove extraneous information from
a test case, which makes fixing the bug easier.

`fuzz` is a fork of [theft](https://github.com/silentbicycle/theft) with small
modifications and support for Windows.

`fuzz` does not depend on anything except for either:

- A POSIX.1-2008-compatible C environment, or
- A Windows C development environment.

Usage
-----

Go to the releases page and download the latest release, which contains a self
contained `fuzz.c` and `fuzz.h` which you can simply compile and use.

Documentation
-------------

For usage documentation, see [doc/usage.md](doc/usage.md).

For more info about shrinking and auto-shrinking, see
[doc/shrinking.md](doc/shrinking.md).

`fuzz` can fork before running properties, to shrink failures that make the
code under test crash or exceed an optional timeout. For more info, see
[doc/forking.md](doc/forking.md).

License
-------

`aeldidi/fuzz` is made availible under the ISC license, however it contains
implementations of the [Mersenne Twister][mt] PRNG and the [FNV-1a][fnv]
hashing algorithm - these are licensed as [BSD-3-Clause][bsd3] and [CC0][cc0]
respectively.

The tests make use of the [greatest][] testing library, which is also availible
under the ISC license.

[greatest]: https://github.com/silentbicycle/greatest
[mt]: http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
[fnv]: http://www.isthe.com/chongo/tech/comp/fnv/
[bsd3]: https://opensource.org/licenses/BSD-3-Clause
[cc0]: https://creativecommons.org/share-your-work/public-domain/cc0/
