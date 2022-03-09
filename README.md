theft: property-based testing for C
===================================

theft is a C library for property-based testing. Where example-based testing
checks test results for specific input, theft tests assert general properties
("for any possible input, [some condition] should hold"), generate input, and
search for counter-examples that make the test fail. If theft finds any
failures, it also knows how to generate and test simpler variants of the input,
and then report the simplest counter-example found.

theft is distributed under the ISC license.

theft does not depend on anything except for either:

- A POSIX.1-2008-compatible C environment, or
- An implementation of the Win32 API (implemented for Windows).

Building with Meson
-------------------

The reccomended way to build theft is using the
[Meson Build System](https://mesonbuild.com).

    meson build
    cd build
    meson compile

The tests can then be run like so:

    meson test

To install libtheft and its headers:

    meson install

To vendor theft, you'd add the following in your `meson.build`:

    theft = subproject('theft')
    theft_dep = theft.get_variable('theft_dep')

And then use it like any other `meson` dependency.

Building with GNU Make
----------------------

To build, using GNU make:

    make

Note: You may need to call it as `gmake`, especially if building on BSD.

To build and run the tests:

    make test

This will produce example output from several falsifiable properties, and
confirm that failures have been found.

To install libtheft and its headers:

    make install    # using sudo, if necessary

theft can also be vendored inside of projects -- in that case, just make
sure the headers in `${VENDOR}/theft/inc/` are added to the `-I` include
path, and `${VENDOR}/theft/build/libtheft.a` is linked.

Usage
-----

For usage documentation, see [doc/usage.md](doc/usage.md).

Properties
----------

For some examples of properties to test, see
[doc/properties.md](doc/properties.md).

Shrinking and Auto-shrinking
----------------------------

For more info about shrinking and auto-shrinking, see
[doc/shrinking.md](doc/shrinking.md).

Forking
-------

theft can fork before running properties, to shrink failures that make
the code under test crash or exceed an optional timeout. For more info,
see [doc/forking.md](doc/forking.md).

License
-------

Theft is made availible under the ISC license, however it contains
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
