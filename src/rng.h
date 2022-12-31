// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef FUZZ_RNG_H
#define FUZZ_RNG_H

#include <inttypes.h>

// Wrapper for Mersenne Twister.
// See copyright and license in fuzz_rng.c, more details at:
//     http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
//
// Local modifications are described in fuzz_mt.c.

// Opaque type for a Mersenne Twister PRNG.
struct fuzz_rng;

// Heap-allocate a mersenne twister struct.
struct fuzz_rng* fuzz_rng_init(uint64_t seed);

// Free a heap-allocated mersenne twister struct.
void fuzz_rng_free(struct fuzz_rng* mt);

// Reset a mersenne twister struct, possibly stack-allocated.
void fuzz_rng_reset(struct fuzz_rng* mt, uint64_t seed);

// Get a 64-bit random number.
uint64_t fuzz_rng_random(struct fuzz_rng* mt);

// Convert a uint64_t to a number on the [0,1]-real-interval.
double fuzz_rng_uint64_to_double(uint64_t x);

#endif
