// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef FUZZ_RANDOM_H
#define FUZZ_RANDOM_H

#include <inttypes.h>

struct fuzz;
struct autoshrink_bit_pool;

// Inject a bit pool for autoshrinking -- Get the random bit stream from
// it, rather than the PRNG, because we'll shrink by shrinking the bit
// pool itself.
void fuzz_random_inject_autoshrink_bit_pool(
		struct fuzz* t, struct autoshrink_bit_pool* bitpool);

// Stop using an autoshrink bit pool.
// (Re-seeding the PRNG will also do this.)
void fuzz_random_stop_using_bit_pool(struct fuzz* t);

// (Re-)initialize the random number generator with a specific seed.
// This stops using the current bit pool.
void fuzz_random_set_seed(struct fuzz* t, uint64_t seed);

#endif
