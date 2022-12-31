// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef FUZZ_BLOOM_H
#define FUZZ_BLOOM_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

// Opaque type for bloom filter.
struct fuzz_bloom;

struct fuzz_bloom_config {
	uint8_t top_block_bits;
	uint8_t min_filter_bits;
};

// Initialize a bloom filter.
struct fuzz_bloom* fuzz_bloom_init(const struct fuzz_bloom_config* config);

// Hash data and mark it in the bloom filter.
bool fuzz_bloom_mark(struct fuzz_bloom* b, uint8_t* data, size_t data_size);

// Check whether the data's hash is in the bloom filter.
bool fuzz_bloom_check(struct fuzz_bloom* b, uint8_t* data, size_t data_size);

// Free the bloom filter.
void fuzz_bloom_free(struct fuzz_bloom* b);

#endif
