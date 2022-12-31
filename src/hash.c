// SPDX-License-Identifier: CC0-1.0
#include <assert.h>

#include "fuzz.h"

// Fowler/Noll/Vo hash, 64-bit FNV-1a.
// This hashing algorithm is in the public domain.
// For more details, see: http://www.isthe.com/chongo/tech/comp/fnv/.
static const uint64_t fnv64_prime        = 1099511628211L;
static const uint64_t fnv64_offset_basis = 14695981039346656037UL;

// Initialize a hasher for incremental hashing.
void
fuzz_hash_init(uint64_t* h)
{
	assert(h);
	*h = fnv64_offset_basis;
}

// Sink more data into an incremental hash.
void
fuzz_hash_sink(uint64_t* h, const uint8_t* data, size_t bytes)
{
	assert(h);
	assert(data);
	if (h == NULL || data == NULL) {
		return;
	}
	uint64_t a = *h;
	for (size_t i = 0; i < bytes; i++) {
		a = (a ^ data[i]) * fnv64_prime;
	}
	*h = a;
}

// Finish hashing and get the result.
uint64_t
fuzz_hash_finish(uint64_t* h)
{
	assert(h);
	uint64_t res = *h;
	fuzz_hash_init(h); // reset
	return res;
}

// Hash a buffer in one pass. (Wraps the above functions.)
uint64_t
fuzz_hash_onepass(const uint8_t* data, size_t bytes)
{
	assert(data);
	uint64_t h = 0;
	fuzz_hash_init(&h);
	fuzz_hash_sink(&h, data, bytes);
	return fuzz_hash_finish(&h);
}
