// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include <assert.h>
#include <stdio.h>

#include "bloom.h"
#include "greatest.h"

TEST
all_marked_should_remain_marked(size_t limit)
{
	struct fuzz_bloom* b = fuzz_bloom_init(NULL);

	char buf[32];
	for (size_t i = 0; i < limit; i++) {
		size_t used = snprintf(buf, sizeof(buf), "key%zd\n", i);
		assert(used < sizeof(buf));
		ASSERTm("marking should not fail",
				fuzz_bloom_mark(b, (uint8_t*)buf, used));
	}

	for (size_t i = 0; i < limit; i++) {
		size_t used = snprintf(buf, sizeof(buf), "key%zd\n", i);
		assert(used < sizeof(buf));
		ASSERTm("marked became unmarked",
				fuzz_bloom_check(b, (uint8_t*)buf, used));
	}

	fuzz_bloom_free(b);
	PASS();
}

SUITE(bloom)
{
	RUN_TESTp(all_marked_should_remain_marked, 10);
	RUN_TESTp(all_marked_should_remain_marked, 1000);
	RUN_TESTp(all_marked_should_remain_marked, 100000);
}
