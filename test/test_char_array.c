// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include <string.h>

#include "fuzz.h"
#include "greatest.h"

static int
prop_char_fails_cause_shrink(struct fuzz* t, void* arg1)
{
	(void)t;
	char* test_str = arg1;

	return strlen(test_str) ? FUZZ_RESULT_FAIL : FUZZ_RESULT_OK;
}

TEST
char_fail_shrinkage(void)
{
	uint64_t seed = fuzz_seed_of_time();

	struct fuzz_run_config cfg = {
			.name  = __func__,
			.prop1 = prop_char_fails_cause_shrink,
			.type_info =
					{
							fuzz_get_builtin_type_info(
									FUZZ_BUILTIN_char_ARRAY),
					},
			.bloom_bits = 20,
			.seed       = seed,
			.trials     = 1,
	};

	ASSERT_EQm("should fail until full contraction", FUZZ_RESULT_FAIL,
			fuzz_run(&cfg));
	PASS();
}

SUITE(char_array)
{
	RUN_TEST(char_fail_shrinkage);
}
