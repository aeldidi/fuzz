// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include <string.h>

#include "greatest.h"
#include "theft.h"

static int
prop_char_fails_cause_shrink(struct theft* t, void* arg1)
{
	(void)t;
	char* test_str = arg1;

	return strlen(test_str) ? THEFT_RESULT_FAIL : THEFT_RESULT_OK;
}

TEST
char_fail_shrinkage(void)
{
	theft_seed seed = theft_seed_of_time();

	struct theft_run_config cfg = {
			.name  = __func__,
			.prop1 = prop_char_fails_cause_shrink,
			.type_info =
					{
							theft_get_builtin_type_info(
									THEFT_BUILTIN_char_ARRAY),
					},
			.bloom_bits = 20,
			.seed       = seed,
			.trials     = 1,
	};

	ASSERT_EQm("should fail until full contraction", THEFT_RESULT_FAIL,
			theft_run(&cfg));
	PASS();
}

SUITE(char_array)
{
	RUN_TEST(char_fail_shrinkage);
}
