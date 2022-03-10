// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2022 Ayman El Didi
#include "test_theft.h"
#include "theft_types.h"

static enum theft_trial_res
prop_always_fail(struct theft* t, void* arg1)
{
	(void)t;
	(void)arg1;
	return THEFT_TRIAL_FAIL;
}

TEST
skip_forking_tests(void)
{
	theft_seed seed = theft_seed_of_time();

	struct theft_run_config cfg = {
			.name       = __func__,
			.prop1      = prop_always_fail,
			.type_info  = {theft_get_builtin_type_info(
                                        THEFT_BUILTIN_int)},
			.bloom_bits = 20,
			.seed       = seed,
			.trials     = 1,
			.fork       = {.enable = true, .timeout = 10},
	};

	printf("res: %d\n", theft_run(&cfg));
	// ASSERT_EQm("forking test should've been skipped", THEFT_RUN_SKIP,
	// 		theft_run(&cfg));
	PASS();
}

SUITE(no_fork)
{
	RUN_TEST(skip_forking_tests);
}
