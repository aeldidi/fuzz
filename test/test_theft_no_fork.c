// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2022 Ayman El Didi
#include "greatest.h"
#include "theft.h"

static int
prop_always_fail(struct theft* t, void* arg1)
{
	(void)t;
	(void)arg1;
	return THEFT_RESULT_FAIL;
}

TEST
skip_forking_tests_when_fork_is_not_supported(void)
{
#if !defined(_WIN32)
	(void)prop_always_fail;
	SKIP();
#else
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
	int ret = theft_run(&cfg);

	ASSERT_EQm("forking test should've been skipped", THEFT_RESULT_SKIP,
			ret);
	PASS();
#endif
}

SUITE(no_fork)
{
	RUN_TEST(skip_forking_tests_when_fork_is_not_supported);
}
