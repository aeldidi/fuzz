// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include <assert.h>
#include <inttypes.h>

#include "fuzz.h"
#include "greatest.h"
#include "types_internal.h"

enum behavior {
	BEH_NONE,
	BEH_SKIP_ALL,
	BEH_ERROR_ALL,
	BEH_SKIP_DURING_AUTOSHRINK,
	BEH_FAIL_DURING_AUTOSHRINK,
	BEH_SHRINK_ERROR,
};

struct err_env {
	uint8_t       tag;
	enum behavior b;
	bool          shrinking;
};

static int
prop_bits_gt_0(struct fuzz* t, void* arg1)
{
	uint8_t* x = (uint8_t*)arg1;
	(void)t;
	return (*x > 0 ? FUZZ_RESULT_OK : FUZZ_RESULT_FAIL);
}

static int
bits_alloc(struct fuzz* t, void* penv, void** output)
{
	assert(penv);
	struct err_env* env = (struct err_env*)penv;
	assert(env->tag == 'e');

	if (env->b == BEH_SKIP_ALL) {
		return FUZZ_RESULT_SKIP;
	} else if (env->b == BEH_ERROR_ALL) {
		return FUZZ_RESULT_ERROR;
	}

	if (env->shrinking) {
		env->shrinking = false;
		if (env->b == BEH_SKIP_DURING_AUTOSHRINK) {
			return FUZZ_RESULT_SKIP;
		} else if (env->b == BEH_FAIL_DURING_AUTOSHRINK) {
			return FUZZ_RESULT_ERROR;
		}
	}

	uint8_t* res = calloc(1, sizeof(*res));
	if (res == NULL) {
		return FUZZ_RESULT_ERROR;
	}
	*res    = fuzz_random_bits(t, 6);
	*output = res;
	return FUZZ_RESULT_OK;
}

TEST
alloc_returns_skip(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_SKIP_ALL,
	};

	static struct fuzz_type_info type_info = {
			.alloc = bits_alloc,
			.free  = fuzz_generic_free_cb,
			.autoshrink_config =
					{
							.enable = true,
					},
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop1     = prop_bits_gt_0,
			.type_info = {&type_info},
			.trials    = 10,
			.hooks =
					{
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);

	ASSERT_EQ_FMT(FUZZ_RESULT_SKIP, res, "%d");
	PASS();
}

static int
prop_should_never_run(struct fuzz* t, void* arg1, void* arg2)
{
	(void)t;
	(void)arg1;
	(void)arg2;
	return FUZZ_RESULT_ERROR;
}

// Check that arguments which have already been generated
// aren't double-freed.
TEST
second_alloc_returns_skip(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_SKIP_ALL,
	};

	static struct fuzz_type_info type_info = {
			.alloc = bits_alloc,
			.free  = fuzz_generic_free_cb,
			.autoshrink_config =
					{
							.enable = true,
					},
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop2     = prop_should_never_run,
			.type_info = {fuzz_get_builtin_type_info(
						      FUZZ_BUILTIN_uint16_t),
					&type_info},
			.trials    = 10,
			.hooks =
					{
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);

	ASSERT_EQ_FMT(FUZZ_RESULT_SKIP, res, "%d");
	PASS();
}

TEST
alloc_returns_error(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_ERROR_ALL,
	};

	static struct fuzz_type_info type_info = {
			.alloc = bits_alloc,
			.free  = fuzz_generic_free_cb,
			.autoshrink_config =
					{
							.enable = true,
					},
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop1     = prop_bits_gt_0,
			.type_info = {&type_info},
			.trials    = 10,
			.hooks =
					{
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);

	ASSERT_EQ_FMT(FUZZ_RESULT_ERROR, res, "%d");
	PASS();
}

TEST
second_alloc_returns_error(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_ERROR_ALL,
	};

	static struct fuzz_type_info type_info = {
			.alloc = bits_alloc,
			.free  = fuzz_generic_free_cb,
			.autoshrink_config =
					{
							.enable = true,
					},
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop2     = prop_should_never_run,
			.type_info = {fuzz_get_builtin_type_info(
						      FUZZ_BUILTIN_uint16_t),
					&type_info},
			.trials    = 10,
			.hooks =
					{
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);

	ASSERT_EQ_FMT(FUZZ_RESULT_ERROR, res, "%d");
	PASS();
}

static int
shrink_pre_set_shrinking(const struct fuzz_pre_shrink_info* info, void* penv)
{
	(void)info;
	struct err_env* env = (struct err_env*)penv;
	assert(env->tag == 'e');
	env->shrinking = true;
	return FUZZ_HOOK_RUN_CONTINUE;
}

TEST
alloc_returns_skip_during_autoshrink(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_SKIP_DURING_AUTOSHRINK,
	};

	static struct fuzz_type_info type_info = {
			.alloc = bits_alloc,
			.free  = fuzz_generic_free_cb,
			.autoshrink_config =
					{
							.enable = true,
					},
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop1     = prop_bits_gt_0,
			.type_info = {&type_info},
			.trials    = 1000,
			.hooks =
					{
							.pre_shrink = shrink_pre_set_shrinking,
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);

	ASSERT_EQ_FMT(FUZZ_RESULT_FAIL, res, "%d");
	PASS();
}

TEST
alloc_returns_error_during_autoshrink(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_FAIL_DURING_AUTOSHRINK,
	};

	static struct fuzz_type_info type_info = {
			.alloc = bits_alloc,
			.free  = fuzz_generic_free_cb,
			.autoshrink_config =
					{
							.enable = true,
					},
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop1     = prop_bits_gt_0,
			.type_info = {&type_info},
			.trials    = 1000,
			.hooks =
					{
							.pre_shrink = shrink_pre_set_shrinking,
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);

	ASSERT_EQ_FMT(FUZZ_RESULT_ERROR, res, "%d");
	PASS();
}

static int
bits_shrink(struct fuzz* t, const void* instance, uint32_t tactic, void* penv,
		void** output)
{
	(void)t;
	assert(penv);
	struct err_env* env = (struct err_env*)penv;
	if (env->b == BEH_SHRINK_ERROR) {
		return FUZZ_SHRINK_ERROR;
	}

	if (tactic == 2) {
		return FUZZ_SHRINK_NO_MORE_TACTICS;
	}

	const uint8_t* bits = (const uint8_t*)instance;
	uint8_t*       res  = calloc(1, sizeof(*res));
	if (res == NULL) {
		return FUZZ_SHRINK_ERROR;
	}
	*res    = (tactic == 0 ? (*bits / 2) : (*bits - 1));
	*output = res;
	return FUZZ_SHRINK_OK;
}

TEST
error_from_both_autoshrink_and_shrink_cb(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_NONE,
	};

	static struct fuzz_type_info type_info = {
			.alloc  = bits_alloc,
			.free   = fuzz_generic_free_cb,
			.shrink = bits_shrink,
			.autoshrink_config =
					{
							.enable = true,
					},
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop1     = prop_bits_gt_0,
			.type_info = {&type_info},
			.hooks =
					{
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);
	ASSERT_ENUM_EQm("defining shrink and autoshrink should error",
			FUZZ_RESULT_ERROR, res, fuzz_result_str);
	PASS();
}

TEST
shrinking_error(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_SHRINK_ERROR,
	};

	static struct fuzz_type_info type_info = {
			.alloc  = bits_alloc,
			.free   = fuzz_generic_free_cb,
			.shrink = bits_shrink,
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop1     = prop_bits_gt_0,
			.type_info = {&type_info},
			.trials    = 10000,
			.hooks =
					{
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);

	ASSERT_EQ_FMT(FUZZ_RESULT_ERROR, res, "%d");
	PASS();
}

static int
pre_run_hook_error(const struct fuzz_pre_run_info* info, void* penv)
{
	struct err_env* env = (struct err_env*)penv;
	assert(env->tag == 'e');
	(void)info;
	return FUZZ_HOOK_RUN_ERROR;
}

TEST
run_pre_hook_error(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_NONE,
	};

	static struct fuzz_type_info type_info = {
			.alloc = bits_alloc,
			.free  = fuzz_generic_free_cb,
			.autoshrink_config =
					{
							.enable = true,
					},
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop1     = prop_bits_gt_0,
			.type_info = {&type_info},
			.trials    = 10000,
			.hooks =
					{
							.pre_run = pre_run_hook_error,
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);
	ASSERT_EQ_FMT(FUZZ_RESULT_ERROR, res, "%d");
	PASS();
}

static int
post_run_hook_error(const struct fuzz_post_run_info* info, void* penv)
{
	struct err_env* env = (struct err_env*)penv;
	assert(env->tag == 'e');
	(void)info;
	return FUZZ_HOOK_RUN_ERROR;
}

TEST
run_post_hook_error(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_NONE,
	};

	static struct fuzz_type_info type_info = {
			.alloc = bits_alloc,
			.free  = fuzz_generic_free_cb,
			.autoshrink_config =
					{
							.enable = true,
					},
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop1     = prop_bits_gt_0,
			.type_info = {&type_info},
			.trials    = 10000,
			.hooks =
					{
							.post_run = post_run_hook_error,
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);
	ASSERT_EQ_FMT(FUZZ_RESULT_ERROR, res, "%d");
	PASS();
}

static int
hook_trial_pre_error(const struct fuzz_pre_trial_info* info, void* penv)
{
	struct err_env* env = (struct err_env*)penv;
	assert(env->tag == 'e');
	(void)info;
	return FUZZ_HOOK_RUN_ERROR;
}

TEST
trial_pre_hook_error(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_NONE,
	};

	static struct fuzz_type_info type_info = {
			.alloc = bits_alloc,
			.free  = fuzz_generic_free_cb,
			.autoshrink_config =
					{
							.enable = true,
					},
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop1     = prop_bits_gt_0,
			.type_info = {&type_info},
			.trials    = 10000,
			.hooks =
					{
							.pre_trial = hook_trial_pre_error,
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);
	ASSERT_EQ_FMT(FUZZ_RESULT_ERROR, res, "%d");
	PASS();
}

static int
hook_trial_post_error(const struct fuzz_post_trial_info* info, void* penv)
{
	struct err_env* env = (struct err_env*)penv;
	assert(env->tag == 'e');
	(void)info;
	return FUZZ_HOOK_RUN_ERROR;
}

TEST
trial_post_hook_error(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_NONE,
	};

	static struct fuzz_type_info type_info = {
			.alloc = bits_alloc,
			.free  = fuzz_generic_free_cb,
			.autoshrink_config =
					{
							.enable = true,
					},
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop1     = prop_bits_gt_0,
			.type_info = {&type_info},
			.trials    = 10000,
			.hooks =
					{
							.post_trial = hook_trial_post_error,
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);
	ASSERT_EQ_FMT(FUZZ_RESULT_ERROR, res, "%d");
	PASS();
}

static int
hook_shrink_pre_error(const struct fuzz_pre_shrink_info* info, void* penv)
{
	struct err_env* env = (struct err_env*)penv;
	assert(env->tag == 'e');
	(void)info;
	return FUZZ_HOOK_RUN_ERROR;
}

TEST
shrink_pre_hook_error(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_NONE,
	};

	static struct fuzz_type_info type_info = {
			.alloc = bits_alloc,
			.free  = fuzz_generic_free_cb,
			.autoshrink_config =
					{
							.enable = true,
					},
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop1     = prop_bits_gt_0,
			.type_info = {&type_info},
			.trials    = 10000,
			.hooks =
					{
							.pre_shrink = hook_shrink_pre_error,
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);
	ASSERT_EQ_FMT(FUZZ_RESULT_ERROR, res, "%d");
	PASS();
}

static int
hook_shrink_post_error(const struct fuzz_post_shrink_info* info, void* penv)
{
	struct err_env* env = (struct err_env*)penv;
	assert(env->tag == 'e');
	(void)info;
	return FUZZ_HOOK_RUN_ERROR;
}

TEST
shrink_post_hook_error(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_NONE,
	};

	static struct fuzz_type_info type_info = {
			.alloc = bits_alloc,
			.free  = fuzz_generic_free_cb,
			.autoshrink_config =
					{
							.enable = true,
					},
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop1     = prop_bits_gt_0,
			.type_info = {&type_info},
			.trials    = 10000,
			.hooks =
					{
							.post_shrink = hook_shrink_post_error,
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);
	ASSERT_EQ_FMT(FUZZ_RESULT_ERROR, res, "%d");
	PASS();
}

static int
hook_shrink_trial_post_error(
		const struct fuzz_post_shrink_trial_info* info, void* penv)
{
	struct err_env* env = (struct err_env*)penv;
	assert(env->tag == 'e');
	(void)info;
	return FUZZ_HOOK_RUN_ERROR;
}

TEST
shrink_trial_post_hook_error(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_NONE,
	};

	static struct fuzz_type_info type_info = {
			.alloc = bits_alloc,
			.free  = fuzz_generic_free_cb,
			.autoshrink_config =
					{
							.enable = true,
					},
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop1     = prop_bits_gt_0,
			.type_info = {&type_info},
			.trials    = 10000,
			.hooks =
					{
							.post_shrink_trial =
									hook_shrink_trial_post_error,
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);
	ASSERT_EQ_FMT(FUZZ_RESULT_ERROR, res, "%d");
	PASS();
}

static int
prop_always_skip(struct fuzz* t, void* arg1)
{
	uint8_t* x = (uint8_t*)arg1;
	(void)t;
	(void)x;
	return FUZZ_RESULT_SKIP;
}

TEST
trial_skip(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_NONE,
	};

	static struct fuzz_type_info type_info = {
			.alloc = bits_alloc,
			.free  = fuzz_generic_free_cb,
			.autoshrink_config =
					{
							.enable = true,
					},
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop1     = prop_always_skip,
			.type_info = {&type_info},
			.trials    = 10,
			.hooks =
					{
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);

	ASSERT_EQ_FMT(FUZZ_RESULT_SKIP, res, "%d");
	PASS();
}

static int
prop_always_error(struct fuzz* t, void* arg1)
{
	uint8_t* x = (uint8_t*)arg1;
	(void)t;
	(void)x;
	return FUZZ_RESULT_ERROR;
}

TEST
trial_error(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_NONE,
	};

	static struct fuzz_type_info type_info = {
			.alloc = bits_alloc,
			.free  = fuzz_generic_free_cb,
			.autoshrink_config =
					{
							.enable = true,
					},
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop1     = prop_always_error,
			.type_info = {&type_info},
			.trials    = 10,
			.hooks =
					{
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);

	ASSERT_EQ_FMT(FUZZ_RESULT_ERROR, res, "%d");
	PASS();
}

static bool trial_error_during_autoshrink_flag = false;

static int
prop_error_if_autoshrinking(struct fuzz* t, void* arg1)
{
	uint8_t* x = (uint8_t*)arg1;
	(void)t;
	if (trial_error_during_autoshrink_flag) {
		return FUZZ_RESULT_ERROR;
	}
	return prop_bits_gt_0(t, x);
}

static int
shrink_pre_set_shrinking_global_flag(
		const struct fuzz_pre_shrink_info* info, void* penv)
{
	struct err_env* env = (struct err_env*)penv;
	assert(env->tag == 'e');
	(void)info;
	trial_error_during_autoshrink_flag = true;
	return FUZZ_HOOK_RUN_CONTINUE;
}

TEST
trial_error_during_autoshrink(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_NONE,
	};

	static struct fuzz_type_info type_info = {
			.alloc = bits_alloc,
			.free  = fuzz_generic_free_cb,
			.autoshrink_config =
					{
							.enable = true,
					},
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop1     = prop_error_if_autoshrinking,
			.type_info = {&type_info},
			.trials    = 1000,
			.hooks =
					{
							.env = (void*)&env,
							.pre_shrink = shrink_pre_set_shrinking_global_flag,
					},
	};

	int res = fuzz_run(&cfg);

	ASSERT_EQ_FMT(FUZZ_RESULT_ERROR, res, "%d");
	PASS();
}

static int
hook_counterexample_error(
		const struct fuzz_counterexample_info* info, void* penv)
{
	struct err_env* env = (struct err_env*)penv;
	assert(env->tag == 'e');
	(void)info;
	return FUZZ_HOOK_RUN_ERROR;
}

TEST
counterexample_error(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_NONE,
	};

	static struct fuzz_type_info type_info = {
			.alloc = bits_alloc,
			.free  = fuzz_generic_free_cb,
			.autoshrink_config =
					{
							.enable = true,
					},
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop1     = prop_bits_gt_0,
			.type_info = {&type_info},
			.trials    = 10000,
			.hooks =
					{
							.counterexample =
									hook_counterexample_error,
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);
	ASSERT_EQ_FMT(FUZZ_RESULT_ERROR, res, "%d");
	PASS();
}

static int
prop_ignore_input_fail_then_pass(struct fuzz* t, void* arg1)
{
	uint8_t* x = (uint8_t*)arg1;
	(void)t;
	(void)x;
	static size_t runs = 0;
	runs++;
	return (runs == 1 ? FUZZ_RESULT_FAIL : FUZZ_RESULT_OK);
}

static int
trial_post_repeat_once(const struct fuzz_post_trial_info* info, void* penv)
{
	struct err_env* env = (struct err_env*)penv;
	assert(env->tag == 'e');
	(void)info;
	return FUZZ_HOOK_RUN_REPEAT_ONCE;
}

TEST
fail_but_pass_when_rerun(void)
{
	struct err_env env = {
			.tag = 'e',
			.b   = BEH_NONE,
	};

	static struct fuzz_type_info type_info = {
			.alloc  = bits_alloc,
			.free   = fuzz_generic_free_cb,
			.shrink = bits_shrink,
	};
	type_info.env = &env;

	struct fuzz_run_config cfg = {
			.prop1     = prop_ignore_input_fail_then_pass,
			.type_info = {&type_info},
			.trials    = 1,
			.hooks =
					{
							.post_trial = trial_post_repeat_once,
							.env = (void*)&env,
					},
	};

	int res = fuzz_run(&cfg);
	ASSERT_EQ_FMT(FUZZ_RESULT_ERROR, res, "%d");
	PASS();
}

// Various tests related to exercising error handling.
SUITE(error)
{
	RUN_TEST(alloc_returns_skip);
	RUN_TEST(alloc_returns_error);
	RUN_TEST(alloc_returns_skip_during_autoshrink);
	RUN_TEST(alloc_returns_error_during_autoshrink);
	RUN_TEST(second_alloc_returns_skip);
	RUN_TEST(second_alloc_returns_error);
	RUN_TEST(shrinking_error);
	RUN_TEST(error_from_both_autoshrink_and_shrink_cb);
	RUN_TEST(run_pre_hook_error);
	RUN_TEST(run_post_hook_error);
	RUN_TEST(trial_pre_hook_error);
	RUN_TEST(trial_post_hook_error);
	RUN_TEST(shrink_pre_hook_error);
	RUN_TEST(shrink_post_hook_error);
	RUN_TEST(shrink_trial_post_hook_error);
	RUN_TEST(trial_skip);
	RUN_TEST(trial_error);
	RUN_TEST(trial_error_during_autoshrink);
	RUN_TEST(counterexample_error);
	RUN_TEST(fail_but_pass_when_rerun);
}
