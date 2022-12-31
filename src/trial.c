// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include <assert.h>
#include <inttypes.h>

#include "autoshrink.h"
#include "call.h"
#include "fuzz.h"
#include "shrink.h"
#include "trial.h"
#include "types_internal.h"

static int report_on_failure(struct fuzz*    t,
		struct fuzz_post_trial_info* hook_info,
		fuzz_hook_trial_post_cb* trial_post, void* trial_post_env);

fuzz_hook_trial_post_cb def_trial_post_cb;

// Now that arguments have been generated, run the trial and update
// counters, call cb with results, etc.
bool
fuzz_trial_run(struct fuzz* t, int* tpres)
{
	assert(t->prop.arity > 0);

	if (t->bloom) {
		fuzz_call_mark_called(t);
	}

	void* args[FUZZ_MAX_ARITY];
	fuzz_trial_get_args(t, args);

	bool                     repeated   = false;
	int                      tres       = fuzz_call(t, args);
	fuzz_hook_trial_post_cb* trial_post = t->hooks.trial_post;
	void* trial_post_env = (trial_post == fuzz_hook_trial_post_print_result
						? t->print_trial_result_env
						: t->hooks.env);

	struct fuzz_post_trial_info hook_info = {
			.t            = t,
			.prop_name    = t->prop.name,
			.total_trials = t->prop.trial_count,
			.run_seed     = t->seeds.run_seed,
			.trial_id     = t->trial.trial,
			.trial_seed   = t->trial.seed,
			.arity        = t->prop.arity,
			.args         = args,
			.result       = tres,
	};

	switch (tres) {
	case FUZZ_RESULT_OK:
		if (!repeated) {
			t->counters.pass++;
		}
		*tpres = trial_post(&hook_info, trial_post_env);
		break;
	case FUZZ_RESULT_FAIL:
		if (!fuzz_shrink(t)) {
			hook_info.result = FUZZ_RESULT_ERROR;
			// We may not have a valid reference to the arguments
			// anymore, so remove the stale pointers.
			for (size_t i = 0; i < t->prop.arity; i++) {
				hook_info.args[i] = NULL;
			}
			*tpres = trial_post(&hook_info, trial_post_env);
			return false;
		}

		if (!repeated) {
			t->counters.fail++;
		}

		fuzz_trial_get_args(t, hook_info.args);
		*tpres = report_on_failure(
				t, &hook_info, trial_post, trial_post_env);
		break;
	case FUZZ_RESULT_SKIP:
		if (!repeated) {
			t->counters.skip++;
		}
		*tpres = trial_post(&hook_info, trial_post_env);
		break;
	case FUZZ_RESULT_DUPLICATE:
		// user callback should not return this; fall through
	case FUZZ_RESULT_ERROR:
		*tpres = trial_post(&hook_info, trial_post_env);
		return false;
	}

	if (*tpres == FUZZ_HOOK_RUN_ERROR) {
		return false;
	}

	return true;
}

void
fuzz_trial_free_args(struct fuzz* t)
{
	for (size_t i = 0; i < t->prop.arity; i++) {
		struct fuzz_type_info* ti = t->prop.type_info[i];

		struct arg_info* ai = &t->trial.args[i];
		if (ai->type == ARG_AUTOSHRINK) {
			fuzz_autoshrink_free_env(t, ai->u.as.env);
		}
		if (ai->instance != NULL && ti->free != NULL) {
			ti->free(t->trial.args[i].instance, ti->env);
		}
	}
}

void
fuzz_trial_get_args(struct fuzz* t, void** args)
{
	for (size_t i = 0; i < t->prop.arity; i++) {
		args[i] = t->trial.args[i].instance;
	}
}

// Print info about a failure.
static int
report_on_failure(struct fuzz* t, struct fuzz_post_trial_info* hook_info,
		fuzz_hook_trial_post_cb* trial_post, void* trial_post_env)
{
	fuzz_hook_counterexample_cb* counterexample = t->hooks.counterexample;
	if (counterexample != NULL) {
		struct fuzz_counterexample_info counterexample_hook_info = {
				.t            = t,
				.prop_name    = t->prop.name,
				.total_trials = t->prop.trial_count,
				.trial_id     = t->trial.trial,
				.trial_seed   = t->trial.seed,
				.arity        = t->prop.arity,
				.type_info    = t->prop.type_info,
				.args         = hook_info->args,
		};

		if (counterexample(&counterexample_hook_info, t->hooks.env) !=
				FUZZ_HOOK_RUN_CONTINUE) {
			return FUZZ_HOOK_RUN_ERROR;
		}
	}

	int res;
	res = trial_post(hook_info, trial_post_env);

	while (res == FUZZ_HOOK_RUN_REPEAT ||
			res == FUZZ_HOOK_RUN_REPEAT_ONCE) {
		hook_info->repeat = true;

		int tres = fuzz_call(t, hook_info->args);
		if (tres == FUZZ_RESULT_FAIL) {
			res = trial_post(hook_info, t->hooks.env);
			if (res == FUZZ_HOOK_RUN_REPEAT_ONCE) {
				break;
			}
		} else if (tres == FUZZ_RESULT_OK) {
			fprintf(t->out, "Warning: Failed property passed when "
					"re-run.\n");
			res = FUZZ_HOOK_RUN_ERROR;
		} else if (tres == FUZZ_RESULT_ERROR) {
			return FUZZ_HOOK_RUN_ERROR;
		} else {
			return FUZZ_HOOK_RUN_CONTINUE;
		}
	}
	return res;
}
