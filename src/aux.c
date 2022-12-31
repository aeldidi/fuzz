// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include <assert.h>
#include <stdlib.h>

#if !defined(_WIN32)
#include <sys/time.h>
#endif

#include "fuzz.h"
#include "polyfill.h"
#include "types_internal.h"

// Name used when no property name is set.
static const char def_prop_name[] = "(anonymous)";

uint64_t
fuzz_seed_of_time(void)
{
	struct timeval tv = {0, 0};
	if (-1 == gettimeofday(&tv, NULL)) {
		return 0;
	}

	return (uint64_t)fuzz_hash_onepass((const uint8_t*)&tv, sizeof(tv));
}

void
fuzz_generic_free_cb(void* instance, void* env)
{
	(void)env;
	free(instance);
}

// Print a tally marker for a trial result, but if there have been
// SCALE_FACTOR consecutive ones, increase the scale by an
// order of magnitude.
static size_t
autoscale_tally(char* buf, size_t buf_size, size_t scale_factor, char* name,
		size_t* cur_scale, char tally, size_t* count)
{
	const size_t scale  = *cur_scale == 0 ? 1 : *cur_scale;
	const size_t nscale = scale_factor * scale;
	size_t       used   = 0;
	if (scale > 1 || *count >= nscale) {
		if (*count == nscale) {
			used = snprintf(buf, buf_size, "(%s x %zd)%c", name,
					nscale, tally);
			*cur_scale = nscale;
		} else if ((*count % scale) == 0) {
			used = snprintf(buf, buf_size, "%c", tally);
		} else {
			buf[0] = '\0'; // truncate -- print nothing
		}
	} else {
		used = snprintf(buf, buf_size, "%c", tally);
	}
	(*count)++;
	return used;
}

void
fuzz_print_trial_result(struct fuzz_print_trial_result_env* env,
		const struct fuzz_post_trial_info*          info)
{
	assert(env);
	assert(info);

	struct fuzz* t = info->t;
	if (t->print_trial_result_env == env) {
		assert(t->print_trial_result_env->tag ==
				FUZZ_PRINT_TRIAL_RESULT_ENV_TAG);
	} else if ((t->hooks.trial_post !=
				   fuzz_hook_trial_post_print_result) &&
			env == t->hooks.env) {
		if (env != NULL &&
				env->tag != FUZZ_PRINT_TRIAL_RESULT_ENV_TAG) {
			fprintf(stderr, "\n"
					"WARNING: The *env passed to "
					"trial_print_trial_result is probably "
					"not\n"
					"a `fuzz_print_trial_result_env` "
					"struct -- to suppress this warning,\n"
					"set env->tag to "
					"FUZZ_PRINT_TRIAL_RESULT_ENV_TAG.\n");
		}
	}

	const uint8_t maxcol = (env->max_column == 0 ? FUZZ_DEF_MAX_COLUMNS
						     : env->max_column);

	size_t used = 0;
	char   buf[64];

	switch (info->result) {
	case FUZZ_RESULT_OK:
		used = autoscale_tally(buf, sizeof(buf), 100, "PASS",
				&env->scale_pass, '.', &env->consec_pass);
		break;
	case FUZZ_RESULT_FAIL:
		used             = snprintf(buf, sizeof(buf), "F");
		env->scale_pass  = 1;
		env->consec_pass = 0;
		env->column      = 0;
		break;
	case FUZZ_RESULT_SKIP:
		used = autoscale_tally(buf, sizeof(buf), 10, "SKIP",
				&env->scale_skip, 's', &env->consec_skip);
		break;
	case FUZZ_RESULT_DUPLICATE:
		used = autoscale_tally(buf, sizeof(buf), 10, "DUP",
				&env->scale_dup, 'd', &env->consec_dup);
		break;
	case FUZZ_RESULT_ERROR:
		used = snprintf(buf, sizeof(buf), "E");
		break;
	default:
		assert(false);
		return;
	}

	assert(info->t);
	FILE* f = (info->t->out == NULL ? stdout : info->t->out);

	if (env->column + used >= maxcol) {
		fprintf(f, "\n");
		env->column = 0;
	}

	fprintf(f, "%s", buf);
	fflush(f);
	assert(used <= UINT8_MAX);
	env->column += (uint8_t)used;
}

int
fuzz_hook_first_fail_halt(const struct fuzz_pre_trial_info* info, void* env)
{
	(void)env;
	return info->failures > 0 ? FUZZ_HOOK_RUN_HALT
				  : FUZZ_HOOK_RUN_CONTINUE;
}

int
fuzz_hook_trial_post_print_result(
		const struct fuzz_post_trial_info* info, void* env)
{
	fuzz_print_trial_result(
			(struct fuzz_print_trial_result_env*)env, info);
	return FUZZ_HOOK_RUN_CONTINUE;
}

int
fuzz_print_counterexample(
		const struct fuzz_counterexample_info* info, void* env)
{
	(void)env;
	struct fuzz* t     = info->t;
	int          arity = info->arity;
	fprintf(t->out, "\n\n -- Counter-Example: %s\n",
			info->prop_name ? info->prop_name : "");
	fprintf(t->out, "    Trial %zd, Seed 0x%016" PRIx64 "\n",
			info->trial_id, (uint64_t)info->trial_seed);
	for (int i = 0; i < arity; i++) {
		struct fuzz_type_info* ti = info->type_info[i];
		if (ti->print) {
			fprintf(t->out, "    Argument %d:\n", i);
			ti->print(t->out, info->args[i], ti->env);
			fprintf(t->out, "\n");
		}
	}
	return FUZZ_HOOK_RUN_CONTINUE;
}

void
fuzz_print_pre_run_info(FILE* f, const struct fuzz_pre_run_info* info)
{
	const char* prop_name =
			info->prop_name ? info->prop_name : def_prop_name;
	fprintf(f, "\n== PROP '%s': %zd trials, seed 0x%016" PRIx64 "\n",
			prop_name, info->total_trials, info->run_seed);
}

int
fuzz_pre_run_hook_print_info(const struct fuzz_pre_run_info* info, void* env)
{
	(void)env;
	fuzz_print_pre_run_info(stdout, info);
	return FUZZ_HOOK_RUN_CONTINUE;
}

void
fuzz_print_post_run_info(FILE* f, const struct fuzz_post_run_info* info)
{
	const struct fuzz_run_report* r = &info->report;
	const char*                   prop_name =
                        info->prop_name ? info->prop_name : def_prop_name;
	fprintf(f, "\n== %s '%s': pass %zd, fail %zd, skip %zd, dup %zd\n",
			r->fail > 0 ? "FAIL" : "PASS", prop_name, r->pass,
			r->fail, r->skip, r->dup);
}

int
fuzz_post_run_hook_print_info(const struct fuzz_post_run_info* info, void* env)
{
	(void)env;
	fuzz_print_post_run_info(stdout, info);
	return FUZZ_HOOK_RUN_CONTINUE;
}

void*
fuzz_hook_get_env(struct fuzz* t)
{
	return t->hooks.env;
}

struct fuzz_aux_print_trial_result_env {
	FILE*         f;          // 0 -> default of stdout
	const uint8_t max_column; // 0 -> default of DEF_MAX_COLUMNS

	uint8_t column;
	size_t  consec_pass;
	size_t  consec_fail;
};

const char*
fuzz_result_str(int res)
{
	switch (res) {
	case FUZZ_RESULT_OK:
		return "PASS";
	case FUZZ_RESULT_FAIL:
		return "FAIL";
	case FUZZ_RESULT_SKIP:
		return "SKIP";
	case FUZZ_RESULT_DUPLICATE:
		return "DUP";
	case FUZZ_RESULT_ERROR:
		return "ERROR";
	case FUZZ_RESULT_ERROR_MEMORY:
		return "ALLOCATION ERROR";
	default:
		return "(matchfail)";
	}
}
