// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include <assert.h>
#include <string.h>

#include "fuzz.h"
#include "polyfill.h"
#include "run.h"
#include "types_internal.h"

#if (-1 & 3) != 3
#error "fuzz requires 2s complement representation for integers"
#endif

static int should_not_run(struct fuzz* t, void* arg1);

// Change T's output stream handle to OUT. (Default: stdout.)
void
fuzz_set_output_stream(struct fuzz* t, FILE* out)
{
	t->out = out;
}

// Run a series of randomized trials of a property function.
//
// Configuration is specified in CFG; many fields are optional.
int
fuzz_run(const struct fuzz_run_config* cfg)
{
	if (cfg == NULL) {
		return FUZZ_RESULT_ERROR;
	}

	if (cfg->fork.enable && !FUZZ_POLYFILL_HAVE_FORK) {
		return FUZZ_RESULT_SKIP;
	}

	struct fuzz* t = NULL;

	enum fuzz_run_init_res init_res = fuzz_run_init(cfg, &t);
	switch (init_res) {
	case FUZZ_RUN_INIT_ERROR_MEMORY:
		return FUZZ_RESULT_ERROR_MEMORY;
	default:
		assert(false);
	case FUZZ_RUN_INIT_ERROR_BAD_ARGS:
		return FUZZ_RESULT_ERROR;
	case FUZZ_RUN_INIT_OK:
		break; // continue below
	}

	int res = fuzz_run_trials(t);
	fuzz_run_free(t);
	return res;
}

int
fuzz_generate(FILE* f, uint64_t seed, const struct fuzz_type_info* info,
		void* hook_env)
{
	int          res = FUZZ_RESULT_OK;
	struct fuzz* t   = NULL;

	struct fuzz_run_config cfg = {
			.name      = "generate",
			.prop1     = should_not_run,
			.type_info = {info},
			.seed      = seed,
			.hooks =
					{
							.env = hook_env,
					},
	};

	enum fuzz_run_init_res init_res = fuzz_run_init(&cfg, &t);
	switch (init_res) {
	case FUZZ_RUN_INIT_ERROR_MEMORY:
		return FUZZ_RESULT_ERROR_MEMORY;
	default:
		assert(false);
	case FUZZ_RUN_INIT_ERROR_BAD_ARGS:
		return FUZZ_RESULT_ERROR;
	case FUZZ_RUN_INIT_OK:
		break; // continue below
	}

	void* instance = NULL;
	int   ares     = info->alloc(t, info->env, &instance);
	switch (ares) {
	case FUZZ_RESULT_OK:
		break; // continue below
	case FUZZ_RESULT_SKIP:
		res = FUZZ_RESULT_SKIP;
		goto cleanup;
	case FUZZ_RESULT_ERROR:
		res = FUZZ_RESULT_ERROR_MEMORY;
		goto cleanup;
	}

	if (info->print) {
		fprintf(f, "-- Seed 0x%016" PRIx64 "\n", seed);
		info->print(f, instance, info->env);
		fprintf(f, "\n");
	}
	if (info->free) {
		info->free(instance, info->env);
	}

cleanup:
	fuzz_run_free(t);
	return res;
}

static int
should_not_run(struct fuzz* t, void* arg1)
{
	(void)t;
	(void)arg1;
	return FUZZ_RESULT_ERROR; // should never be run
}
