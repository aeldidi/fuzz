// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include <assert.h>
#include <string.h>

#include "polyfill.h"
#include "theft.h"
#include "theft_run.h"
#include "theft_types.h"
#include "theft_types_internal.h"

#if (-1 != ~0)
#error "theft requires 2s complement representation for integers"
#endif

static int should_not_run(struct theft* t, void* arg1);

/* Change T's output stream handle to OUT. (Default: stdout.) */
void
theft_set_output_stream(struct theft* t, FILE* out)
{
	t->out = out;
}

/* Run a series of randomized trials of a property function.
 *
 * Configuration is specified in CFG; many fields are optional.
 * See the type definition in `theft_types.h`. */
int
theft_run(const struct theft_run_config* cfg)
{
	if (cfg == NULL) {
		return THEFT_RESULT_ERROR;
	}

	if (cfg->fork.enable && !THEFT_POLYFILL_HAVE_FORK) {
		return THEFT_RESULT_SKIP;
	}

	struct theft* t = NULL;

	enum theft_run_init_res init_res = theft_run_init(cfg, &t);
	switch (init_res) {
	case THEFT_RUN_INIT_ERROR_MEMORY:
		return THEFT_RESULT_ERROR_MEMORY;
	default:
		assert(false);
	case THEFT_RUN_INIT_ERROR_BAD_ARGS:
		return THEFT_RESULT_ERROR;
	case THEFT_RUN_INIT_OK:
		break; /* continue below */
	}

	int res = theft_run_trials(t);
	theft_run_free(t);
	return res;
}

int
theft_generate(FILE* f, theft_seed seed, const struct theft_type_info* info,
		void* hook_env)
{
	int           res = THEFT_RESULT_OK;
	struct theft* t   = NULL;

	struct theft_run_config cfg = {
			.name      = "generate",
			.prop1     = should_not_run,
			.type_info = {info},
			.seed      = seed,
			.hooks =
					{
							.env = hook_env,
					},
	};

	enum theft_run_init_res init_res = theft_run_init(&cfg, &t);
	switch (init_res) {
	case THEFT_RUN_INIT_ERROR_MEMORY:
		return THEFT_RESULT_ERROR_MEMORY;
	default:
		assert(false);
	case THEFT_RUN_INIT_ERROR_BAD_ARGS:
		return THEFT_RESULT_ERROR;
	case THEFT_RUN_INIT_OK:
		break; /* continue below */
	}

	void* instance = NULL;
	int   ares     = info->alloc(t, info->env, &instance);
	switch (ares) {
	case THEFT_RESULT_OK:
		break; /* continue below */
	case THEFT_RESULT_SKIP:
		res = THEFT_RESULT_SKIP;
		goto cleanup;
	case THEFT_RESULT_ERROR:
		res = THEFT_RESULT_ERROR_MEMORY;
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
	theft_run_free(t);
	return res;
}

static int
should_not_run(struct theft* t, void* arg1)
{
	(void)t;
	(void)arg1;
	return THEFT_RESULT_ERROR; /* should never be run */
}
