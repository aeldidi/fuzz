// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef FUZZ_RUN_H
#define FUZZ_RUN_H

struct fuzz;
struct fuzz_run_config;

enum fuzz_run_init_res {
	FUZZ_RUN_INIT_OK,
	FUZZ_RUN_INIT_ERROR_MEMORY   = -1,
	FUZZ_RUN_INIT_ERROR_BAD_ARGS = -2,
};
enum fuzz_run_init_res fuzz_run_init(
		const struct fuzz_run_config* cfg, struct fuzz** output);

// Actually run the trials, with all arguments made explicit.
int fuzz_run_trials(struct fuzz* t);

void fuzz_run_free(struct fuzz* t);

#endif
