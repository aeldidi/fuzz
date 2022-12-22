// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef THEFT_RUN_H
#define THEFT_RUN_H

struct theft;
struct theft_run_config;

enum theft_run_init_res {
	THEFT_RUN_INIT_OK,
	THEFT_RUN_INIT_ERROR_MEMORY   = -1,
	THEFT_RUN_INIT_ERROR_BAD_ARGS = -2,
};
enum theft_run_init_res theft_run_init(
		const struct theft_run_config* cfg, struct theft** output);

/* Actually run the trials, with all arguments made explicit. */
int theft_run_trials(struct theft* t);

void theft_run_free(struct theft* t);

#endif
