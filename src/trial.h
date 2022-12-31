// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef FUZZ_TRIAL_H
#define FUZZ_TRIAL_H

#include <stdbool.h>

struct fuzz;

bool fuzz_trial_run(struct fuzz* t, int* post_trial_res);

void fuzz_trial_get_args(struct fuzz* t, void** args);

void fuzz_trial_free_args(struct fuzz* t);

#endif
