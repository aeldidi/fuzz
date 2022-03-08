// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef THEFT_TRIAL_H
#define THEFT_TRIAL_H

#include <stdbool.h>

#include "theft_trial_internal.h"

bool theft_trial_run(struct theft* t, enum theft_hook_trial_post_res* tpres);

void theft_trial_get_args(struct theft* t, void** args);

void theft_trial_free_args(struct theft* t);

#endif
