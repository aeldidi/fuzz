// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef FUZZ_CALL_H
#define FUZZ_CALL_H

#include <stdbool.h>

struct fuzz;

// Actually call the property function referenced in INFO, with the arguments
// in ARGS.
int fuzz_call(struct fuzz* t, void** args);

// Check if this combination of argument instances has been called.
bool fuzz_call_check_called(struct fuzz* t);

// Mark the tuple of argument instances as called in the bloom filter.
void fuzz_call_mark_called(struct fuzz* t);

#endif
