// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef FUZZ_SHRINK_H
#define FUZZ_SHRINK_H

#include <stdbool.h>

struct fuzz;

// Attempt to simplify all arguments, breadth first. Continue as long as
// progress is made, i.e., until a local minimum is reached.
bool fuzz_shrink(struct fuzz* t);

#endif
