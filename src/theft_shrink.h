// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef THEFT_SHRINK_H
#define THEFT_SHRINK_H

#include <stdbool.h>

#include "theft_shrink_internal.h"

/* Attempt to simplify all arguments, breadth first. Continue as long as
 * progress is made, i.e., until a local minimum is reached. */
bool theft_shrink(struct theft* t);

#endif
