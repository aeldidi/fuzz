// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef TEST_THEFT_AUTOSHRINK_LL_H
#define TEST_THEFT_AUTOSHRINK_LL_H

#include <inttypes.h>

struct ll {
	char       tag;
	uint8_t    value;
	struct ll* next;
};

extern struct theft_type_info ll_info;

#endif
