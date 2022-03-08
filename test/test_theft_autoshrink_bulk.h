// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef TEST_THEFT_AUTOSHRINK_BULK_H
#define TEST_THEFT_AUTOSHRINK_BULK_H

#include <stddef.h>
#include <stdint.h>

struct bulk_buffer {
	size_t    size;
	uint64_t* buf;
};

extern struct theft_type_info bb_info;

#endif
