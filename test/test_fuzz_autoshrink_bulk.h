// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef TEST_FUZZ_AUTOSHRINK_BULK_H
#define TEST_FUZZ_AUTOSHRINK_BULK_H

#include <inttypes.h>
#include <stddef.h>

struct bulk_buffer {
	size_t    size;
	uint64_t* buf;
};

extern struct fuzz_type_info bb_info;

#endif
