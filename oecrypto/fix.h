// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_FIX_H
#define _OE_FIX_H

#include <stdint.h>
#include <string.h>

// Defines so that oecrypto compiles properly
#define OE_EXTERNC_BEGIN
#define OE_EXTERNC_END
#define OE_INLINE static __inline
#define OE_ENUM_MAX 0xffffffff

typedef int oe_result_t;

static __inline int oe_constant_time_mem_equal(const void* a, const void* b, size_t s)
{
	return memcmp(a, b, s) == 0;
}

#endif