/*
 * Copyright (c) 2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifdef __GNUC__
#define	__bswap16(_x)	__builtin_bswap16(_x)
#define	__bswap32(_x)	__builtin_bswap32(_x)
#define	__bswap64(_x)	__builtin_bswap64(_x)
#else /* __GNUC__ */
static __inline __uint16_t
__bswap16(__uint16_t _x)
{

	return ((__uint16_t)((_x >> 8) | ((_x << 8) & 0xff00)));
}

static __inline __uint32_t
__bswap32(__uint32_t _x)
{

	return ((__uint32_t)((_x >> 24) | ((_x >> 8) & 0xff00) |
	    ((_x << 8) & 0xff0000) | ((_x << 24) & 0xff000000)));
}
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define	htobe32(_x)	__bswap32(_x)
#define	be32toh(_x)	__bswap32(_x)
#define	htobe16(_x)	__bswap16(_x)
#define	be16toh(_x)	__bswap16(_x)
#else
#define	htobe32(_x)	((__uint32_t)(_x))
#define	be32toh(_x)	((__uint32_t)(_x))
#define	htobe16(_x)	((__uint16_t)(_x))
#define	be16toh(_x)	((__uint16_t)(_x))
#endif
