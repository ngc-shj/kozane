/*
 * Copyright (c) 2020-2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "event_log.h"

const struct event_log_algorithm algorithms[] = {
	{ EVLOG_TPM_ALG_SHA256, "SHA256", SHA256_DIGEST_SIZE },
	{ EVLOG_TPM_ALG_SHA384, "SHA384", SHA384_DIGEST_SIZE },
	{ EVLOG_TPM_ALG_SHA512, "SHA512", SHA512_DIGEST_SIZE },
};

const struct event_log_algorithm *
event_log_algorithm_lookup(uint16_t algorithm_id)
{
	for (size_t i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]);
	     i++) {
		if (algorithms[i].id == algorithm_id) {
			return &algorithms[i];
		}
	}

	return NULL;
}

size_t event_log_append_str(char *dst, size_t cap, size_t *pos, const char *s)
{
	size_t n = strlen(s);
	size_t room = (*pos < cap) ? (cap - *pos) : 0;

	if (room) {
		/* copy as much as fits, leave NUL handled by caller if needed */
		size_t to_copy = (n < room) ? n : (room - 1);
		memcpy(dst + *pos, s, to_copy);
		dst[*pos + to_copy] = '\0';
	}
	*pos += n;
	return n;
}

size_t event_log_write_hex_spaced(char *dst, size_t dst_len, size_t nbytes,
				  const uint8_t *digest)
{
	static const char HEX[] = "0123456789abcdef";
	size_t pos = 0;

	if (nbytes > dst_len / 3) {
		nbytes = dst_len / 3;
	}

	for (size_t i = 0; i < nbytes; i++) {
		dst[pos++] = HEX[digest[i] >> 4];
		dst[pos++] = HEX[digest[i] & 0x0F];
		dst[pos++] = ' ';
	}

	if (dst_len > 0) {
		if (pos >= dst_len) {
			dst[dst_len - 1] = '\0';
		} else {
			dst[pos] = '\0';
		}
	}

	return pos; /* count that WOULD have been written */
}
