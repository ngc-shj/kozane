/*
 * Copyright (c) 2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DIGEST_H
#define DIGEST_H

#include <stddef.h>
#include <stdint.h>

#include "event_log.h"

/**
 * @brief Lookup algorithm metadata by numeric identifier.
 *
 * Translates a TPM/TCG-style algorithm ID into a description structure
 * containing name, digest length, and other properties.
 *
 * @param[in] algo_id  Numeric algorithm identifier (e.g. TPM2_ALG_SHA256).
 *
 * @return Pointer to a constant algorithm descriptor, or NULL if not found.
 */
const struct event_log_algorithm *
event_log_algorithm_lookup(uint16_t algorithm_id);

/**
 * @brief Append a C-string to a growing buffer with running position.
 *
 * Appends as many characters from @p s as fit, ensuring NUL-termination if any
 * bytes were copied. Advances @p *pos by the full length of @p s regardless of
 * truncation, enabling “would-have-written” accounting at the call site.
 *
 * @param[in,out] dst  Destination buffer.
 * @param[in]     cap  Total capacity of @p dst (bytes, incl. space for NUL).
 * @param[in,out] pos  In: current logical length; Out: increased by strlen(@p s).
 * @param[in]     s    NUL-terminated string to append.
 *
 * @return strlen(@p s).
 *
 * @note Intended usage pattern:
 * @code
 * size_t pos = 0; buf[0] = '\0';
 * append_str(buf, cap, &pos, "prefix: ");
 * append_str(buf, cap, &pos, value);
 * bool truncated = (pos >= cap);
 * @endcode
 */
size_t event_log_append_str(char *dst, size_t cap, size_t *pos, const char *s);

/**
 * @brief Convert bytes to lower-hex with spaces (e.g., "aa ff …").
 *
 * Writes at most @p dst_len bytes including the terminating NUL (if @p dst_len > 0).
 * Always returns the number of characters that would have been written
 * (excluding the NUL), so you can detect truncation by checking
 * `return_value >= dst_len`.
 *
 * @param[out] dst      Destination buffer for ASCII hex; may be NULL only if @p dst_len == 0.
 * @param[in]  dst_len  Capacity of @p dst in bytes (including room for NUL).
 * @param[in]  nbytes   Number of input bytes to render.
 * @param[in]  digest   Pointer to @p nbytes of data; not modified.
 *
 * @return Characters that would have been written (excluding the terminating NUL).
 *
 * Example:
 * @code
 * // For 3 bytes, required size is 3*3 - 1 + 1 (for NUL) = 9
 * char buf[9];
 * size_t need = write_hex_spaced(buf, sizeof buf, 3, in);
 * bool truncated = (need >= sizeof buf);
 * @endcode
 */
size_t event_log_write_hex_spaced(char *dst, size_t dst_len, size_t nbytes,
				  const uint8_t *digest);

#endif /* DIGEST_H */
