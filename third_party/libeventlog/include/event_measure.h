/*
 * Copyright (c) 2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef EVENT_MEASURE_H
#define EVENT_MEASURE_H

#include "event_log.h"
#include "event_record.h"

typedef int (*evlog_hash_func_t)(uint32_t alg, void *data, unsigned int len,
				 uint8_t *digest);

#define EVLOG_INVALID_ID UINT32_MAX

/**
 * Initialize the Event Log and register supported hash functions.
 *
 * Initializes the Event Log subsystem using the provided memory region
 * and registers one or more cryptographic hash functions for use in
 * event measurements. This function must be called before any measurements
 * or event recording can take place.
 *
 * @param[in] start      Pointer to the beginning of the Event Log buffer.
 * @param[in] finish     Pointer to the end of the Event Log buffer.
 * @param[in] pos        Previous cursor position.
 * @param[in] hash_func  Pointer to a structure containing the hash function
 *                       pointer and associated algorithm identifiers.
 *
 * @return 0 on success, or a negative error code on failure.
 */
int event_log_init_and_reg(uint8_t *start, uint8_t *finish, size_t pos,
			   evlog_hash_func_t hash_func);

/**
 * @brief Measure a memory region and record a TCG event.
 *
 * Computes one or more cryptographic digests over the byte range
 * [data_base, data_base + data_size) using the library's currently
 * configured digest algorithm set, then appends an event to the
 * platform event log associated with PCR @p pcr. The event payload is
 * the caller-provided @p event_data buffer (copied as-is).
 *
 * @param[in] data_base        Pointer to the base of the data to be measured.
 * @param[in] data_size        Size of the data in bytes.
 * @param[in] data_id          Identifier used to match against metadata.
 * @param[in] event_data       Pointer to event data.
 * @param[in] event_data_size  Size of event data in bytes.
 *
 * @return 0 on success, or a negative error code on failure.
 */
int event_log_measure_and_record(uint32_t pcr, uintptr_t data_base,
				 uint32_t data_size, const void *event_data,
				 size_t event_data_size);

/**
 * @brief Compute a cryptographic hash of a memory region.
 *
 * Hashes the byte range [data_base, data_base + data_size) using the
 * configured digest algorithms using a user specified cryptographic backend,
 * and writes the resulting digest to @p hash_buf.
 *
 * @param[in]  data_base      Pointer to the base of the data to be measured.
 * @param[in]  data_size      Size of the data in bytes.
 * @param[out] hash_buf       Buffer to hold the resulting hash output
 * @param[in]  hash_buf_size  Size of the hash buffer in bytes.
 *
 * @return 0 on success, or an error code on failure.
 */
int event_log_measure(uintptr_t data_base, size_t data_size, uint8_t *hash_buf,
		      size_t hash_buf_size);

#endif /* EVENT_MEASURE_H */
