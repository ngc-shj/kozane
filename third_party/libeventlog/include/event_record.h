/*
 * Copyright (c) 2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef EVENT_RECORD_H
#define EVENT_RECORD_H

#include "event_log.h"

/* Functions' declarations */

/**
 * Initialize the Event Log buffer.
 *
 * Sets global pointers to manage the Event Log memory region,
 * allowing subsequent log operations to write into the buffer.
 *
 * @param[in] start  Pointer to the start of the Event Log buffer.
 * @param[in] finish Pointer to the end of the buffer
 *                             (i.e., one byte past the last valid address).
 *
 * @return 0 on success, or -EINVAL if the input range is invalid.
 */
int event_log_buf_init(uint8_t *start, uint8_t *finish);

/**
 * Initialize the Event Log library.
 *
 * @param[in] start  Pointer to the start of the Event Log buffer.
 * @param[in] finish Pointer to the end of the buffer
 *                             (i.e., one byte past the last valid address).
 *
 * @return 0 on success, or a negative error code on failure.
 */
int event_log_init(uint8_t *start, uint8_t *finish);

/**
 * Initialize the Event Log library from a previous offset.
 *
 * @param[in] start  Pointer to the start of the Event Log buffer.
 * @param[in] finish Pointer to the end of the buffer
 *                             (i.e., one byte past the last valid address).
 * @param[in] pos    Previous cursor position.
 *
 * @return 0 on success, or a negative error code on failure.
 */
int event_log_init_from_pos(uint8_t *start, uint8_t *finish, size_t pos);

/**
 * @brief Write a PCR event with multiple digests.
 *
 * @param[in] pcr_index        PCR index of the event.
 * @param[in] event_type       Type of the event.
 * @param[in] digests          Pointer to digest values.
 * @param[in] event_data       Pointer to event data.
 * @param[in] event_data_size  Size of event data in bytes.
 *
 * @return 0 on success, negative on error.
 *
  * @note In the PC Client spec for TPM 1.2, the event log used a fixed SHA-1 digest
 *       (20 bytes) for each event (SHA1 log format). With TPM 2.0, PCRs may use
 *       multiple hash algorithms, so each event must include all digests recorded
 *       (crypto-agile event log format).
 *
 */
int event_log_write_pcr_event2(uint32_t pcr_index, uint32_t event_type,
			       const tpml_digest_values *digests,
			       const uint8_t *event_data,
			       uint32_t event_data_size);

/**
 * @brief Write a PCR event with a single digest.
 *
 * @param[in] pcr_index        PCR index of the event.
 * @param[in] event_type       Type of the event.
 * @param[in] algorithm_id     Hash function ID.
 * @param[in] digest           Pointer to digest values.
 * @param[in] event_data       Pointer to event data.
 * @param[in] event_data_size  Size of event data in bytes.
 *
 * @return 0 on success, negative on error.
 *
 */
int event_log_write_pcr_event2_single(uint32_t pcr_index, uint32_t event_type,
				      uint32_t algorithm_id, uint8_t *digest,
				      const uint8_t *event_data,
				      uint32_t event_data_size);

/**
 * @brief Write a PCR event with a single digest.
 *
 * @param[in] pcr_index        PCR index of the event.
 * @param[in] event_type       Type of the event.
 * @param[in] digest           Pointer to event digest.
 * @param[in] event_data       Pointer to event data.
 * @param[in] event_data_size  Size of event data in bytes.
 *
 * @return 0 on success, negative on error.
 *
 * @note In TPM 1.2 platforms, the event log always uses SHA-1 digests
 *       (SHA1 log format). For TPM 2.0, see @ref event_log_write_pcr_event2
 *       for the crypto-agile event log format.
 */
int event_log_write_pcr_event(uint32_t pcr_index, uint32_t event_type,
			      const uint8_t *digest, const uint8_t *event_data,
			      uint32_t event_data_size);

/**
 * @brief Initialize the Event Log with mandatory header events.
 *
 * Writes the Specification ID (SpecID) and Startup Locality events
 * as required by the TCG PC Client Platform Firmware Profile.
 * These must be the first entries in the Event Log.
 *
 * @param[in] algorithms       Pointer to array of digest algorithm descriptors.
 * @param[in] algo_count       Number of elements in @p algorithms.
 * @param[in] locality         Startup locality value (0–4).
 * @param[in] vendor_info      Pointer to vendor-specific information.
 * @param[in] vendor_info_size Size of vendor-specific information in bytes.
 *
 * @return 0 on success, negative on error.
 *
 * @retval -EINVAL  If arguments are invalid (e.g., null pointer or size mismatch).
 * @retval -ENOMEM  If memory allocation fails while writing the header.
 *
 * @note This function must be called before any PCR events are written
 *       to the Event Log. The SpecID and Startup Locality events are
 *       always the first log entries.
 */
int event_log_write_header(const tpm_alg_id *algorithms, uint32_t algo_count,
			   uint8_t locality, const uint8_t *vendor_info,
			   uint8_t vendor_info_size);

/**
 * @brief Write the SpecID event to the Event Log.
 *
 * Records a @ref TCG_EfiSpecIDEventStruct that declares the event log
 * format and the hashing algorithms supported by the platform.
 *
 * @param[in] algorithms       Array of supported algorithm identifiers and digest sizes.
 * @param[in] algo_count       Number of entries in the @p algorithms array.
 * @param[in] vendor_info      Pointer to vendor-specific information.
 * @param[in] vendor_info_size Size of @p vendor_info in bytes.
 *
 * @return 0 on success, negative on error.
 *
 * @note The SpecID event is the first event in a crypto-agile event log
 *       (TPM 2.0). It describes the log format and must be recorded before
 *       any PCR events.
 */
int event_log_write_specid_event(const tpm_alg_id *algorithms,
				 uint32_t algo_count,
				 const uint8_t *vendor_info,
				 uint8_t vendor_info_size);

/**
 * Get the current size of the Event Log.
 *
 * Calculates how many bytes of the Event Log buffer have been used,
 * based on the current log pointer and the start of the buffer.
 *
 * @param[in] start Pointer to the start of the Event Log buffer.
 *
 * @return The number of bytes currently used in the Event Log.
 */
size_t event_log_get_cur_size(uint8_t *start);

#endif
