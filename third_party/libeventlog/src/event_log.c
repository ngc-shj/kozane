/*
 * Copyright (c) 2020-2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "debug.h"
#include "digest.h"
#include "event_log.h"
#include "event_measure.h"
#include "event_record.h"
#include "tcg.h"

/* Running Event Log Pointer */
static uint8_t *log_ptr;

/* Pointer to the first byte of the Event Log buffer */
static uint8_t *log_start;

/* Pointer to the first byte past end of the Event Log buffer */
static uintptr_t log_end;

/* Hash function for event log operations set by user. */
static evlog_hash_func_t event_log_hash_func;

static const tcg_efi_spec_id_event_t *spec_id_header;

/* size lookup from your spec_id_header table */
static inline uint16_t digest_size_for_alg(uint16_t alg)
{
	assert(spec_id_header != NULL);

	for (size_t k = 0U; k < spec_id_header->number_of_algorithms; k++) {
		if (spec_id_header->digest_size[k].algorithm_id == alg) {
			return spec_id_header->digest_size[k].digest_size;
		}
	}

	return 0;
}

static inline bool exceeds_bounds(uintptr_t ptr, size_t min_size)
{
	return min_size > log_end - ptr;
}

int event_log_write_pcr_event2_single(uint32_t pcr_index, uint32_t event_type,
				      uint32_t algorithm_id, uint8_t *digest,
				      const uint8_t *event_data,
				      uint32_t event_data_size)
{
	uint8_t *dst_p;
	event2_header_t *pcr_event = (event2_header_t *)log_ptr;
	uint16_t digest_size;

	if (log_ptr == NULL || spec_id_header == NULL) {
		ERROR("Cannot call library function, initialization not completed.\n");
		return -EFAULT;
	}

	if (event_type != EV_NO_ACTION && digest == NULL) {
		return -EINVAL;
	}

	if (event_data_size > 0U && event_data == NULL) {
		return -EINVAL;
	}

	/* Minimum space: header without digests/data */
	if (exceeds_bounds((uintptr_t)pcr_event, sizeof(event2_header_t))) {
		return -ENOMEM;
	}

	pcr_event->pcr_index = pcr_index;
	pcr_event->event_type = event_type;

	/* TCG_PCR_EVENT2.Digests.Count */
	if (spec_id_header->number_of_algorithms != 1U ||
	    algorithm_id != spec_id_header->digest_size[0].algorithm_id) {
		/*
		 * Only write single digests when only one algorithm is registered, each
		 * entry should have as many digests as are registered in the SpecID
		 * event.
		 */
		return -EINVAL;
	}

	pcr_event->digests.count = spec_id_header->number_of_algorithms;

	/* TCG_PCR_EVENT2.Digests.Digests[] */
	pcr_event->digests.digests->algorithm_id = algorithm_id;
	digest_size = digest_size_for_alg(algorithm_id);
	if (digest_size == 0U) {
		return -EINVAL;
	}

	(void)memcpy(pcr_event->digests.digests[0].digest, digest, digest_size);

	dst_p = pcr_event->digests.digests[0].digest + digest_size;

	if (exceeds_bounds((uintptr_t)dst_p,
			   sizeof(event_data) + event_data_size)) {
		return -ENOMEM;
	}

	((event2_data_t *)dst_p)->event_size = event_data_size;
	dst_p += offsetof(event2_data_t, event);

	if (event_data_size > 0U) {
		(void)memcpy(dst_p, event_data, event_data_size);
		dst_p += event_data_size;
	}

	log_ptr = dst_p;

	return 0;
}

int event_log_write_pcr_event2(uint32_t pcr_index, uint32_t event_type,
			       const tpml_digest_values *digests,
			       const uint8_t *event_data,
			       uint32_t event_data_size)
{
	size_t tpmt_ha_digest_sz;
	uint8_t *dst_p;
	tpmt_ha *curr = NULL;
	event2_header_t *pcr_event = (event2_header_t *)log_ptr;
	uint16_t digest_size;

	if (log_ptr == NULL || spec_id_header == NULL) {
		ERROR("Cannot call library function, initialization not completed.\n");
		return -EFAULT;
	}

	if (event_type != EV_NO_ACTION) {
		if (digests == NULL || digests->count == 0 ||
		    digests->count != spec_id_header->number_of_algorithms) {
			ERROR("Invalid digests, none passed or mismatch with SpecID Header.\n");
			return -EINVAL;
		}

		curr = (tpmt_ha *)&digests->digests;
	}

	if (event_data_size > 0U && event_data == NULL) {
		return -EINVAL;
	}

	/* Minimum space: header without digests/data */
	if (exceeds_bounds((uintptr_t)pcr_event, sizeof(event2_header_t))) {
		return -ENOMEM;
	}

	pcr_event->pcr_index = pcr_index;
	pcr_event->event_type = event_type;

	/* TCG_PCR_EVENT2.Digests.Count */
	pcr_event->digests.count = spec_id_header->number_of_algorithms;

	/* TCG_PCR_EVENT2.Digests.Digests[] */
	dst_p = (uint8_t *)&pcr_event->digests.digests;

	for (size_t i = 0; i < spec_id_header->number_of_algorithms; i++) {
		if (pcr_event->event_type == EV_NO_ACTION) {
			((tpmt_ha *)dst_p)->algorithm_id =
				spec_id_header->digest_size[i].algorithm_id;

			(void)memset(
				((tpmt_ha *)dst_p)->digest, 0,
				spec_id_header->digest_size[i].digest_size);

			dst_p += sizeof(tpmt_ha) +
				 spec_id_header->digest_size[i].digest_size;
		} else {
			digest_size = digest_size_for_alg(curr->algorithm_id);

			tpmt_ha_digest_sz = sizeof(tpmt_ha) + digest_size;

			if (exceeds_bounds((uintptr_t)dst_p,
					   tpmt_ha_digest_sz)) {
				return -ENOMEM;
			}

			/* TCG_PCR_EVENT2.Digests.Digests[i] */
			(void)memcpy(dst_p, curr, tpmt_ha_digest_sz);

			/* Increment to next digest location accounting for variable length digests. */
			curr = (tpmt_ha *)((uint8_t *)curr + tpmt_ha_digest_sz);
			dst_p += tpmt_ha_digest_sz;
		}
	}

	if (exceeds_bounds((uintptr_t)dst_p,
			   sizeof(event_data) + event_data_size)) {
		return -ENOMEM;
	}

	((event2_data_t *)dst_p)->event_size = event_data_size;
	dst_p += offsetof(event2_data_t, event);

	if (event_data_size > 0U) {
		(void)memcpy(dst_p, event_data, event_data_size);
		dst_p += event_data_size;
	}

	log_ptr = dst_p;

	return 0;
}

int event_log_write_pcr_event(uint32_t pcr_index, uint32_t event_type,
			      const uint8_t *digest, const uint8_t *event_data,
			      uint32_t event_data_size)
{
	tcg_pcr_event_t *pcr_event = (tcg_pcr_event_t *)log_ptr;

	if (event_data_size > 0U && event_data == NULL) {
		return -EINVAL;
	}

	/* Minimum space: header without digests/data */
	if (exceeds_bounds((uintptr_t)pcr_event, sizeof(tcg_pcr_event_t))) {
		return -ENOMEM;
	}

	/* TCG_PCR_EVENT.PCRIndex */
	pcr_event->pcr_index = pcr_index;

	/* TCG_PCR_EVENT.EventType */
	pcr_event->event_type = event_type;

	/* TCG_PCR_EVENT.Digest */
	if (digest != NULL) {
		(void)memcpy(pcr_event->digest, digest, SHA1_DIGEST_SIZE);
	} else {
		(void)memset(pcr_event->digest, 0, SHA1_DIGEST_SIZE);
	}

	/* TCG_PCR_EVENT.EventSize*/
	pcr_event->event_size = event_data_size;

	if (exceeds_bounds((uintptr_t)pcr_event->event,
			   pcr_event->event_size)) {
		return -ENOMEM;
	}

	if (event_data_size > 0U) {
		(void)memcpy(pcr_event->event, event_data, event_data_size);
	}

	log_ptr = (uint8_t *)pcr_event->event + event_data_size;
	return 0;
}

int event_log_init(uint8_t *start, uint8_t *finish)
{
	if ((start == NULL || finish == NULL) || start > finish) {
		return -EINVAL;
	}

	log_ptr = start;
	log_end = (uintptr_t)finish;
	log_start = start;

	return 0;
}

int event_log_init_from_pos(uint8_t *start, uint8_t *finish, size_t pos)
{
	uint8_t *ptr = start;
	int rc;

	rc = event_log_init(start, finish);
	if (rc < 0) {
		return rc;
	}

	/*
	 * If a prior cursor offset is provided, the first event in a TCG EFI log
	 * should be the Spec ID event carried in ev->event[]. Probe for the "Spec
	 * ID Event03" signature.
	 */
	if (pos > 0U) {
		if (pos > (finish - start) ||
		    pos < sizeof(struct tcg_efi_spec_id_event)) {
			ERROR("Invalid cursor offset (%ld).\n", pos);
			return -EINVAL;
		}

		ptr = ((tcg_pcr_event_t *)start)->event;
		rc = memcmp(ptr, TCG_ID_EVENT_SIGNATURE_03,
			    strlen(TCG_ID_EVENT_SIGNATURE_03));
		if (rc != 0U) {
			ERROR("Invalid SpecID header at base address %p.\n",
			      log_start);
			return -EINVAL;
		}

		spec_id_header = (tcg_efi_spec_id_event_t *)ptr;
	}

	log_ptr = start + pos;

	return 0;
}

int event_log_write_specid_event(const tpm_alg_id *algorithms,
				 uint32_t algo_count,
				 const uint8_t *vendor_info,
				 uint8_t vendor_info_size)
{
	tcg_pcr_event_t *pcr_event;
	tcg_vendor_info_t *vendor_info_ptr;
	size_t total_size;
	int rc;
	tcg_efi_spec_id_event_t *spec_id_ptr;
	const tcg_efi_spec_id_event_t spec_id_event = {
		.signature = TCG_ID_EVENT_SIGNATURE_03,
		.platform_class = PLATFORM_CLASS_CLIENT,
		.spec_version_minor = TCG_SPEC_VERSION_MINOR_TPM2,
		.spec_version_major = TCG_SPEC_VERSION_MAJOR_TPM2,
		.spec_errata = TCG_SPEC_ERRATA_TPM2,
		.uintn_size =
			(uint8_t)(sizeof(unsigned int) / sizeof(uint32_t)),
	};

	if (log_ptr == NULL) {
		ERROR("Cannot call library function, initialization not completed.\n");
		return -EFAULT;
	}

	if (algorithms == NULL || algo_count == 0U) {
		ERROR("Invalid algorithm configuration.\n");
		return -EINVAL;
	}

	pcr_event = (tcg_pcr_event_t *)log_ptr;

	/* Prime with template header (PCR index, EV_NO_ACTION, signature, etc.) */
	rc = event_log_write_pcr_event(PCR_0, EV_NO_ACTION, NULL,
				       (uint8_t *)&spec_id_event,
				       sizeof(spec_id_event));
	if (rc != 0U) {
		return rc;
	}

	/* Total bytes we will write into the log buffer for TCG_EfiSpecIDEvent. */
	total_size = sizeof(tcg_efi_spec_id_event_t) +
		     sizeof(id_event_algorithm_size_t) * algo_count +
		     sizeof(tcg_vendor_info_t) + vendor_info_size;

	spec_id_ptr = (tcg_efi_spec_id_event_t *)pcr_event->event;

	/* Check buffer capacity for the entire record */
	if (exceeds_bounds((uintptr_t)spec_id_ptr, total_size)) {
		return -ENOMEM;
	}

	/* TCG_EfiSpecIdEvent.DigestSize */
	spec_id_ptr->number_of_algorithms = algo_count;
	for (uint16_t i = 0; i < algo_count; i++) {
		switch (algorithms[i]) {
		case EVLOG_TPM_ALG_SHA256:
			spec_id_ptr->digest_size[i].digest_size =
				SHA256_DIGEST_SIZE;
			break;
		case EVLOG_TPM_ALG_SHA384:
			spec_id_ptr->digest_size[i].digest_size =
				SHA384_DIGEST_SIZE;
			break;
		case EVLOG_TPM_ALG_SHA512:
			spec_id_ptr->digest_size[i].digest_size =
				SHA512_DIGEST_SIZE;
			break;
		default:
			ERROR("Unrecognized TPM algorithm ID %u",
			      algorithms[i]);
			return EINVAL;
		}

		spec_id_ptr->digest_size[i].algorithm_id = algorithms[i];
	}

	/* TCG_EfiSpecIdEvent.VendorInfo */
	if (vendor_info_size > 0) {
		vendor_info_ptr =
			(tcg_vendor_info_t *)(spec_id_ptr->digest_size +
					      algo_count);

		vendor_info_ptr->vendor_info_size = vendor_info_size;

		if (vendor_info == NULL) {
			ERROR("Invalid VendorInfo buffer.\n");
			return -EINVAL;
		}

		(void)memcpy(vendor_info_ptr->vendor_info, vendor_info,
			     vendor_info_size);
	}

	/*
	 * Stash the TCG_EfiSpecIdEvent for later to enable discovery of supported
	 * algorithms.
	 */
	spec_id_header = spec_id_ptr;

	pcr_event->event_size = total_size;
	log_ptr = (uint8_t *)spec_id_ptr + total_size;

	return 0;
}

int event_log_write_header(const tpm_alg_id *algorithms, uint32_t algo_count,
			   uint8_t locality, const uint8_t *vendor_info,
			   uint8_t vendor_info_size)
{
	startup_locality_event_t startup_locality = {
		TCG_STARTUP_LOCALITY_SIGNATURE, locality
	};
	int rc;

	rc = event_log_write_specid_event(algorithms, algo_count, vendor_info,
					  vendor_info_size);
	if (rc != 0) {
		ERROR("Failed to write SpecID event: %d\n", rc);
		return rc;
	}

	rc = event_log_write_pcr_event2(PCR_0, EV_NO_ACTION, NULL,
					(uint8_t *)&startup_locality,
					sizeof(startup_locality_event_t));
	if (rc != 0) {
		ERROR("Failed to write startup locality: %d\n", rc);
		return rc;
	}

	return 0;
}

int event_log_measure(uintptr_t data_base, size_t data_size, uint8_t *hash_buf,
		      size_t hash_buf_size)
{
	int rc;
	uint8_t *digest_buf;
	uint8_t *hash_buf_end = hash_buf + hash_buf_size;
	const id_event_algorithm_size_t *event_log_algo;

	if (event_log_hash_func == NULL) {
		ERROR("No hash function registered for measurement.\n");
		return -EINVAL;
	}

	if (hash_buf == NULL || hash_buf_size == sizeof(tpml_digest_values)) {
		ERROR("Invalid hash buffer or insufficient space.\n");
		return -EINVAL;
	}

	/*
	 * Write the digest count into hash buffer, the buffer should have
	 * sufficient space to hold the count and count * sizeof(tpmt_ha)
	 * digests.
	 */
	((tpml_digest_values *)hash_buf)->count =
		spec_id_header->number_of_algorithms;
	digest_buf =
		(uint8_t *)hash_buf + offsetof(tpml_digest_values, digests);

	for (size_t i = 0; i < spec_id_header->number_of_algorithms; i++) {
		event_log_algo = &spec_id_header->digest_size[i];
		assert(event_log_algo->digest_size != 0U);

		if (digest_buf > hash_buf_end - (sizeof(tpmt_ha) +
						 event_log_algo->digest_size)) {
			ERROR("Not enough memory in allocated hash buffer.\n");
			return -ENOMEM;
		}

		((tpmt_ha *)digest_buf)->algorithm_id =
			event_log_algo->algorithm_id;

		rc = event_log_hash_func(((tpmt_ha *)digest_buf)->algorithm_id,
					 (void *)data_base, data_size,
					 ((tpmt_ha *)digest_buf)->digest);
		if (rc < 0) {
			ERROR("Image measurement failed (%d).\n", rc);
			return rc;
		}

		digest_buf += sizeof(tpmt_ha) + event_log_algo->digest_size;
	}

	return 0;
}

int event_log_init_and_reg(uint8_t *start, uint8_t *finish, size_t pos,
			   evlog_hash_func_t hash_func)
{
	int rc = event_log_init_from_pos(start, finish, pos);
	if (rc < 0) {
		return rc;
	}

	if (hash_func == NULL) {
		WARN("No hash backend provided, skipping registration.\n");
	} else {
		event_log_hash_func = hash_func;
	}

	return 0;
}

int event_log_measure_and_record(uint32_t pcr, uintptr_t data_base,
				 uint32_t data_size, const void *event_data,
				 size_t event_data_size)
{
	uint8_t hash_buf[MAX_TPML_BUFFER_SIZE];
	int rc;

	if (log_ptr == NULL || spec_id_header == NULL) {
		ERROR("Cannot call library function, initialization not completed.\n");
		return -EINVAL;
	}

	/* Measure the payload with algorithm selected by EventLog driver */
	rc = event_log_measure(data_base, data_size, hash_buf,
			       sizeof(hash_buf));
	if (rc != 0) {
		return rc;
	}

	rc = event_log_write_pcr_event2(pcr, EV_POST_CODE,
					(const tpml_digest_values *)hash_buf,
					event_data, event_data_size);
	if (rc != 0) {
		return rc;
	}

	return 0;
}

size_t event_log_get_cur_size(uint8_t *_start)
{
	assert(_start != NULL);
	assert(log_ptr >= _start);

	return (size_t)((uintptr_t)log_ptr - (uintptr_t)_start);
}
