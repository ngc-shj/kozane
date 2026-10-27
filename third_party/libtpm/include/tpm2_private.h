/*
 * Copyright (c) 2025-2026, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TPM2_PRIVATE_H
#define TPM2_PRIVATE_H

#include "tpm2_chip.h"
#include "debug.h"

/*
 * TPM FIFO register space address offsets
 */
#define TPM_FIFO_REG_ACCESS	((uint32_t)0x000U)
#define TPM_FIFO_REG_INTR_ENABLE	((uint32_t)0x008U)
#define TPM_FIFO_REG_INTR_VECTOR	((uint32_t)0x00CU)
#define TPM_FIFO_REG_INTR_STS	((uint32_t)0x010U)
#define TPM_FIFO_REG_INTF_CAPS	((uint32_t)0x014U)
#define TPM_FIFO_REG_STATUS	((uint32_t)0x018U)
#define TPM_FIFO_REG_BURST_COUNT_LO	((uint32_t)0x019U)
#define TPM_FIFO_REG_BURST_COUNT_HI	((uint32_t)0x020U)
#define TPM_FIFO_REG_DATA_FIFO	((uint32_t)0x024U)
#define TPM_FIFO_REG_VENDID	((uint32_t)0xF00U)
#define TPM_FIFO_REG_DEVID	((uint32_t)0xF02U)
#define TPM_FIFO_REG_REVID	((uint32_t)0xF04U)

/* Structure tags (16-bit) */
#define TPM_ST_NO_SESSIONS	((uint16_t)0x8001U)
#define TPM_ST_SESSIONS	((uint16_t)0x8002U)

/* Sizes / handles */
#define TPM_MIN_AUTH_SIZE	((uint32_t)9U)
#define TPM_RS_PW	((uint32_t)0x40000009UL)
#define TPM_ZERO_NONCE_SIZE	((uint32_t)0U)
#define TPM_ATTRIBUTES_DISABLE	((uint32_t)0U)
#define TPM_ZERO_HMAC_SIZE	((uint32_t)0U)
#define TPM_SINGLE_HASH_COUNT	((uint32_t)1U)
/* 24 PCRs bit-mask with 3 bytes */
#define TPM_PCR_SELECT_SIZE	((uint8_t)0x3U)

/* Commands (16-bit) */
#define TPM_CMD_STARTUP	((uint16_t)0x0144U)
#define TPM_CMD_PCR_READ	((uint16_t)0x017EU)
#define TPM_CMD_PCR_EXTEND	((uint16_t)0x0182U)

/* Response codes (16-bit) */
#define TPM_RESPONSE_SUCCESS	((uint16_t)0x0000U)

/* ACCESS register bit masks (8-bit) */
#define TPM_ACCESS_ACTIVE_LOCALITY	((uint8_t)(1U << 5))
#define TPM_ACCESS_VALID	((uint8_t)(1U << 7))
#define TPM_ACCESS_RELINQUISH_LOCALITY	((uint8_t)(1U << 5))
#define TPM_ACCESS_REQUEST_USE	((uint8_t)(1U << 1))
#define TPM_ACCESS_REQUEST_PENDING	((uint8_t)(1U << 2))

/* STATUS register bit masks (8-bit) */
#define TPM_STAT_VALID	((uint8_t)(1U << 7))
#define TPM_STAT_COMMAND_READY	((uint8_t)(1U << 6))
#define TPM_STAT_GO	((uint8_t)(1U << 5))
#define TPM_STAT_AVAIL	((uint8_t)(1U << 4))
#define TPM_STAT_EXPECT	((uint8_t)(1U << 3))

#define TPM_READ_HEADER	((int32_t)-1)

#define TPM_HEADER_SIZE	((uint32_t)10U)
#define MAX_SIZE_CMDBUF	((uint32_t)256U)
#define MAX_CMD_DATA	((uint32_t)(MAX_SIZE_CMDBUF - TPM_HEADER_SIZE))
#define MAX_DIGEST_SIZE	((uint32_t)32U)

/*
 * Provide a backward-compatible implementation of static_assert.
 * This keyword was introduced in C11, so it may be unavailable in
 * projects targeting older C standards.
 */
#if __STDC_VERSION__ >= 201112L
#define TPM_STATIC_ASSERT(cond, msg) _Static_assert(cond, #msg)
#else
#define TPM_STATIC_ASSERT(cond, msg) \
	typedef char static_assertion_##msg[(cond) ? 1 : -1]
#endif

struct tpm_cmd_hdr {
	uint16_t tag;
	uint32_t cmd_size;
	uint32_t cmd_code;
} __attribute__((__packed__));
typedef struct tpm_cmd_hdr tpm_cmd_hdr;

struct tpm_cmd {
	tpm_cmd_hdr header;
	uint8_t data[MAX_CMD_DATA];
} __attribute__((__packed__));
typedef struct tpm_cmd tpm_cmd;

struct tpm_pcr_single_read_res {
	uint32_t pcr_update_ctr;
	uint32_t tpml_pcr_selection_count;
	uint16_t tpms_pcr_selection_hash;
	uint32_t tpms_pcr_selection_num_octate_bitmap;
	uint32_t tpml_digest_count;
	uint16_t tpml_digest_size;
	uint8_t digest[MAX_DIGEST_SIZE];
} __attribute__((packed));

TPM_STATIC_ASSERT(sizeof(tpm_cmd_hdr) == TPM_HEADER_SIZE,
		  tpm_cmd_hdr__incorrect_size);

typedef struct interface_ops {
	int (*get_info)(struct tpm_chip_data *chip_data, uint8_t locality);
	int (*send)(struct tpm_chip_data *chip_data, const tpm_cmd *buf);
	int (*receive)(struct tpm_chip_data *chip_data, tpm_cmd *buf);
	int (*request_access)(struct tpm_chip_data *chip_data,
			      uint8_t locality);
	int (*release_locality)(struct tpm_chip_data *chip_data,
				uint8_t locality);
} interface_ops_t;

extern struct tpm_timeout_ops tpm_timeout_ops;
extern const struct tpm_spi_plat *tpm_spidev;
extern int tpm_last_transport_error;

struct interface_ops *tpm_interface_getops(struct tpm_chip_data *chip_data,
					   uint8_t locality);

int tpm2_fifo_write_byte(uint16_t tpm_reg, uint8_t val);

int tpm2_fifo_read_byte(uint16_t tpm_reg, uint8_t *val);

int tpm2_fifo_read_chunk(uint16_t tpm_reg, uint8_t len, void *val);

/* HAS_LIB_TIMER is set if a standard library (e.g. POSIX) timer supplies
 * the timeout functions, rather than being passed explicitly to the TPM
 * library.
 */
#ifdef HAS_LIB_TIMER
extern const struct tpm_timeout_ops tpm_lib_timeout_ops;
#endif

#endif /* TPM2_PRIVATE_H */
