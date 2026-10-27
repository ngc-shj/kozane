/*
 * Copyright (c) 2025-2026, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TPM2_H
#define TPM2_H

#include <errno.h>
#include <stdint.h>
#include "platform/tpm_platform.h"
#include "tpm2_chip.h"

#define TPM_SU_CLEAR 0x0000U
#define TPM_SU_STATE 0x0001U

#define TPM_ALG_SHA256	((uint16_t)0x000BU)

/* Return values */
enum tpm_ret_value {
	TPM_SUCCESS = 0,
	TPM_ERR_RESPONSE = -1,
	TPM_INVALID_PARAM = -2,
	TPM_ERR_TIMEOUT = -3,
	TPM_ERR_TRANSFER = -4,
};

int tpm_get_last_transport_error(void);

int tpm_interface_init(const struct tpm_spi_plat *transport,
		       const struct tpm_timeout_ops *timeout_ops,
		       struct tpm_chip_data *chip_data, uint8_t locality);

int tpm_interface_close(struct tpm_chip_data *chip_data, uint8_t locality);

int tpm_startup(struct tpm_chip_data *chip_data, uint16_t mode);

int tpm_pcr_extend(struct tpm_chip_data *chip_data, uint32_t index,
		   uint16_t algorithm, const uint8_t *digest,
		   uint32_t digest_len);

int tpm_pcr_read_single(struct tpm_chip_data *chip_data, uint32_t index,
			uint16_t algorithm,
			uint8_t *pcr_digest_read,
			size_t pcr_digest_read_len);

#endif /* TPM2_H */
