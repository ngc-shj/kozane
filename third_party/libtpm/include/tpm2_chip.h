/*
 * Copyright (c) 2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdbool.h>
#include <stdint.h>

#ifndef TPM2_CHIP_H
#define TPM2_CHIP_H

struct tpm_chip_timeouts {
	unsigned long msec_a, msec_b;
	unsigned long msec_c, msec_d;
};

struct tpm_chip_data {
	uint8_t locality;
	const struct tpm_chip_timeouts *timeouts;
};

#endif /* TPM2_CHIP_H */
