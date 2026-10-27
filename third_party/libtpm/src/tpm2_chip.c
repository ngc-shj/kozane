
/*
 * Copyright (c) 2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <tpm2_chip.h>

/*
 * TPM timeout values
 * Reference: TCG PC Client Platform TPM Profile (PTP) Specification v1.05
 */
const struct tpm_chip_timeouts tpm_timeouts = {
	.msec_a = 750,
	.msec_b = 2000,
	.msec_c = 200,
	.msec_d = 30,
};

struct tpm_chip_data tpm_chip_data = {
	.locality = -1,
	.timeouts = &tpm_timeouts,
};
