/*
 * Copyright (c) 2026, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef TPM_PLATFORM_H
#define TPM_PLATFORM_H

#include <stdbool.h>
#include <stdint.h>

struct tpm_spi_plat;

struct tpm_timeout_ops {
	uint64_t (*timeout_init_us)(uint32_t usec);
	bool (*timeout_elapsed)(uint64_t cnt);
};

#endif /* TPM_PLATFORM_H */
