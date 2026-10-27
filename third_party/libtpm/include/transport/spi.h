/*
 * Copyright (c) 2025-2026, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TPM_SPI_TRANSPORT_H
#define TPM_SPI_TRANSPORT_H

struct tpm_spi_ops {
	int (*get_access)(void *ctx);
	void (*release_access)(void *ctx);
	void (*start)(void *ctx);
	void (*stop)(void *ctx);
	int (*xfer)(void *ctx, unsigned int bytelen,
		    const void *dout, void *din);
};

struct tpm_spi_priv;

struct tpm_spi_plat {
	struct tpm_spi_priv *priv;
	const struct tpm_spi_ops *ops;
};



#endif /* TPM_SPI_TRANSPORT_H */
