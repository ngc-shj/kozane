/*
 * Copyright (c) 2025-2026, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <tpm2.h>
#include <tpm2_chip.h>
#include <tpm2_private.h>
#include <transport/spi.h>

#define ENCODE_LIMIT 64U
#define TPM_SPI_ADDR_PREFIX 0xD4U
#define RETRY_COUNT 50U

typedef enum { TPM_ACCESS_READ = 0, TPM_ACCESS_WRITE = 1 } tpm_access_t;

const struct tpm_spi_plat *tpm_spidev;

static int tpm2_spi_transfer(const void *data_out, void *data_in, uint8_t len)
{
	int r = tpm_spidev->ops->xfer(tpm_spidev->priv, len, data_out, data_in);
	if (r != 0) {
		tpm_last_transport_error = r;
	}
	return r;
}

/*
 * Reference: TCG PC Client Platform TPM Profile (PTP) Specification v1.05
 */
static int tpm2_spi_start_transaction(uint16_t tpm_reg, tpm_access_t access,
				      uint8_t len)
{
	int rc;
	uint8_t header[4];
	uint8_t header_response[4];
	uint8_t zero = 0, byte;
	int retries;

	/* check to make sure len does not exceed the encoding limit */
	if (len > ENCODE_LIMIT) {
		return TPM_INVALID_PARAM;
	}

	/*
	 * 7.4.6 TPM SPI Bit protocol calls for the following header
	 * to be sent to the TPM at the start of every attempted read/write.
	 */

	/* header[0] contains the r/w and the xfer size, if the msb is not
	 * set, the operation is write, if it is set then it is read.
	 * The size of the transfer is encoded, and must not overwrite
	 * the two msb, therefore an ENCODE LIMIT of 64.
	 */
	header[0] = ((access == TPM_ACCESS_WRITE) ? 0x00 : 0x80) | (len - 1);

	/*
	 * header[1] contains the address offset 0xD4_xxxx as defined
	 * in the TPM spec.
	 */
	header[1] = TPM_SPI_ADDR_PREFIX;

	/*
	 * header[2] and header[3] contain the address of the register
	 * to be read/written.
	 */
	header[2] = tpm_reg >> 8;
	header[3] = tpm_reg;

	rc = tpm2_spi_transfer(header, header_response, 4);
	if (rc != 0) {
		return TPM_ERR_TRANSFER;
	}

	/*
	 * 7.4.5 Flow Control defines a wait state in order to accommodate
	 * the TPM in case it needs to free its buffer.
	 */
	if ((header_response[3] & 0x01) != 0U) {
		return TPM_SUCCESS;
	}

	/*
	 * if the wait state over bit is not set in the initial header_response,
	 * poll for the wait state over by sending a zeroed byte, if the
	 * RETRY_COUNT is exceeded the transfer fails.
	 */
	for (retries = RETRY_COUNT; retries > 0; retries--) {
		rc = tpm2_spi_transfer(&zero, &byte, 1);
		if (rc != 0) {
			return TPM_ERR_TRANSFER;
		}
		if ((byte & 0x01) != 0U) {
			return TPM_SUCCESS;
		}
	}

	if (retries == 0) {
		ERROR("%s: TPM Timeout\n", __func__);
		return TPM_ERR_TIMEOUT;
	}

	return TPM_SUCCESS;
}

static void tpm2_spi_end_transaction(void)
{
	tpm_spidev->ops->stop(tpm_spidev->priv);
	tpm_spidev->ops->release_access(tpm_spidev->priv);
}

static int tpm2_spi_init(void)
{
	int rc;

	rc = tpm_spidev->ops->get_access(tpm_spidev->priv);
	if (rc != 0) {
		tpm_last_transport_error = rc;
		return TPM_ERR_TRANSFER;
	}
	tpm_spidev->ops->start(tpm_spidev->priv);
	return 0;
}

static int tpm2_fifo_io(uint16_t tpm_reg, tpm_access_t access, uint8_t len,
			void *val)
{
	int rc;

	rc = tpm2_spi_init();
	if (rc != 0) {
		return rc;
	}

	rc = tpm2_spi_start_transaction(tpm_reg, access, len);
	if (rc != 0) {
		tpm2_spi_end_transaction();
		return rc;
	}

	rc = tpm2_spi_transfer((access == TPM_ACCESS_WRITE) ? val : NULL,
			       (access == TPM_ACCESS_READ) ? val : NULL, len);
	if (rc != 0) {
		tpm2_spi_end_transaction();
		return TPM_ERR_TRANSFER;
	}

	tpm2_spi_end_transaction();

	return TPM_SUCCESS;
}

int tpm2_fifo_write_byte(uint16_t tpm_reg, uint8_t val)
{
	return tpm2_fifo_io(tpm_reg, TPM_ACCESS_WRITE, 1, &val);
}

int tpm2_fifo_read_byte(uint16_t tpm_reg, uint8_t *val)
{
	return tpm2_fifo_io(tpm_reg, TPM_ACCESS_READ, 1, val);
}

int tpm2_fifo_read_chunk(uint16_t tpm_reg, uint8_t len, void *val)
{
	if ((len != 1) && (len != 2) && (len != 4)) {
		return TPM_INVALID_PARAM;
	}

	return tpm2_fifo_io(tpm_reg, TPM_ACCESS_READ, len, val);
}
