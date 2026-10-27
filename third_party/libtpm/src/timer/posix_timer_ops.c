/*
 * Copyright (c) 2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "tpm2.h"

/**
 * @brief Gets the current time in microseconds using CLOCK_MONOTONIC.
 *
 * @return Time in microseconds since system boot (or an unspecified starting point).
 */
static uint64_t get_time_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/**
 * @brief Retrieves the current timer value as the lower 32 bits of microseconds.
 *
 * @return 32-bit timer value.
 */
static uint32_t get_timer_value_impl(void)
{
	return (uint32_t)(get_time_us() & 0xFFFFFFFF);
}

/**
 * @brief Initializes a timeout by returning the expiration timestamp.
 *
 * @param usec Timeout duration in microseconds.
 * @return Expiration timestamp in microseconds.
 */
static uint64_t timeout_init_us_impl(uint32_t usec)
{
	return get_time_us() + (uint64_t)usec;
}

/**
 * @brief Determines if the specified timeout has elapsed.
 *
 * @param expiry_time_us The expiration time from timeout_init_us().
 * @return true if the timeout has expired, false otherwise.
 */
static bool timeout_elapsed_impl(uint64_t expiry_time_us)
{
	return get_time_us() >= expiry_time_us;
}

/**
 * @brief Global instance of the POSIX-based timer implementation.
 *
 */
const struct tpm_timeout_ops tpm_lib_timeout_ops = {
	.timeout_init_us = timeout_init_us_impl,
	.timeout_elapsed = timeout_elapsed_impl
};
