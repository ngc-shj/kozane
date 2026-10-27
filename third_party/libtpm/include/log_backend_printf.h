/*
 * Copyright (c) 2025, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LOG_BACKEND_PRINTF_H
#define LOG_BACKEND_PRINTF_H

#include <stdio.h>

#define tpm_log printf

#define LOG_MARKER_ERROR "[ERROR] "
#define LOG_MARKER_NOTICE "[NOTICE] "
#define LOG_MARKER_WARNING "[WARNING] "
#define LOG_MARKER_INFO "[INFO] "
#define LOG_MARKER_VERBOSE "[VERBOSE] "

#endif /* LOG_BACKEND_PRINTF_H */
