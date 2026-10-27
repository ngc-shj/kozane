/*
 * Copyright (c) 2025, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LOG_BACKEND_PRINTF_H
#define LOG_BACKEND_PRINTF_H

#include <stdio.h>

#define evlog_log printf

#define EVLOG_MARKER_ERROR "[ERROR] "
#define EVLOG_MARKER_NOTICE "[NOTICE] "
#define EVLOG_MARKER_WARNING "[WARNING] "
#define EVLOG_MARKER_INFO "[INFO] "
#define EVLOG_MARKER_VERBOSE "[VERBOSE] "

#endif /* LOG_BACKEND_PRINTF_H */
