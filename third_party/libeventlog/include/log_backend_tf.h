/*
 * Copyright (c) 2025, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LOG_BACKEND_TF_H
#define LOG_BACKEND_TF_H

#include <stdio.h>

void evlog_log(const char *fmt, ...) __asm__("tf_log");

#define EVLOG_MARKER_ERROR "\xa" /* 10 */
#define EVLOG_MARKER_NOTICE "\x14" /* 20 */
#define EVLOG_MARKER_WARNING "\x1e" /* 30 */
#define EVLOG_MARKER_INFO "\x28" /* 40 */
#define EVLOG_MARKER_VERBOSE "\x32" /* 50 */

#endif /* LOG_BACKEND_TF_H */
