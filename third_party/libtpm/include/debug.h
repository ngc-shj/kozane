/*
 * Copyright (c) 2013-2025, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DEBUG_H
#define DEBUG_H

#include DEBUG_BACKEND_HEADER

/*
 * The log output macros print output to the console. These macros produce
 * compiled log output only if the LOG_LEVEL defined in the makefile (or the
 * make command line) is greater or equal than the level required for that
 * type of log output.
 *
 * The format expected is the same as for printf(). For example:
 * INFO("Info %s.\n", "message")    -> INFO:    Info message.
 * WARN("Warning %s.\n", "message") -> WARNING: Warning message.
 */

#define LOG_LEVEL_NONE 0
#define LOG_LEVEL_ERROR 10
#define LOG_LEVEL_NOTICE 20
#define LOG_LEVEL_WARNING 30
#define LOG_LEVEL_INFO 40
#define LOG_LEVEL_VERBOSE 50

/*
 * If the log output is too low then this macro is used in place of tpm_log()
 * below. The intent is to get the compiler to evaluate the function call for
 * type checking and format specifier correctness but let it optimize it out.
 */
#define no_tpm_log(fmt, ...)                         \
	do {                                         \
		if (false) {                         \
			tpm_log(fmt, ##__VA_ARGS__); \
		}                                    \
	} while (false)

#if LOG_LEVEL >= LOG_LEVEL_ERROR
#define ERROR(...) tpm_log(LOG_MARKER_ERROR __VA_ARGS__)
#else
#define ERROR(...) no_tpm_log(LOG_MARKER_ERROR __VA_ARGS__)
#endif

#if LOG_LEVEL >= LOG_LEVEL_NOTICE
#define NOTICE(...) tpm_log(LOG_MARKER_NOTICE __VA_ARGS__)
#else
#define NOTICE(...) no_tpm_log(LOG_MARKER_NOTICE __VA_ARGS__)
#endif

#if LOG_LEVEL >= LOG_LEVEL_WARNING
#define WARN(...) tpm_log(LOG_MARKER_WARNING __VA_ARGS__)
#else
#define WARN(...) no_tpm_log(LOG_MARKER_WARNING __VA_ARGS__)
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO
#define INFO(...) tpm_log(LOG_MARKER_INFO __VA_ARGS__)
#else
#define INFO(...) no_tpm_log(LOG_MARKER_INFO __VA_ARGS__)
#endif

#if LOG_LEVEL >= LOG_LEVEL_VERBOSE
#define VERBOSE(...) tpm_log(LOG_MARKER_VERBOSE __VA_ARGS__)
#else
#define VERBOSE(...) no_tpm_log(LOG_MARKER_VERBOSE __VA_ARGS__)
#endif

#endif /* DEBUG_H */
