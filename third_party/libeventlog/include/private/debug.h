/*
 * Copyright (c) 2025, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DEBUG_H
#define DEBUG_H

#include DEBUG_BACKEND_HEADER

/*
 * The log output macros print output to the console. These macros produce
 * compiled log output only if the EVLOG_LOG_LEVEL defined in the makefile (or the
 * make command line) is greater or equal than the level required for that
 * type of log output.
 *
 * The format expected is the same as for printf(). For example:
 * INFO("Info %s.\n", "message")    -> INFO:    Info message.
 * WARN("Warning %s.\n", "message") -> WARNING: Warning message.
 */

#define EVLOG_LEVEL_NONE 0
#define EVLOG_LEVEL_ERROR 10
#define EVLOG_LEVEL_NOTICE 20
#define EVLOG_LEVEL_WARNING 30
#define EVLOG_LEVEL_INFO 40
#define EVLOG_LEVEL_VERBOSE 50

/*
 * If the log output is too low then this macro is used in place of evlog_log()
 * below. The intent is to get the compiler to evaluate the function call for
 * type checking and format specifier correctness but let it optimize it out.
 */
#define no_evlog_log(fmt, ...)                         \
	do {                                           \
		if (false) {                           \
			evlog_log(fmt, ##__VA_ARGS__); \
		}                                      \
	} while (false)

#if EVLOG_LOG_LEVEL >= EVLOG_LEVEL_ERROR
#define ERROR(...) evlog_log(EVLOG_MARKER_ERROR __VA_ARGS__)
#else
#define ERROR(...) no_evlog_log(EVLOG_MARKER_ERROR __VA_ARGS__)
#endif

#if EVLOG_LOG_LEVEL >= EVLOG_LEVEL_NOTICE
#define NOTICE(...) evlog_log(EVLOG_MARKER_NOTICE __VA_ARGS__)
#else
#define NOTICE(...) no_evlog_log(EVLOG_MARKER_NOTICE __VA_ARGS__)
#endif

#if EVLOG_LOG_LEVEL >= EVLOG_LEVEL_WARNING
#define WARN(...) evlog_log(EVLOG_MARKER_WARNING __VA_ARGS__)
#else
#define WARN(...) no_evlog_log(EVLOG_MARKER_WARNING __VA_ARGS__)
#endif

#if EVLOG_LOG_LEVEL >= EVLOG_LEVEL_INFO
#define INFO(...) evlog_log(EVLOG_MARKER_INFO __VA_ARGS__)
#else
#define INFO(...) no_evlog_log(EVLOG_MARKER_INFO __VA_ARGS__)
#endif

#if EVLOG_LOG_LEVEL >= EVLOG_LEVEL_VERBOSE
#define VERBOSE(...) evlog_log(EVLOG_MARKER_VERBOSE __VA_ARGS__)
#else
#define VERBOSE(...) no_evlog_log(EVLOG_MARKER_VERBOSE __VA_ARGS__)
#endif

#endif /* DEBUG_H */
