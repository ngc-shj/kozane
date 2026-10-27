#!/usr/bin/env bash
#
# Copyright (c) 2025, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_INSTALL_DIR="${SCRIPT_DIR}"
TEST_INSTALL_BUILD_DIR="${TEST_INSTALL_DIR}/build"

LIBEVENTLOG_DIR="$(realpath "${SCRIPT_DIR}/../..")"
LIBEVENTLOG_BUILD_DIR="${LIBEVENTLOG_DIR}/build"
INSTALL_DIR="$(mktemp -d)"

echo "==> Building main project at ${LIBEVENTLOG_DIR}"
cmake -S "${LIBEVENTLOG_DIR}" -B "${LIBEVENTLOG_BUILD_DIR}" \
	-DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}" -DDEBUG_BACKEND_HEADER="log_backend_printf.h" --fresh
cmake --build "${LIBEVENTLOG_BUILD_DIR}" --parallel
cmake --install "${LIBEVENTLOG_BUILD_DIR}"

echo "==> Building subproject at ${TEST_INSTALL_DIR}"
cmake -S "${TEST_INSTALL_DIR}" -B "${TEST_INSTALL_BUILD_DIR}" \
	-DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}" --fresh
cmake --build "${TEST_INSTALL_BUILD_DIR}" --parallel

echo "==> Building subproject at ${TEST_INSTALL_DIR} without CMake"
cc -I${INSTALL_DIR}/include -L${INSTALL_DIR}/lib -leventlog ${TEST_INSTALL_DIR}/main.c
