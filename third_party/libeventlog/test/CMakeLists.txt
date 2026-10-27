#
# Copyright (c) 2025, Arm Limited.
#
# SPDX-License-Identifier: BSD-3-Clause
#

enable_testing()

add_executable(eventlog_tests
    main.c
    utils.c
)

target_include_directories(eventlog_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/test
)

target_link_libraries(eventlog_tests PRIVATE
    unity
    eventlog
)

add_test(NAME eventlog_tests COMMAND eventlog_tests)
