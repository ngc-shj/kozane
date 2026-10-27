#
# Copyright (c) 2025, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#

cmake_minimum_required(VERSION 3.15)

project(libtpm2 VERSION 0.1 LANGUAGES C)

#
# Set global flags.
#
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED TRUE)
set(CMAKE_C_EXTENSIONS TRUE)
set (TPM_INTERFACE "NONE" CACHE STRING "Transport interface for TPM (Currently supported: FIFO_SPI)")
set_property (CACHE TPM_INTERFACE PROPERTY STRINGS "FIFO_SPI")

set(
    LOG_LEVEL "" CACHE STRING
    "Log Level options:
     0  - NONE
     10 - ERROR
     20 - NOTICE
     30 - WARNING
     40 - INFO
     50 - VERBOSE"
)

if(LOG_LEVEL STREQUAL "")
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        set(LOG_LEVEL 10)
    else()
        set(LOG_LEVEL 40)
    endif()
endif()

add_compile_definitions(LOG_LEVEL=${LOG_LEVEL})

set(DEBUG_BACKEND_HEADER "log_backend_printf.h" CACHE STRING "Path to debug backend header")
add_compile_definitions(DEBUG_BACKEND_HEADER="${DEBUG_BACKEND_HEADER}")

set (LIB_TIMER "NONE" CACHE STRING "Option to use library timer, rather than explicitly pass one")
set_property (CACHE LIB_TIMER PROPERTY STRINGS "NONE" "POSIX")


SET(TARGET_GROUP release CACHE STRING "Specify the Build Target [\"release\" by default]")

add_library(tpm2
    STATIC
        ${PROJECT_SOURCE_DIR}/src/tpm2_chip.c
        ${PROJECT_SOURCE_DIR}/src/tpm2_cmds.c
)

if (NOT DEFINED TPM_INTERFACE OR
    TPM_INTERFACE STREQUAL "" OR
    TPM_INTERFACE STREQUAL "NONE")
    message(WARNING "TPM_INTERFACE not set — defaulting to FIFO_SPI")
    set(TPM_INTERFACE "FIFO_SPI")
endif()

if (${TPM_INTERFACE} STREQUAL "FIFO_SPI")
   target_sources (tpm2
       PRIVATE
        ${PROJECT_SOURCE_DIR}/src/tpm2_fifo.c
        ${PROJECT_SOURCE_DIR}/src/tpm2_fifo_spi.c
   )
   target_compile_definitions(tpm2 PRIVATE TPM_INTERFACE_FIFO_SPI)
else()
   message(FATAL_ERROR "Unknown transport interface selected")
endif()

if (${LIB_TIMER} STREQUAL "POSIX")
   target_sources (tpm2
       PRIVATE
          ${PROJECT_SOURCE_DIR}/src/timer/posix_timer_ops.c
   )
   add_compile_definitions (HAS_LIB_TIMER=1)
endif()


target_include_directories(tpm2
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
	$<INSTALL_INTERFACE:include/tpm2>  # extra path for unqualified includes
)


if(PROJECT_API)
    include(${PROJECT_SOURCE_DIR}/cmake/ProjectApi.cmake)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# Install the library
install(TARGETS tpm2
    EXPORT tpm2Targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES
    ${PROJECT_SOURCE_DIR}/include/tpm2.h
    ${PROJECT_SOURCE_DIR}/include/tpm2_chip.h
    ${PROJECT_SOURCE_DIR}/include/transport/spi.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tpm2
)

# Export targets file
install(EXPORT tpm2Targets
    FILE tpm2Targets.cmake
    NAMESPACE tpm2::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tpm2
)

# Generate Config and Version files
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/tpm2ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    ${PROJECT_SOURCE_DIR}/tpm2Config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/tpm2Config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tpm2
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/tpm2Config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/tpm2ConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tpm2
)
