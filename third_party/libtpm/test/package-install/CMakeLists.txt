cmake_minimum_required(VERSION 3.10)
project(tpm2_verify LANGUAGES C)

SET(INSTALL_PREFIX "/tmp/install/dir" CACHE STRING "Install directory.")

# Point CMake to your installed package
set(CMAKE_INSTALL_PREFIX "${INSTALL_PREFIX}")

find_package(tpm2 REQUIRED)

add_library(test_integration main.c)
target_link_libraries(test_integration PRIVATE tpm2::tpm2)
