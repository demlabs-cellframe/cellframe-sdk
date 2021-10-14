project(cellframe-crypto-unit_test C)

cmake_minimum_required(VERSION 3.1)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_COLOR_MAKEFILE   ON)
set(CMAKE_C_STANDARD 11)

# Predefine project
SET( CPACK_PACKAGE_NAME  "${PROJECT_NAME}")
SET( CPACK_PACKAGE_VERSION_MAJOR 4)
SET( CPACK_PACKAGE_VERSION_MINOR 4)
SET( CPACK_PACKAGE_VERSION_PATCH 52)

# init CellFrame SDK
# add_definitions("-DDAP_VERSION=\"${CPACK_PACKAGE_VERSION_MAJOR}-${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}\"")
# set(SUBMODULES_NO_BUILD ON)
# include (cellframe-sdk/cmake/OS_Detection.cmake)

add_definitions("-DDAP_VERSION=\"${CPACK_PACKAGE_VERSION_MAJOR}\"")
set(SUBMODULES_NO_BUILD OFF)
set(SUPPORT_PYTHON_PLUGINS OFF)

file(GLOB PRJ_HEADERS /*.h)
file(GLOB SUB_SOURCES /*.c)
add_executable(${PROJECT_NAME} "main.c"
    "bytes_to_words.c"
    "threefish.c"
    "threefish.h"
    "testtf.c"
    ${PRJ_HEADERS})

set(CMAKE_BUILD_TYPE Debug)
