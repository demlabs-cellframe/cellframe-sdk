# MIT License
#
# Copyright (c) 2015-2021 The ViaDuck Project
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

cmake_minimum_required(VERSION 3.2)
project(openssl-cmake)

if (POLICY CMP0135)
    # policy CMP0135 will use OLD behavior for consistency
    cmake_policy(SET CMP0135 OLD)
endif()

set(BUILD_OPENSSL ON CACHE BOOL "Automated OpenSSL building")
set(OPENSSL_INSTALL_MAN OFF CACHE STRING "Install man pages?")
set(OPENSSL_MODULES "" CACHE STRING "OpenSSL configure options")
set(CROSS_ANDROID OFF CACHE BOOL "Cross-compiling for Android?")
set(CROSS OFF CACHE BOOL "Cross-compiling?")
set(CROSS_TARGET OFF CACHE STRING "Cross-compilation target")

# allow including our modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

# mimic system ssl and crypto targets
add_library(ssl INTERFACE)
add_library(crypto INTERFACE)


# build our own or use prebuilts

# set up fake targets
add_library(ssl_lib STATIC IMPORTED GLOBAL)
add_library(crypto_lib STATIC IMPORTED GLOBAL)

target_link_libraries(ssl INTERFACE ssl_lib)
target_link_libraries(crypto INTERFACE crypto_lib)

# set up prefix
if (BUILD_OPENSSL)
    set(OPENSSL_PREFIX ${CMAKE_CURRENT_BINARY_DIR})
else()
    set(OPENSSL_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/openssl-prefix/src/openssl)
endif()

set(OPENSSL_LIBSSL_PATH ${OPENSSL_PREFIX}/usr/local/lib/libssl.a)
set(OPENSSL_LIBCRYPTO_PATH ${OPENSSL_PREFIX}/usr/local/lib/libcrypto.a)

# set up openssl target

include(BuildOpenSSL)

# set import locations
set_target_properties(ssl_lib PROPERTIES IMPORTED_LOCATION ${OPENSSL_LIBSSL_PATH})
set_target_properties(crypto_lib PROPERTIES IMPORTED_LOCATION ${OPENSSL_LIBCRYPTO_PATH})

# set include locations
target_include_directories(ssl BEFORE INTERFACE $<BUILD_INTERFACE:${OPENSSL_PREFIX}/usr/local/include>)
target_include_directories(crypto BEFORE INTERFACE $<BUILD_INTERFACE:${OPENSSL_PREFIX}/usr/local/include>)

# add fake targets to common target
add_dependencies(ssl_lib openssl)
add_dependencies(crypto_lib openssl)
