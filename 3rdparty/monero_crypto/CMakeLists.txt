# Copyright (c) 2014-2017, The Monero Project
# Copyright (c) 2018, DapCash Project
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

project (monero_crypto)

# ARCH defines the target architecture, either by an explicit identifier or
# one of the following two keywords. By default, ARCH a value of 'native':
# target arch = host arch, binary is not portable. When ARCH is set to the
# string 'default', no -march arg is passed, which creates a binary that is
# portable across processors in the same family as host processor.  In cases
# when ARCH is not set to an explicit identifier, cmake's builtin is used
# to identify the target architecture, to direct logic in this cmake script.
# Since ARCH is a cached variable, it will not be set on first cmake invocation.
set(STATIC 1)

if (NOT ARCH OR ARCH STREQUAL "" OR ARCH STREQUAL "native" OR ARCH STREQUAL "default")
  set(ARCH_ID "${CMAKE_SYSTEM_PROCESSOR}")
else()
  set(ARCH_ID "${ARCH}")
endif()
string(TOLOWER "${ARCH_ID}" ARM_ID)
string(SUBSTRING "${ARM_ID}" 0 3 ARM_TEST)
if (ARM_TEST STREQUAL "arm")
  set(ARM 1)
  string(SUBSTRING "${ARM_ID}" 0 5 ARM_TEST)
  if (ARM_TEST STREQUAL "armv6")
    set(ARM6 1)
  endif()
  if (ARM_TEST STREQUAL "armv7")
    set(ARM7 1)
  endif()
endif()

if (ARM_ID STREQUAL "aarch64" OR ARM_ID STREQUAL "arm64" OR ARM_ID STREQUAL "armv8-a")
  set(ARM 1)
  set(ARM8 1)
  set(ARCH "armv8-a")
endif()

if(ARCH_ID STREQUAL "ppc64le")
  set(PPC64LE 1)
endif()

if(WIN32 OR ARM)
  set(OPT_FLAGS_RELEASE "-O2")
else()
  set(OPT_FLAGS_RELEASE "-Ofast")
endif()


# Check if we're on FreeBSD so we can exclude the local miniupnpc (it should be installed from ports instead)
# CMAKE_SYSTEM_NAME checks are commonly known, but specifically taken from libsdl's CMakeLists
if(CMAKE_SYSTEM_NAME MATCHES "kFreeBSD.*|FreeBSD")
  set(FREEBSD TRUE)
endif()

# Check if we're on DragonFly BSD. See the README.md for build instructions.
if(CMAKE_SYSTEM_NAME MATCHES "DragonFly.*")
  set(DRAGONFLY TRUE)
endif()

# Check if we're on OpenBSD. See the README.md for build instructions.
if(CMAKE_SYSTEM_NAME MATCHES "kOpenBSD.*|OpenBSD.*")
  set(OPENBSD TRUE)
endif()

if(APPLE)
  include_directories(SYSTEM /usr/include/malloc)
  if(POLICY CMP0042)
    cmake_policy(SET CMP0042 NEW)
  endif()
endif()

if(MSVC)
  add_definitions("/bigobj /MP /W3 /GS- /D_CRT_SECURE_NO_WARNINGS /wd4996 /wd4345 /D_WIN32_WINNT=0x0600 /DWIN32_LEAN_AND_MEAN /DGTEST_HAS_TR1_TUPLE=0 /FIinline_c.h /D__SSE4_1__")
  # set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Dinline=__inline")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /STACK:10485760")
  foreach(VAR CMAKE_C_FLAGS_DEBUG CMAKE_CXX_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE CMAKE_CXX_FLAGS_RELEASE)
    string(REPLACE "/MD" "/MT" ${VAR} "${${VAR}}")
  endforeach()
  include_directories(SYSTEM src/platform/msc)
else()
    set(ARCH native CACHE STRING "CPU to build for: -march value or 'default' to not pass -march at all")
    message(STATUS "[*] Building on ${CMAKE_SYSTEM_PROCESSOR} for ${ARCH}")
    if(ARCH STREQUAL "default")
      set(ARCH_FLAG "")
    elseif(ARCH STREQUAL "native")
      set(ARCH_FLAG "")
    elseif(PPC64LE)
      set(ARCH_FLAG "-mcpu=${ARCH}")
    elseif(IOS AND ARCH STREQUAL "arm64")
      message(STATUS "IOS: Changing arch from arm64 to armv8")
      set(ARCH_FLAG "-march=armv8")
    else()
      set(ARCH_FLAG "-march=${ARCH}")
    endif()
    set(WARNINGS "-Wall -Wextra -Wpointer-arith -Wundef -Wvla -Wwrite-strings -Wno-error=extra -Wno-error=deprecated-declarations -Wno-unused-parameter -Wno-unused-variable -Wno-error=unused-variable -Wno-error=undef -Wno-error=uninitialized")
    if(NOT MINGW)
      set(WARNINGS_AS_ERRORS_FLAG "-Werror")
    endif()
    if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
      if(ARM)
        set(WARNINGS "${WARNINGS} -Wno-error=inline-asm")
      endif()
    else()
      set(WARNINGS "${WARNINGS} -Wlogical-op -Wno-error=maybe-uninitialized -Wno-error=cpp")
    endif()
    if(MINGW)
        set(WARNINGS "${WARNINGS} -Wno-error=unused-value -Wno-error=unused-but-set-variable")
        set(MINGW_FLAG "${MINGW_FLAG} -DWIN32_LEAN_AND_MEAN")
        set(Boost_THREADAPI win32)
        include_directories(SYSTEM src/platform/mingw)
        # mingw doesn't support LTO (multiple definition errors at link time)
        set(USE_LTO_DEFAULT false)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--stack,10485760")
        if(NOT BUILD_64)
          add_definitions(-DWINVER=0x0501 -D_WIN32_WINNT=0x0501)
        endif()
      endif()
      set(C_WARNINGS "-Waggregate-return -Wnested-externs -Wold-style-definition -Wstrict-prototypes")
      set(CXX_WARNINGS "-Wno-reorder -Wno-missing-field-initializers")

      if(COVERAGE)
        message(STATUS "Building with profiling for test coverage report")
        set(COVERAGE_FLAGS "-fprofile-arcs -ftest-coverage --coverage")
      endif()

      # With GCC 6.1.1 the compiled binary malfunctions due to aliasing. Until that
      # is fixed in the code (Issue #847), force compiler to be conservative.
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-strict-aliasing")
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-strict-aliasing")

      option(NO_AES "[!] Explicitly disable AES support" ${NO_AES})

      if(NO_AES)
        message(STATUS "[!] AES support explicitly disabled")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNO_AES")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNO_AES")
      elseif(NOT ARM AND NOT PPC64LE)
        message(STATUS "[ ] AES support enabled")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -maes")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")
      elseif(PPC64LE)
        message(STATUS "[!] AES support not available on ppc64le")
      elseif(ARM6)
        message(STATUS "[!] AES support not available on ARMv6")
      elseif(ARM7)
        message(STATUS "[!] AES support not available on ARMv7")
      elseif(ARM8 AND NOT ANDROID)
        #CHECK_CXX_ACCEPTS_FLAG("-march=${ARCH}+crypto" ARCH_PLUS_CRYPTO)
        if(ARCH_PLUS_CRYPTO)
          message(STATUS "[*] Crypto extensions enabled for ARMv8")
          set(ARCH_FLAG "-march=${ARCH}+crypto")
        else()
          message(STATUS "[!] Crypto extensions unavailable on your ARMv8 device")
        endif()
      else()
        message(STATUS "[!] AES support disabled")
      endif()
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -D_GNU_SOURCE ${MINGW_FLAG} ${STATIC_ASSERT_FLAG} ${WARNINGS} ${C_WARNINGS} ${ARCH_FLAG} ${COVERAGE_FLAGS} ${PIC_FLAG}")
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -D_GNU_SOURCE ${MINGW_FLAG} ${STATIC_ASSERT_CPP_FLAG} ${WARNINGS} ${CXX_WARNINGS} ${ARCH_FLAG} ${COVERAGE_FLAGS} ${PIC_FLAG}")

      # With GCC 6.1.1 the compiled binary malfunctions due to aliasing. Until that
      # is fixed in the code (Issue #847), force compiler to be conservative.
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-strict-aliasing")
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-strict-aliasing")
      if(ARM)
        message(STATUS "[ ] Setting FPU Flags for ARM Processors")

        #NB NEON hardware does not fully implement the IEEE 754 standard for floating-point arithmetic
        #Need custom assembly code to take full advantage of NEON SIMD

        #Cortex-A5/9  -mfpu=neon-fp16
        #Cortex-A7/15 -mfpu=neon-vfpv4
        #Cortex-A8    -mfpu=neon
        #ARMv8        -FP and SIMD on by default for all ARM8v-A series, NO -mfpu setting needed

        #For custom -mtune, processor IDs for ARMv8-A series:
        #0xd04 - Cortex-A35
        #0xd07 - Cortex-A57
        #0xd08 - Cortex-A72
        #0xd03 - Cortex-A73

        if(NOT ARM8 AND NOT ANDROID)
          CHECK_CXX_ACCEPTS_FLAG(-mfpu=vfp3-d16 CXX_ACCEPTS_VFP3_D16)
          CHECK_CXX_ACCEPTS_FLAG(-mfpu=vfp4 CXX_ACCEPTS_VFP4)
          CHECK_CXX_ACCEPTS_FLAG(-mfloat-abi=hard CXX_ACCEPTS_MFLOAT_HARD)
          CHECK_CXX_ACCEPTS_FLAG(-mfloat-abi=softfp CXX_ACCEPTS_MFLOAT_SOFTFP)
        endif()

        if(ARM8)
          #CHECK_CXX_ACCEPTS_FLAG(-mfix-cortex-a53-835769 CXX_ACCEPTS_MFIX_CORTEX_A53_835769)
          #CHECK_CXX_ACCEPTS_FLAG(-mfix-cortex-a53-843419 CXX_ACCEPTS_MFIX_CORTEX_A53_843419)
        endif()

        if(ARM6)
          message(STATUS "[ ] Selecting VFP for ARMv6")
          set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpu=vfp")
          set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfpu=vfp")
        endif(ARM6)
        if(ARM7)
          if(CXX_ACCEPTS_VFP3_D16 AND NOT CXX_ACCEPTS_VFP4)
            message(STATUS "[ ] Selecting VFP3 for ARMv7")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpu=vfp3-d16")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfpu=vfp3-d16")
          endif()

          if(CXX_ACCEPTS_VFP4)
            message(STATUS "[ ] Selecting VFP4 for ARMv7")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfpu=vfp4")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfpu=vfp4")
          endif()

          if(CXX_ACCEPTS_MFLOAT_HARD)
            message(STATUS "[ ] Setting Hardware ABI for Floating Point")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfloat-abi=hard")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfloat-abi=hard")
          endif()

          if(CXX_ACCEPTS_MFLOAT_SOFTFP AND NOT CXX_ACCEPTS_MFLOAT_HARD)
            message(STATUS "[ ] Setting Software ABI for Floating Point")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfloat-abi=softfp")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfloat-abi=softfp")
          endif()
        endif(ARM7)
        if(ARM8)
           if(CXX_ACCEPTS_MFIX_CORTEX_A53_835769)
             message(STATUS "[ ] Enabling Cortex-A53 workaround 835769")
             set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfix-cortex-a53-835769")
             set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfix-cortex-a53-835769")
           endif()

           if(CXX_ACCEPTS_MFIX_CORTEX_A53_843419)
             message(STATUS "[ ] Enabling Cortex-A53 workaround 843419")
             set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfix-cortex-a53-843419")
             set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mfix-cortex-a53-843419")
           endif()
         endif(ARM8)

       endif(ARM)
       if(ANDROID AND NOT BUILD_GUI_DEPS STREQUAL "ON" OR IOS)
         #From Android 5: "only position independent executables (PIE) are supported"
         message(STATUS "[ ] Enabling PIE executable")
         set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
         set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE")
         set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_CXX_FLAGS} -fPIE -pie")
       endif()

       if(APPLE)
         set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DGTEST_HAS_TR1_TUPLE=0")
       endif()

       set(DEBUG_FLAGS "-g3")
       if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND NOT (CMAKE_C_COMPILER_VERSION VERSION_LESS 4.8))
         set(DEBUG_FLAGS "${DEBUG_FLAGS} -Og ")
       else()
         set(DEBUG_FLAGS "${DEBUG_FLAGS} -O0 ")
       endif()

       if(NOT DEFINED USE_LTO_DEFAULT)
         set(USE_LTO_DEFAULT false)
       endif()
       set(USE_LTO ${USE_LTO_DEFAULT} CACHE BOOL "Use Link-Time Optimization (Release mode only)")

       if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
         # There is a clang bug that does not allow to compile code that uses AES-NI intrinsics if -flto is enabled, so explicitly disable
         set(USE_LTO false)
       endif()
       if(USE_LTO)
         set(RELEASE_FLAGS "${RELEASE_FLAGS} -flto")
         if(STATIC)
           set(RELEASE_FLAGS "${RELEASE_FLAGS} -ffat-lto-objects")
         endif()
         # Since gcc 4.9 the LTO format is non-standard (slim), so we need the gcc-specific ar and ranlib binaries
         if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND NOT (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.9.0) AND NOT OPENBSD AND NOT DRAGONFLY)
           # When invoking cmake on distributions on which gcc's binaries are prefixed
           # with an arch-specific triplet, the user must specify -DCHOST=<prefix>
           if (DEFINED CHOST)
             set(CMAKE_AR "${CHOST}-gcc-ar")
             set(CMAKE_RANLIB "${CHOST}-gcc-ranlib")
           else()
             set(CMAKE_AR "gcc-ar")
             set(CMAKE_RANLIB "gcc-ranlib")
           endif()
         endif()
       endif()

       set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${DEBUG_FLAGS}")
       set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${DEBUG_FLAGS}")
       set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${RELEASE_FLAGS}")
       set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${RELEASE_FLAGS}")
endif()





set(monero_crypto_sources
  aesb.c
  blake256.c
  chacha8.c
  crypto-ops-data.c
  crypto-ops.c
  groestl.c
  hash-extra-blake.c
  hash-extra-groestl.c
  hash-extra-jh.c
  hash-extra-skein.c
  hash.c
  jh.c
  keccak.c
  oaes_lib.c
  random.c
  skein.c
  slow-hash.c
  tree-hash.c)

set(monero_crypto_headers)

set(monero_crypto_private_headers
  blake256.h
  chacha8.h
  crypto-ops.h
  crypto.h
  generic-ops.h
  groestl.h
  groestl_tables.h
  hash-ops.h
  hash.h
  initializer.h
  jh.h
  keccak.h
  oaes_config.h
  oaes_lib.h
  random.h
  skein.h
  skein_port.h)



if (ARM)
  option(NO_OPTIMIZED_MULTIPLY_ON_ARM
	   "Compute multiply using generic C implementation instead of ARM ASM" OFF)
  if(NO_OPTIMIZED_MULTIPLY_ON_ARM)
    message(STATUS "[ ] Using generic C implementation for multiply")
    set_property(SOURCE slow-hash.c
      PROPERTY COMPILE_DEFINITIONS "NO_OPTIMIZED_MULTIPLY_ON_ARM")
  endif()
endif()

# Because of the way Qt works on android with JNI, the code does not live in the main android thread
# So this code runs with a 1 MB default stack size. 
# This will force the use of the heap for the allocation of the scratchpad
if (ANDROID OR IOS)
  if( BUILD_GUI_DEPS )
    add_definitions(-DFORCE_USE_HEAP=1)
  endif()
endif()


add_library(${PROJECT_NAME} STATIC ${monero_crypto_sources})
target_include_directories(monero_crypto INTERFACE .)


set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)

