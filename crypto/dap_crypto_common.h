#ifndef __CRYPTO_COMMON_H__
#define __CRYPTO_COMMON_H__


// For C++
#ifdef __cplusplus
extern "C" {
#endif


#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "rand/dap_rand.h"
#include "sha3/fips202.h"

// Definition of operating system

#define OS_WIN       1
#define OS_LINUX     2
#define OS_MACOS     3

#if defined(_WIN32)        // Microsoft Windows OS
    #define OS_TARGET OS_WIN
#elif defined(__linux__)        // Linux OS
    #define OS_TARGET OS_LINUX
#elif defined(__APPLE__)         // MACOS
    #define OS_TARGET OS_MACOS
#else
    #error -- "Unsupported OS"
#endif


// Definition of compiler

#define COMPILER_VC      1
#define COMPILER_GCC     2
#define COMPILER_CLANG   3

#if defined(_MSC_VER)           // Microsoft Visual C compiler
    #define COMPILER COMPILER_VC
#elif defined(__GNUC__)         // GNU GCC compiler
    #define COMPILER COMPILER_GCC
#elif defined(__clang__)        // Clang compiler
    #define COMPILER COMPILER_CLANG
#else
    #error -- "Unsupported COMPILER"
#endif


// Definition of the targeted architecture and basic data types
#define TARGET_AMD64        1
#define TARGET_x86          2
#define TARGET_ARM          3
#define TARGET_ARM64        4

#if (defined(__x86_64__) || defined(__x86_64) || defined(__arch64__) || defined(_M_AMD64) || defined(_M_X64) || defined(_WIN64) || !defined(__LP64__))
    #define _AMD64_
#elif (defined(__aarch64__))
    #define _ARM64_
#else
    #define _X86_
#endif

#if defined(_AMD64_)
    #define TARGET TARGET_AMD64
    #define RADIX           64
    #define LOG2RADIX       6
    typedef uint64_t        digit_t;  // Unsigned 64-bit digit
    typedef int64_t         sdigit_t;  // Signed 64-bit digit
    typedef uint32_t        hdigit_t; // Unsigned 32-bit digit
    #define NWORDS_FIELD    12    // Number of words of a 751-bit field element
    #define p751_ZERO_WORDS 5  // Number of "0" digits in the least significant part of p751 + 1
#elif defined(_X86_)
    #define TARGET TARGET_x86
    #define RADIX           32
    #define LOG2RADIX       5
    typedef uint32_t        digit_t;        // Unsigned 32-bit digit
    typedef int32_t         sdigit_t;       // Signed 32-bit digit
    typedef uint16_t        hdigit_t; // Unsigned 16-bit digit
    #define NWORDS_FIELD    24
    #define p751_ZERO_WORDS 11
#elif defined(_ARM_)
    #define TARGET TARGET_ARM
    #define RADIX           32
    #define LOG2RADIX       5
    typedef uint32_t        digit_t;        // Unsigned 32-bit digit
    typedef int32_t         sdigit_t;       // Signed 32-bit digit
    typedef uint16_t        hdigit_t; // Unsigned 16-bit digit
    #define NWORDS_FIELD    24
    #define p751_ZERO_WORDS 11
#elif defined(_ARM64_)
    #define TARGET TARGET_ARM64
    #define RADIX           64
    #define LOG2RADIX       6
    typedef uint64_t        digit_t;        // Unsigned 64-bit digit
    typedef int64_t         sdigit_t;       // Signed 64-bit digit
    typedef uint32_t        hdigit_t;
    #define NWORDS_FIELD    12
    #define p751_ZERO_WORDS 5
#else
    #error -- "Unsupported ARCHITECTURE"
#endif

#define RADIX64

// Instruction support

#define NO_SIMD_SUPPORT 0
#define AVX_SUPPORT     1
#define AVX2_SUPPORT    2

#if defined(__AVX2__)
    #define SIMD_SUPPORT AVX2_SUPPORT       // AVX2 support selection
#elif defined(__AVX__)
    #define SIMD_SUPPORT AVX_SUPPORT        // AVX support selection
#else
    #define SIMD_SUPPORT NO_SIMD_SUPPORT
#endif

#if defined(__ASM__)                          // Assembly support selection
    #define ASM_SUPPORT
#endif

#if (SIMD_SUPPORT == NO_SIMD_SUPPORT)                      // Selection of generic, portable implementation
    #define GENERIC_IMPLEMENTATION
#endif

// Unsupported configurations

#if defined(ASM_SUPPORT) && (OS_TARGET == OS_WIN)
    #error -- "Assembly is not supported on this platform"
#endif

#if defined(ASM_SUPPORT) && defined(GENERIC_IMPLEMENTATION)
    #error -- "Unsupported configuration"
#endif

#if (SIMD_SUPPORT != NO_SIMD_SUPPORT) && defined(GENERIC_IMPLEMENTATION)
    #error -- "Unsupported configuration"
#endif

#if (TARGET != TARGET_AMD64) && !defined(GENERIC_IMPLEMENTATION)
    #error -- "Unsupported configuration"
#endif

#if (OS_TARGET == OS_LINUX) && defined(ASM_SUPPORT) && (SIMD_SUPPORT != AVX2_SUPPORT)
    #error -- "Unsupported configuration"
#endif


// Definitions of the error-handling type and error codes

/*typedef enum {
    CRYPTO_MSRLN_SUCCESS,                          // 0x00
    CRYPTO_MSRLN_ERROR,                            // 0x01
    CRYPTO_MSRLN_ERROR_DURING_TEST,                // 0x02
    CRYPTO_MSRLN_ERROR_UNKNOWN,                    // 0x03
    CRYPTO_MSRLN_ERROR_NOT_IMPLEMENTED,            // 0x04
    CRYPTO_MSRLN_ERROR_NO_MEMORY,                  // 0x05
    CRYPTO_MSRLN_ERROR_INVALID_PARAMETER,          // 0x06
    CRYPTO_MSRLN_ERROR_SHARED_KEY,                 // 0x07
    CRYPTO_MSRLN_ERROR_TOO_MANY_ITERATIONS,        // 0x08
    CRYPTO_MSRLN_ERROR_END_OF_LIST
} CRYPTO_MSRLN_STATUS;

#define CRYPTO_STATUS_TYPE_SIZE (CRYPTO_ERROR_END_OF_LIST)


// Definitions of the error messages
// NOTE: they must match the error codes above

#define CRYPTO_MSG_SUCCESS                                "CRYPTO_SUCCESS"
#define CRYPTO_MSG_ERROR                                  "CRYPTO_ERROR"
#define CRYPTO_MSG_ERROR_DURING_TEST                      "CRYPTO_ERROR_DURING_TEST"
#define CRYPTO_MSG_ERROR_UNKNOWN                          "CRYPTO_ERROR_UNKNOWN"
#define CRYPTO_MSG_ERROR_NOT_IMPLEMENTED                  "CRYPTO_ERROR_NOT_IMPLEMENTED"
#define CRYPTO_MSG_ERROR_NO_MEMORY                        "CRYPTO_ERROR_NO_MEMORY"
#define CRYPTO_MSG_ERROR_INVALID_PARAMETER                "CRYPTO_ERROR_INVALID_PARAMETER"
#define CRYPTO_MSG_ERROR_SHARED_KEY                       "CRYPTO_ERROR_SHARED_KEY"
#define CRYPTO_MSG_ERROR_TOO_MANY_ITERATIONS              "CRYPTO_ERROR_TOO_MANY_ITERATIONS"
*/

#ifdef __cplusplus
}
#endif


#endif
