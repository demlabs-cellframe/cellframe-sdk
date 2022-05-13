/*
 * Copyright 2015-2022 Leonid Yuriev <leo@yuriev.ru>
 * and other libmdbx authors: please see AUTHORS file.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#pragma once
/* *INDENT-OFF* */
/* clang-format off */

#ifndef __GNUC_PREREQ
#   if defined(__GNUC__) && defined(__GNUC_MINOR__)
#       define __GNUC_PREREQ(maj, min) \
          ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#   else
#       define __GNUC_PREREQ(maj, min) (0)
#   endif
#endif /* __GNUC_PREREQ */

#ifndef __CLANG_PREREQ
#   ifdef __clang__
#       define __CLANG_PREREQ(maj,min) \
          ((__clang_major__ << 16) + __clang_minor__ >= ((maj) << 16) + (min))
#   else
#       define __CLANG_PREREQ(maj,min) (0)
#   endif
#endif /* __CLANG_PREREQ */

#ifndef __GLIBC_PREREQ
#   if defined(__GLIBC__) && defined(__GLIBC_MINOR__)
#       define __GLIBC_PREREQ(maj, min) \
          ((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min))
#   else
#       define __GLIBC_PREREQ(maj, min) (0)
#   endif
#endif /* __GLIBC_PREREQ */

#ifndef __has_warning
#   define __has_warning(x) (0)
#endif

#ifndef __has_include
#   define __has_include(x) (0)
#endif

#if __has_feature(thread_sanitizer)
#   define __SANITIZE_THREAD__ 1
#endif

#if __has_feature(address_sanitizer)
#   define __SANITIZE_ADDRESS__ 1
#endif

/*----------------------------------------------------------------------------*/

#ifndef __extern_C
#   ifdef __cplusplus
#       define __extern_C extern "C"
#   else
#       define __extern_C
#   endif
#endif /* __extern_C */

#if !defined(nullptr) && !defined(__cplusplus) || (__cplusplus < 201103L && !defined(_MSC_VER))
#   define nullptr NULL
#endif

/*----------------------------------------------------------------------------*/

#ifndef __always_inline
#   if defined(__GNUC__) || __has_attribute(__always_inline__)
#       define __always_inline __inline __attribute__((__always_inline__))
#   elif defined(_MSC_VER)
#       define __always_inline __forceinline
#   else
#       define __always_inline
#   endif
#endif /* __always_inline */

#ifndef __noinline
#   if defined(__GNUC__) || __has_attribute(__noinline__)
#       define __noinline __attribute__((__noinline__))
#   elif defined(_MSC_VER)
#       define __noinline __declspec(noinline)
#   else
#       define __noinline
#   endif
#endif /* __noinline */

#ifndef __must_check_result
#   if defined(__GNUC__) || __has_attribute(__warn_unused_result__)
#       define __must_check_result __attribute__((__warn_unused_result__))
#   else
#       define __must_check_result
#   endif
#endif /* __must_check_result */

#if !defined(__noop) && !defined(_MSC_VER)
#   define __noop(...) do {} while(0)
#endif /* __noop */

#if defined(__fallthrough) &&                                                  \
    (defined(__MINGW__) || defined(__MINGW32__) || defined(__MINGW64__))
#undef __fallthrough
#endif /* __fallthrough workaround for MinGW */

#ifndef __fallthrough
#  if defined(__cplusplus) && (__has_cpp_attribute(fallthrough) &&             \
     (!defined(__clang__) || __clang__ > 4)) || __cplusplus >= 201703L
#    define __fallthrough [[fallthrough]]
#  elif __GNUC_PREREQ(8, 0) && defined(__cplusplus) && __cplusplus >= 201103L
#    define __fallthrough [[fallthrough]]
#  elif __GNUC_PREREQ(7, 0) &&                                                 \
    (!defined(__LCC__) || (__LCC__ == 124 && __LCC_MINOR__ >= 12) ||           \
     (__LCC__ == 125 && __LCC_MINOR__ >= 5) || (__LCC__ >= 126))
#    define __fallthrough __attribute__((__fallthrough__))
#  elif defined(__clang__) && defined(__cplusplus) && __cplusplus >= 201103L &&\
    __has_feature(cxx_attributes) && __has_warning("-Wimplicit-fallthrough")
#    define __fallthrough [[clang::fallthrough]]
#  else
#    define __fallthrough
#  endif
#endif /* __fallthrough */

#ifndef __unreachable
#   if __GNUC_PREREQ(4,5) || __has_builtin(__builtin_unreachable)
#       define __unreachable() __builtin_unreachable()
#   elif defined(_MSC_VER)
#       define __unreachable() __assume(0)
#   else
#       define __unreachable() __noop()
#   endif
#endif /* __unreachable */

#ifndef __prefetch
#   if defined(__GNUC__) || defined(__clang__) || __has_builtin(__builtin_prefetch)
#       define __prefetch(ptr) __builtin_prefetch(ptr)
#   else
#       define __prefetch(ptr) __noop(ptr)
#   endif
#endif /* __prefetch */

#ifndef __nothrow
#   if defined(__cplusplus)
#       if __cplusplus < 201703L
#           define __nothrow throw()
#       else
#           define __nothrow noexcept(true)
#       endif /* __cplusplus */
#   elif defined(__GNUC__) || __has_attribute(__nothrow__)
#       define __nothrow __attribute__((__nothrow__))
#   elif defined(_MSC_VER) && defined(__cplusplus)
#       define __nothrow __declspec(nothrow)
#   else
#       define __nothrow
#   endif
#endif /* __nothrow */

#ifndef __hidden
#   if defined(__GNUC__) || __has_attribute(__visibility__)
#       define __hidden __attribute__((__visibility__("hidden")))
#   else
#       define __hidden
#   endif
#endif /* __hidden */

#ifndef __optimize
#   if defined(__OPTIMIZE__)
#       if (defined(__GNUC__) && !defined(__clang__)) || __has_attribute(__optimize__)
#           define __optimize(ops) __attribute__((__optimize__(ops)))
#       else
#           define __optimize(ops)
#       endif
#   else
#       define __optimize(ops)
#   endif
#endif /* __optimize */

#ifndef __hot
#   if defined(__OPTIMIZE__)
#       if defined(__e2k__)
#           define __hot __attribute__((__hot__)) __optimize(3)
#       elif defined(__clang__) && !__has_attribute(__hot_) \
        && __has_attribute(__section__) && (defined(__linux__) || defined(__gnu_linux__))
            /* just put frequently used functions in separate section */
#           define __hot __attribute__((__section__("text.hot"))) __optimize("O3")
#       elif defined(__GNUC__) || __has_attribute(__hot__)
#           define __hot __attribute__((__hot__)) __optimize("O3")
#       else
#           define __hot __optimize("O3")
#       endif
#   else
#       define __hot
#   endif
#endif /* __hot */

#ifndef __cold
#   if defined(__OPTIMIZE__)
#       if defined(__e2k__)
#           define __cold __attribute__((__cold__)) __optimize(1)
#       elif defined(__clang__) && !__has_attribute(cold) \
        && __has_attribute(__section__) && (defined(__linux__) || defined(__gnu_linux__))
            /* just put infrequently used functions in separate section */
#           define __cold __attribute__((__section__("text.unlikely"))) __optimize("Os")
#       elif defined(__GNUC__) || __has_attribute(cold)
#           define __cold __attribute__((__cold__)) __optimize("Os")
#       else
#           define __cold __optimize("Os")
#       endif
#   else
#       define __cold
#   endif
#endif /* __cold */

#ifndef __flatten
#   if defined(__OPTIMIZE__) && (defined(__GNUC__) || __has_attribute(__flatten__))
#       define __flatten __attribute__((__flatten__))
#   else
#       define __flatten
#   endif
#endif /* __flatten */

#ifndef likely
#   if (defined(__GNUC__) || __has_builtin(__builtin_expect)) && !defined(__COVERITY__)
#       define likely(cond) __builtin_expect(!!(cond), 1)
#   else
#       define likely(x) (!!(x))
#   endif
#endif /* likely */

#ifndef unlikely
#   if (defined(__GNUC__) || __has_builtin(__builtin_expect)) && !defined(__COVERITY__)
#       define unlikely(cond) __builtin_expect(!!(cond), 0)
#   else
#       define unlikely(x) (!!(x))
#   endif
#endif /* unlikely */

#ifndef __anonymous_struct_extension__
#   if defined(__GNUC__)
#       define __anonymous_struct_extension__ __extension__
#   else
#       define __anonymous_struct_extension__
#   endif
#endif /* __anonymous_struct_extension__ */

#ifndef __Wpedantic_format_voidptr
    MDBX_MAYBE_UNUSED MDBX_PURE_FUNCTION static __inline  const void*
        __Wpedantic_format_voidptr(const void* ptr) {return ptr;}
#   define __Wpedantic_format_voidptr(ARG) __Wpedantic_format_voidptr(ARG)
#endif /* __Wpedantic_format_voidptr */

/*----------------------------------------------------------------------------*/

#if defined(MDBX_USE_VALGRIND)
#   include <valgrind/memcheck.h>
#   ifndef VALGRIND_DISABLE_ADDR_ERROR_REPORTING_IN_RANGE
        /* LY: available since Valgrind 3.10 */
#       define VALGRIND_DISABLE_ADDR_ERROR_REPORTING_IN_RANGE(a,s)
#       define VALGRIND_ENABLE_ADDR_ERROR_REPORTING_IN_RANGE(a,s)
#   endif
#elif !defined(RUNNING_ON_VALGRIND)
#   define VALGRIND_CREATE_MEMPOOL(h,r,z)
#   define VALGRIND_DESTROY_MEMPOOL(h)
#   define VALGRIND_MEMPOOL_TRIM(h,a,s)
#   define VALGRIND_MEMPOOL_ALLOC(h,a,s)
#   define VALGRIND_MEMPOOL_FREE(h,a)
#   define VALGRIND_MEMPOOL_CHANGE(h,a,b,s)
#   define VALGRIND_MAKE_MEM_NOACCESS(a,s)
#   define VALGRIND_MAKE_MEM_DEFINED(a,s)
#   define VALGRIND_MAKE_MEM_UNDEFINED(a,s)
#   define VALGRIND_DISABLE_ADDR_ERROR_REPORTING_IN_RANGE(a,s)
#   define VALGRIND_ENABLE_ADDR_ERROR_REPORTING_IN_RANGE(a,s)
#   define VALGRIND_CHECK_MEM_IS_ADDRESSABLE(a,s) (0)
#   define VALGRIND_CHECK_MEM_IS_DEFINED(a,s) (0)
#   define RUNNING_ON_VALGRIND (0)
#endif /* MDBX_USE_VALGRIND */

#ifdef __SANITIZE_ADDRESS__
#   include <sanitizer/asan_interface.h>
#elif !defined(ASAN_POISON_MEMORY_REGION)
#   define ASAN_POISON_MEMORY_REGION(addr, size) \
        ((void)(addr), (void)(size))
#   define ASAN_UNPOISON_MEMORY_REGION(addr, size) \
        ((void)(addr), (void)(size))
#endif /* __SANITIZE_ADDRESS__ */

/*----------------------------------------------------------------------------*/

#ifndef ARRAY_LENGTH
#   ifdef __cplusplus
        template <typename T, size_t N>
        char (&__ArraySizeHelper(T (&array)[N]))[N];
#       define ARRAY_LENGTH(array) (sizeof(::__ArraySizeHelper(array)))
#   else
#       define ARRAY_LENGTH(array) (sizeof(array) / sizeof(array[0]))
#   endif
#endif /* ARRAY_LENGTH */

#ifndef ARRAY_END
#   define ARRAY_END(array) (&array[ARRAY_LENGTH(array)])
#endif /* ARRAY_END */

#define CONCAT(a,b) a##b
#define XCONCAT(a,b) CONCAT(a,b)

#ifndef offsetof
#   define offsetof(type, member)  __builtin_offsetof(type, member)
#endif /* offsetof */

#ifndef container_of
#   define container_of(ptr, type, member) \
        ((type *)((char *)(ptr) - offsetof(type, member)))
#endif /* container_of */

#define MDBX_TETRAD(a, b, c, d)                                                \
  ((uint32_t)(a) << 24 | (uint32_t)(b) << 16 | (uint32_t)(c) << 8 | (d))

#define MDBX_STRING_TETRAD(str) MDBX_TETRAD(str[0], str[1], str[2], str[3])

#define FIXME "FIXME: " __FILE__ ", " MDBX_STRINGIFY(__LINE__)

#ifndef STATIC_ASSERT_MSG
#   if defined(static_assert)
#       define STATIC_ASSERT_MSG(expr, msg) static_assert(expr, msg)
#   elif defined(_STATIC_ASSERT)
#       define STATIC_ASSERT_MSG(expr, msg) _STATIC_ASSERT(expr)
#   elif defined(_MSC_VER)
#       include <crtdbg.h>
#       define STATIC_ASSERT_MSG(expr, msg) _STATIC_ASSERT(expr)
#   elif (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L) \
          || __has_feature(c_static_assert)
#       define STATIC_ASSERT_MSG(expr, msg) _Static_assert(expr, msg)
#   else
#       define STATIC_ASSERT_MSG(expr, msg) switch (0) {case 0:case (expr):;}
#   endif
#endif /* STATIC_ASSERT */

#ifndef STATIC_ASSERT
#   define STATIC_ASSERT(expr) STATIC_ASSERT_MSG(expr, #expr)
#endif

/* *INDENT-ON* */
/* clang-format on */
