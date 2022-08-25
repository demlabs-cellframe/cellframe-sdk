/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * Anatolii Kurotych <akurotych@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/
//#define _XOPEN_SOURCE 700

#pragma once
#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#ifndef __cplusplus
# include <stdatomic.h>
#else
# include <atomic>
# define _Atomic(X) std::atomic< X >
#define atomic_bool _Atomic(bool)
#define atomic_uint _Atomic(uint)
#endif


#include <time.h>
#ifdef DAP_OS_WINDOWS
#include <fcntl.h>
#define pipe(pfds) _pipe(pfds, 4096, _O_BINARY)
#define strerror_r(arg1, arg2, arg3) strerror_s(arg2, arg3, arg1)
#endif
#ifdef __MACH__
#include <dispatch/dispatch.h>
#endif
#include "portable_endian.h"
typedef uint8_t byte_t;

#define BIT( x ) ( 1 << x )
// Stuffs an integer into a pointer type
#define DAP_INT_TO_POINTER(i) ((void*) (size_t) (i))
// Extracts an integer from a pointer
#define DAP_POINTER_TO_INT(p) ((int)  (size_t) (void *) (p))
// Stuffs an unsigned integer into a pointer type
#define DAP_UINT_TO_POINTER(u) ((void*) (unsigned long) (u))
// Extracts an unsigned integer from a pointer
#define DAP_POINTER_TO_UINT(p) ((unsigned int) (unsigned long) (p))
// Stuffs a size_t into a pointer type
#define DAP_SIZE_TO_POINTER(s) ((void*) (size_t) (s))
// Extracts a size_t from a pointer
#define DAP_POINTER_TO_SIZE(p) ((size_t) (p))

#if defined(__GNUC__) ||defined (__clang__)
  #define DAP_ALIGN_PACKED  __attribute__((aligned(1),packed))
#else
  #define DAP_ALIGN_PACKED  __attribute__((aligned(1),packed))
#endif

#ifdef _MSC_VER
  #define DAP_STATIC_INLINE static __forceinline
  #define DAP_INLINE __forceinline
  #define DAP_ALIGNED(x) __declspec( align(x) )
#else
  #define DAP_STATIC_INLINE static __attribute__((always_inline)) inline
  #define DAP_INLINE __attribute__((always_inline)) inline
  #define DAP_ALIGNED(x) __attribute__ ((aligned (x)))
#endif

#ifndef TRUE
  #define TRUE  true
  #define FALSE false
#endif

#ifndef UNUSED
  #define UNUSED(x) (void)(x)
#endif

#ifndef ROUNDUP
  #define ROUNDUP(n,width) (((n) + (width) - 1) & ~(unsigned)((width) - 1))
#endif

#ifdef __cplusplus
#define DAP_CAST_REINT(t,v) reinterpret_cast<t*>(v)
#else
#define DAP_CAST_REINT(t,v) ((t*) v)
#endif

#if DAP_USE_RPMALLOC
  #include "rpmalloc.h"
  #define DAP_MALLOC(a)         rpmalloc(a)
  #define DAP_FREE(a)           rpfree(a)
  #define DAP_CALLOC(a, b)      rpcalloc(a, b)
  #define DAP_ALMALLOC(a, b)    rpaligned_alloc(a, b)
  #define DAP_ALREALLOC(a,b,c)  rpaligned_realloc(a, b, c, 0, 0)
  #define DAP_ALFREE(a)         rpfree(a)
  #define DAP_NEW(a)            DAP_CAST_REINT(a, rpmalloc(sizeof(a)))
  #define DAP_NEW_SIZE(a, b)    DAP_CAST_REINT(a, rpmalloc(b))
  #define DAP_NEW_Z(a)          DAP_CAST_REINT(a, rpcalloc(1,sizeof(a)))
  #define DAP_NEW_Z_SIZE(a, b)  DAP_CAST_REINT(a, rpcalloc(1,b))
  #define DAP_REALLOC(a, b)     rprealloc(a,b)
  #define DAP_DELETE(a)         rpfree(a)
  #define DAP_DUP(a)            memcpy(rpmalloc(sizeof(*a)), a, sizeof(*a))
  #define DAP_DUP_SIZE(a, s)    memcpy(rpmalloc(s), a, s)
#else
  #define DAP_MALLOC(a)         malloc(a)
  #define DAP_FREE(a)           free(a)
  #define DAP_CALLOC(a, b)      calloc(a, b)
  #define DAP_ALMALLOC(a, b)    _dap_aligned_alloc(a, b)
  #define DAP_ALREALLOC(a, b)   _dap_aligned_realloc(a, b)
  #define DAP_ALFREE(a)         _dap_aligned_free(a, b)
  #define DAP_NEW( a )          DAP_CAST_REINT(a, malloc(sizeof(a)) )
  #define DAP_NEW_SIZE(a, b)    DAP_CAST_REINT(a, malloc(b) )
  #define DAP_NEW_STACK( a )        DAP_CAST_REINT(a, alloca(sizeof(a)) )
  #define DAP_NEW_STACK_SIZE(a, b)  DAP_CAST_REINT(a, alloca(b) )
  #define DAP_NEW_Z( a )        DAP_CAST_REINT(a, calloc(1,sizeof(a)))
  #define DAP_NEW_Z_SIZE(a, b)  DAP_CAST_REINT(a, calloc(1,b))
  #define DAP_REALLOC(a, b)     realloc(a,b)
  #define DAP_DELETE(a)         free((void *)a)
  #define DAP_DUP(a)            memcpy(malloc(sizeof(*a)), a, sizeof(*a))
  #define DAP_DUP_SIZE(a, s)    memcpy(malloc(s), a, s)
#endif

#define DAP_DEL_Z(a)            if (a) { DAP_DELETE((void *)a); (a) = NULL; }

DAP_STATIC_INLINE void *_dap_aligned_alloc( uintptr_t alignment, uintptr_t size )
{
    uintptr_t ptr = (uintptr_t) DAP_MALLOC( size + (alignment * 2) + sizeof(void *) );

    if ( !ptr )
        return (void *)ptr;

    uintptr_t al_ptr = ( ptr + sizeof(void *) + alignment) & ~(alignment - 1 );
    ((uintptr_t *)al_ptr)[-1] = ptr;

    return (void *)al_ptr;
}

DAP_STATIC_INLINE void *_dap_aligned_realloc( uintptr_t alignment, void *bptr, uintptr_t size )
{
    uintptr_t ptr = (uintptr_t) DAP_REALLOC( bptr, size + (alignment * 2) + sizeof(void *) );

    if ( !ptr )
        return (void *)ptr;

    uintptr_t al_ptr = ( ptr + sizeof(void *) + alignment) & ~(alignment - 1 );
    ((uintptr_t *)al_ptr)[-1] = ptr;

    return (void *)al_ptr;
}

DAP_STATIC_INLINE void _dap_aligned_free( void *ptr )
{
    if ( !ptr )
        return;

    void  *base_ptr = (void *)((uintptr_t *)ptr)[-1];
    DAP_FREE( base_ptr );
}

/*
 * 23: added support for encryption key type parameter and option to encrypt headers
 * 24: Update hashes protocol
*/
#define DAP_PROTOCOL_VERSION          24
#define DAP_PROTOCOL_VERSION_DEFAULT  24 // used if version is not explicitly specified

#define DAP_CLIENT_PROTOCOL_VERSION   24

#if (__SIZEOF_LONG__ == 4) || defined (DAP_OS_DARWIN)
#define DAP_UINT64_FORMAT_X  "llX"
#define DAP_UINT64_FORMAT_x  "llx"
#define DAP_UINT64_FORMAT_U  "llu"
#elif (__SIZEOF_LONG__ == 8)
#define DAP_UINT64_FORMAT_X  "lX"
#define DAP_UINT64_FORMAT_x  "lx"
#define DAP_UINT64_FORMAT_U  "lu"
#else
#error "DAP_UINT64_FORMAT_* are undefined for your platform"
#endif


#ifdef DAP_OS_WINDOWS
#ifdef _WIN64
#define DAP_FORMAT_SOCKET "llu"
#else
#define DAP_FORMAT_SOCKET "lu"
#endif // _WIN64
#define DAP_FORMAT_HANDLE "p"
#else
#define DAP_FORMAT_SOCKET "d"
#define DAP_FORMAT_HANDLE "d"
#endif // DAP_OS_WINDOWS

#ifndef LOWORD
  #define LOWORD( l ) ((uint16_t) (((uintptr_t) (l)) & 0xFFFF))
  #define HIWORD( l ) ((uint16_t) ((((uintptr_t) (l)) >> 16) & 0xFFFF))
  #define LOBYTE( w ) ((uint8_t) (((uintptr_t) (w)) & 0xFF))
  #define HIBYTE( w ) ((uint8_t) ((((uintptr_t) (w)) >> 8) & 0xFF))
#endif

#ifndef RGB
  #define RGB(r,g,b) ((uint32_t)(((uint8_t)(r)|((uint16_t)((uint8_t)(g))<<8))|(((uint32_t)(uint8_t)(b))<<16)))
  #define RGBA(r, g, b, a) ((uint32_t) ((uint32_t)RGB(r,g,b) | (uint32_t)(a) << 24))
  #define GetRValue(rgb) (LOBYTE(rgb))
  #define GetGValue(rgb) (LOBYTE(((uint16_t)(rgb)) >> 8))
  #define GetBValue(rgb) (LOBYTE((rgb)>>16))
  #define GetAValue(rgb) (LOBYTE((rgb)>>24))
#endif

#define QBYTE RGBA

#define DAP_LOG_HISTORY 1

//#define DAP_LOG_HISTORY_STR_SIZE    128
//#define DAP_LOG_HISTORY_MAX_STRINGS 4096
//#define DAP_LOG_HISTORY_BUFFER_SIZE (DAP_LOG_HISTORY_STR_SIZE * DAP_LOG_HISTORY_MAX_STRINGS)
//#define DAP_LOG_HISTORY_M           (DAP_LOG_HISTORY_MAX_STRINGS - 1)

#ifdef _WIN32
  #define dap_sscanf            __mingw_sscanf
  #define dap_vsscanf           __mingw_vsscanf
  #define dap_scanf             __mingw_scanf
  #define dap_vscanf            __mingw_vscanf
  #define dap_fscanf            __mingw_fscanf
  #define dap_vfscanf           __mingw_vfscanf
  #define dap_sprintf           __mingw_sprintf
  #define dap_snprintf          __mingw_snprintf
  #define dap_printf            __mingw_printf
  #define dap_vprintf           __mingw_vprintf
  #define dap_fprintf           __mingw_fprintf
  #define dap_vfprintf          __mingw_vfprintf
  #define dap_vsprintf          __mingw_vsprintf
  #define dap_vsnprintf         __mingw_vsnprintf
  #define dap_asprintf          __mingw_asprintf
  #define dap_vasprintf         __mingw_vasprintf
#else
  #define dap_sscanf            sscanf
  #define dap_vsscanf           vsscanf
  #define dap_scanf             scanf
  #define dap_vscanf            vscanf
  #define dap_fscanf            fscanf
  #define dap_vfscanf           vfscanf
  #define dap_sprintf           sprintf
  #define dap_snprintf          snprintf
  #define dap_printf            printf
  #define dap_vprintf           vprintf
  #define dap_fprintf           fprintf
  #define dap_vfprintf          vfprintf
  #define dap_vsprintf          vsprintf
  #define dap_vsnprintf         vsnprintf
  #define dap_asprintf          asprintf
  #define dap_vasprintf         vasprintf
#endif

typedef int dap_spinlock_t;

/**
 * @brief The log_level enum
 */

typedef enum dap_log_level {

  L_DEBUG     = 0,
  L_INFO      = 1,
  L_NOTICE    = 2,
  L_MSG       = 3,
  L_DAP       = 4,
  L_WARNING   = 5,
  L_ATT       = 6,
  L_ERROR     = 7,
  L_CRITICAL  = 8,
  L_TOTAL,

} dap_log_level_t;

typedef struct dap_log_history_str_s {

  time_t    t;
  uint8_t   *str;
  uint32_t  len;

} dap_log_history_str_t;

#define DAP_INTERVAL_TIMERS_MAX 15

typedef void (*dap_timer_callback_t)(void *param);
typedef struct dap_timer_interface {
    void *timer;
    dap_timer_callback_t callback;
    void *param;
} dap_timer_interface_t;

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MAX_PATH
#define MAX_PATH 120
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif


extern uint16_t htoa_lut256[ 256 ];

#define dap_htoa64( out, in, len ) \
{\
  uintptr_t  _len = len; \
  uint16_t *__restrict _out = (uint16_t *__restrict)out; \
  uint64_t *__restrict _in  = (uint64_t *__restrict)in;\
\
  while ( _len ) {\
    uint64_t  _val = *_in ++;\
    _out[0] = htoa_lut256[  _val & 0x00000000000000FF ];\
    _out[1] = htoa_lut256[ (_val & 0x000000000000FF00) >> 8 ];\
    _out[2] = htoa_lut256[ (_val & 0x0000000000FF0000) >> 16 ];\
    _out[3] = htoa_lut256[ (_val & 0x00000000FF000000) >> 24 ];\
    _out[4] = htoa_lut256[ (_val & 0x000000FF00000000) >> 32 ];\
    _out[5] = htoa_lut256[ (_val & 0x0000FF0000000000) >> 40 ];\
    _out[6] = htoa_lut256[ (_val & 0x00FF000000000000) >> 48 ];\
    _out[7] = htoa_lut256[ (_val & 0xFF00000000000000) >> 56 ];\
    _out += 8;\
    _len -= 8;\
  }\
}

typedef enum {
    DAP_ASCII_ALNUM = 1 << 0,
    DAP_ASCII_ALPHA = 1 << 1,
    DAP_ASCII_CNTRL = 1 << 2,
    DAP_ASCII_DIGIT = 1 << 3,
    DAP_ASCII_GRAPH = 1 << 4,
    DAP_ASCII_LOWER = 1 << 5,
    DAP_ASCII_PRINT = 1 << 6,
    DAP_ASCII_PUNCT = 1 << 7,
    DAP_ASCII_SPACE = 1 << 8,
    DAP_ASCII_UPPER = 1 << 9,
    DAP_ASCII_XDIGIT = 1 << 10
} DapAsciiType;

static const uint16_t s_ascii_table_data[256] = {
    0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004,
    0x004, 0x104, 0x104, 0x004, 0x104, 0x104, 0x004, 0x004,
    0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004,
    0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004, 0x004,
    0x140, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0,
    0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0,
    0x459, 0x459, 0x459, 0x459, 0x459, 0x459, 0x459, 0x459,
    0x459, 0x459, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0,
    0x0d0, 0x653, 0x653, 0x653, 0x653, 0x653, 0x653, 0x253,
    0x253, 0x253, 0x253, 0x253, 0x253, 0x253, 0x253, 0x253,
    0x253, 0x253, 0x253, 0x253, 0x253, 0x253, 0x253, 0x253,
    0x253, 0x253, 0x253, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x0d0,
    0x0d0, 0x473, 0x473, 0x473, 0x473, 0x473, 0x473, 0x073,
    0x073, 0x073, 0x073, 0x073, 0x073, 0x073, 0x073, 0x073,
    0x073, 0x073, 0x073, 0x073, 0x073, 0x073, 0x073, 0x073,
    0x073, 0x073, 0x073, 0x0d0, 0x0d0, 0x0d0, 0x0d0, 0x004
/* the upper 128 are all zeroes */
};

//const uint16_t * const c_dap_ascii_table = s_ascii_table_data;

#define dap_ascii_isspace(c) (s_ascii_table_data[(unsigned char) (c)] & DAP_ASCII_SPACE)
#define dap_ascii_isalpha(c) (s_ascii_table_data[(unsigned char) (c)] & DAP_ASCII_ALPHA)
#define dap_ascii_isalnum(c) (s_ascii_table_data[(unsigned char) (c)] & DAP_ASCII_ALNUM)
#define dap_ascii_isdigit(c) (s_ascii_table_data[(unsigned char) (c)] & DAP_ASCII_DIGIT)

void dap_sleep( uint32_t ms );

DAP_STATIC_INLINE bool DAP_AtomicTryLock( dap_spinlock_t *lock )
{
    return (__sync_lock_test_and_set(lock, 1) == 0);
}

DAP_STATIC_INLINE void DAP_AtomicLock( dap_spinlock_t *lock )
{
    while ( !DAP_AtomicTryLock(lock) ) {
        dap_sleep( 0 );
    }
}

DAP_STATIC_INLINE void DAP_AtomicUnlock( dap_spinlock_t *lock )
{
    __sync_lock_release( lock );
}

DAP_INLINE void dap_uint_to_hex(char *arr, uint64_t val, short size) {
    short i = 0;
    for (i = 0; i < size; ++i) {
        arr[i] = (char)(((uint64_t) val >> (8 * (size - 1 - i))) & 0xFFu);
    }
}

DAP_INLINE uint64_t dap_hex_to_uint(const char *arr, short size) {
    uint64_t val = 0;
    short i = 0;
    for (i = 0; i < size; ++i){
        uint8_t byte = (uint8_t) *arr++;
        val = (val << 8) | (byte & 0xFFu);
    }
    return val;
}

extern char *g_sys_dir_path;

//int dap_common_init( const char * a_log_file );
int dap_common_init( const char *console_title, const char *a_log_file, const char *a_log_dirpath );
int wdap_common_init( const char *console_title, const wchar_t *a_wlog_file);

void dap_common_deinit(void);

// set max items in log list
void dap_log_set_max_item(unsigned int a_max);
// get logs from list
char *dap_log_get_item(time_t a_start_time, int a_limit);

#if defined __GNUC__ || defined __clang__
#ifdef __MINGW_PRINTF_FORMAT
#define DAP_PRINTF_ATTR(format_index, args_index) \
    __attribute__ ((format (gnu_printf, format_index, args_index)))
#else
#define DAP_PRINTF_ATTR(format_index, args_index) \
    __attribute__ ((format (printf, format_index, args_index)))
#endif
#else /* __GNUC__ */
#define DAP_PRINTF_ATTR(format_index, args_index)
#endif /* __GNUC__ */


DAP_PRINTF_ATTR(3, 4) void _log_it( const char * log_tag, enum dap_log_level, const char * format, ... );
#define log_it(_log_level, ...) _log_it( LOG_TAG, _log_level, ##__VA_ARGS__)
#define debug_if(flg, lvl, ...) _log_it(((flg) ? LOG_TAG : NULL), (lvl), ##__VA_ARGS__)

#ifdef DAP_SYS_DEBUG
void    _log_it_ext( const char *, unsigned, enum dap_log_level, const char * format, ... );
void    _dump_it (const char *, unsigned , const char *a_var_name, const void *src, unsigned short srclen);
#undef  log_it
#define log_it( _log_level, ...) _log_it_ext( __func__, __LINE__, (_log_level), ##__VA_ARGS__)
#define dump_it(v,s,l) _dump_it( __func__, __LINE__, (v), (s), (l))
#else
#define dump_it(v,s,l)
#endif



const char * log_error(void);
void dap_log_level_set(enum dap_log_level ll);
enum dap_log_level dap_log_level_get(void);
void dap_set_log_tag_width(size_t width);

const char * dap_get_appname();
void dap_set_appname(const char * a_appname);

char *dap_itoa(int i);

unsigned dap_gettid();

int get_select_breaker(void);
int send_select_break(void);
int exec_with_ret(char**, const char*);
char* exec_with_ret_multistring(const char* a_cmd);
char * dap_random_string_create_alloc(size_t a_length);
void dap_random_string_fill(char *str, size_t length);
void dap_dump_hex(const void* data, size_t size);

size_t dap_hex2bin(uint8_t *a_out, const char *a_in, size_t a_len);
size_t dap_bin2hex(char *a_out, const void *a_in, size_t a_len);
void dap_digit_from_string(const char *num_str, void *raw, size_t raw_len);
void dap_digit_from_string2(const char *num_str, void *raw, size_t raw_len);

void *dap_interval_timer_create(unsigned int a_msec, dap_timer_callback_t a_callback, void *a_param);
int dap_interval_timer_delete(void *a_timer);
void dap_interval_timer_deinit();

static inline void * dap_mempcpy(void * a_dest,const void * a_src,size_t n)
{
    return ((byte_t*) memcpy(a_dest,a_src,n))+n;
}

DAP_STATIC_INLINE int dap_is_alpha(char c) { return dap_ascii_isalnum(c); }
DAP_STATIC_INLINE int dap_is_digit(char c) { return dap_ascii_isdigit(c); }
DAP_STATIC_INLINE int dap_is_alpha_and_(char c) { return dap_is_alpha(c) || c == '_'; }
char **dap_parse_items(const char *a_str, char a_delimiter, int *a_count, const int a_only_digit);

unsigned int dap_crc32c(unsigned int crc, const void *buf, size_t buflen);

static inline const char *dap_get_arch() { //Get current architecture, detectx nearly every architecture. Coded by Freak
        #if defined(__x86_64__) || defined(_M_X64)
        return "x86_64";
        #elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
        return "x86_32";
        #elif defined(__ARM_ARCH_2__)
        return "arm2";
        #elif defined(__ARM_ARCH_3__) || defined(__ARM_ARCH_3M__)
        return "arm3";
        #elif defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
        return "arm4t";
        #elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
        return "arm5"
        #elif defined(__ARM_ARCH_6T2_) || defined(__ARM_ARCH_6T2_)
        return "arm6t2";
        #elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__)
        return "arm6";
        #elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
        return "arm7";
        #elif defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
        return "arm7a";
        #elif defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
        return "arm7r";
        #elif defined(__ARM_ARCH_7M__)
        return "arm7m";
        #elif defined(__ARM_ARCH_7S__)
        return "arm7s";
        #elif defined(__aarch64__) || defined(_M_ARM64)
        return "arm64";
        #elif defined(mips) || defined(__mips__) || defined(__mips)
        return "mips";
        #elif defined(__sh__)
        return "superh";
        #elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__PPC__) || defined(_ARCH_PPC)
        return "powerpc";
        #elif defined(__PPC64__) || defined(__ppc64__) || defined(_ARCH_PPC64)
        return "powerpc64";
        #elif defined(__sparc__) || defined(__sparc)
        return "sparc";
        #elif defined(__m68k__)
        return "m68k";
        #else
        return "unknown";
        #endif
    }

#ifdef __MINGW32__
int exec_silent(const char *a_cmd);
#endif

#ifdef __cplusplus
}
#endif
