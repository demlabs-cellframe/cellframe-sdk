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
#ifndef _WINSOCKAPI_
#include <winsock2.h>
#endif
#include <fcntl.h>
#define pipe(pfds) _pipe(pfds, 4096, _O_BINARY)
#define strerror_r(arg1, arg2, arg3) strerror_s(arg2, arg3, arg1)
#else
#include <unistd.h>
#endif
#ifdef __MACH__
#include <dispatch/dispatch.h>
#endif
#include "portable_endian.h"

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
#define DAP_CAST_REINT(t,v) ((t*)(v))
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
#elif   DAP_SYS_DEBUG

#include    <assert.h>

#define     MEMSTAT$SZ_NAME     63
#define     MEMSTAT$K_MAXNR     8192
#define     MEMSTAT$K_MINTOLOG  (32*1024)

typedef struct __dap_memstat_rec__ {

        unsigned char   fac_len,                                        /* Length of the facility name */
                        fac_name[MEMSTAT$SZ_NAME + 1];                  /* A human readable facility name, ASCIC */

        ssize_t         alloc_sz;                                       /* A size of the single allocations */
        atomic_ullong   alloc_nr,                                       /* A number of allocations */
                        free_nr;                                        /* A number of deallocations */
} dap_memstat_rec_t;

int     dap_memstat_reg (dap_memstat_rec_t   *a_memstat_rec);
void    dap_memstat_show (void);
extern  dap_memstat_rec_t    *g_memstat [MEMSTAT$K_MAXNR];              /* Array to keep pointers to module/facility specific memstat vecros */

static inline void s_vm_free(const char *a_rtn_name, int a_rtn_line, void *a_ptr);
static inline void *s_vm_get(const char *a_rtn_name, int a_rtn_line, ssize_t a_size);
static inline void *s_vm_get_z(const char *a_rtn_name, int a_rtn_line, ssize_t a_nr, ssize_t a_size);
static inline void *s_vm_extend(const char *a_rtn_name, int a_rtn_line, void *a_ptr, ssize_t a_size);


    #define DAP_FREE(a)         s_vm_free(__func__, __LINE__, (void *) a)
    #define DAP_DELETE(a)       s_vm_free(__func__, __LINE__, (void *) a)

    #define DAP_MALLOC(a)       s_vm_get(__func__, __LINE__, a)
    #define DAP_CALLOC(a, b)    s_vm_get_z(__func__, __LINE__, a, b)
    #define DAP_ALMALLOC(a, b)    _dap_aligned_alloc(a, b)
    #define DAP_ALREALLOC(a, b)   _dap_aligned_realloc(a, b)
    #define DAP_ALFREE(a)         _dap_aligned_free(a, b)
    #define DAP_NEW( a )          DAP_CAST_REINT(a, s_vm_get(__func__, __LINE__, sizeof(a)) )
    #define DAP_NEW_SIZE(a, b)    DAP_CAST_REINT(a, s_vm_get(__func__, __LINE__, b) )
    #define DAP_NEW_S( a )        DAP_CAST_REINT(a, alloca(sizeof(a)) )
    #define DAP_NEW_S_SIZE(a, b)  DAP_CAST_REINT(a, alloca(b) )
    #define DAP_NEW_Z( a )        DAP_CAST_REINT(a, s_vm_get_z(__func__, __LINE__, 1,sizeof(a)))
    #define DAP_NEW_Z_SIZE(a, b)  DAP_CAST_REINT(a, s_vm_get_z(__func__, __LINE__, 1,b))
    #define DAP_REALLOC(a, b)     s_vm_extend(__func__, __LINE__, a,b)

    #define DAP_DUP(a)            memcpy(s_vm_get(__func__, __LINE__, sizeof(*a)), a, sizeof(*a))
    #define DAP_DUP_SIZE(a, s)    memcpy(s_vm_get(__func__, __LINE__, s), a, s)

#else
  #define DAP_MALLOC(p)         malloc(p)
  #define DAP_FREE(p)           free(p)
  #define DAP_CALLOC(p, s)      s > 0 ? calloc(p, s) : NULL
  #define DAP_ALMALLOC(p, s)    s > 0 ? _dap_aligned_alloc(p, s) : NULL
  #define DAP_ALREALLOC(p, s)   s > 0 ? _dap_aligned_realloc(p, s) : ({ _dap_aligned_free(p); NULL; })
  #define DAP_ALFREE(p)         _dap_aligned_free(p)
  #define DAP_PAGE_ALMALLOC(p)  _dap_page_aligned_alloc(p)
  #define DAP_PAGE_ALFREE(p)    _dap_page_aligned_free(p)
  #define DAP_NEW(t)            DAP_CAST_REINT(t, malloc(sizeof(t)))
  #define DAP_NEW_SIZE(t, s)    s > 0 ? DAP_CAST_REINT(t, malloc(s)) : NULL
  #define DAP_NEW_S(t)          DAP_CAST_REINT(t, alloca(sizeof(t)))
  #define DAP_NEW_S_SIZE(t, s)  s > 0 ? DAP_CAST_REINT(t, alloca(s)) : NULL
  #define DAP_NEW_Z(t)          DAP_CAST_REINT(t, calloc(1, sizeof(t)))
  #define DAP_NEW_Z_SIZE(t, s)  ((s) > 0 ? DAP_CAST_REINT(t, calloc(1, (s))) : NULL)
  #define DAP_REALLOC(t, s)     s > 0 ? realloc(t, s) : ({ DAP_DEL_Z(t); (void*) NULL; })
  #define DAP_DELETE(p)         free((void*)(p))
  #define DAP_DUP(p)            ({ void *p1 = p ? calloc(1, sizeof(*p)) : NULL; p1 ? memcpy(p1, p, sizeof(*p)) : NULL; })
  #define DAP_DUP_SIZE(p, s)    ({ void *p1 = p && (s > 0) ? calloc(1, s) : NULL; p1 ? memcpy(p1, p, s) : NULL; })
#endif

#define DAP_DEL_Z(a)            do { if (a) { DAP_DELETE(a); (a) = NULL; } } while (0);

DAP_STATIC_INLINE unsigned long dap_pagesize() {
    static int s = 0;
    if (s)
        return s;
#ifdef DAP_OS_WINDOWS
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    s = si.dwPageSize;
#else
    s = sysconf(_SC_PAGESIZE);
#endif
    return s ? s : 4096;
}

#ifdef DAP_OS_WINDOWS
typedef struct iovec {
    void    *iov_base; /* Data */
    size_t  iov_len; /* ... and its' size */
} iovec_t;

size_t dap_readv    (HANDLE a_hf, iovec_t const *a_bufs, int a_bufs_num, DWORD *a_err);
size_t dap_writev   (HANDLE a_hf, const char* a_filename, iovec_t const *a_bufs, int a_bufs_num, DWORD *a_err);

#else
#define dap_readv readv
#define dap_writev writev
#endif

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
    uintptr_t ptr = (uintptr_t)(DAP_REALLOC( bptr, size + (alignment * 2) + sizeof(void *) ));

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

DAP_STATIC_INLINE void *_dap_page_aligned_alloc(size_t size) {
#ifndef DAP_OS_WINDOWS
    return valloc(size);
#else
    return VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#endif
}

DAP_STATIC_INLINE void _dap_page_aligned_free(void *ptr) {
#ifndef DAP_OS_WINDOWS
    free(ptr);
#else
    VirtualFree(ptr, 0, MEM_RELEASE);
#endif
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

typedef uint8_t byte_t;
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

typedef void *dap_interval_timer_t;
typedef void (*dap_timer_callback_t)(void *param);

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

#define dap_ascii_isspace(c) (s_ascii_table_data[(unsigned char) (c)] & DAP_ASCII_SPACE) != 0
#define dap_ascii_isalpha(c) (s_ascii_table_data[(unsigned char) (c)] & DAP_ASCII_ALPHA) != 0

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
#define log_it(_log_level, ...) _log_it(LOG_TAG, _log_level, ##__VA_ARGS__)
#define debug_if(flg, lvl, ...) _log_it(((flg) ? LOG_TAG : NULL), (lvl), ##__VA_ARGS__)

#ifdef DAP_SYS_DEBUG
void    _log_it_ext( const char *, unsigned, enum dap_log_level, const char * format, ... );
void    _dump_it (const char *, unsigned , const char *a_var_name, const void *src, unsigned short srclen);
#undef  log_it
#define log_it( _log_level, ...)        _log_it_ext( __func__, __LINE__, (_log_level), ##__VA_ARGS__)
#undef  debug_if
#define debug_if(flg, _log_level, ...)  _log_it_ext( __func__, __LINE__, (flg) ? (_log_level) : -1 , ##__VA_ARGS__)

#define dump_it(v,s,l)                  _dump_it( __func__, __LINE__, (v), (s), (l))


static inline void s_vm_free(
            const char  *a_rtn_name,
                int     a_rtn_line,
                void    *a_ptr
                )
{
        if ( !a_ptr )
            return;


        log_it(L_DEBUG, "Free .........: [%p] at %s:%d", a_ptr, a_rtn_name, a_rtn_line);
        free(a_ptr);
}


static inline void *s_vm_get (
            const char  *a_rtn_name,
                int     a_rtn_line,
                ssize_t a_size
                )
{
void    *l_ptr;

        if ( !a_size )
            return  NULL;

        if ( !(l_ptr = malloc(a_size)) )
        {
            assert ( l_ptr );
            return  NULL;
        }

        if ( a_size > MEMSTAT$K_MINTOLOG )
            log_it(L_DEBUG, "Allocated ....: [%p] %zd octets, at %s:%d", l_ptr, a_size, a_rtn_name, a_rtn_line);

        return  l_ptr;
}

static inline void *s_vm_get_z(
        const char *a_rtn_name,
                int a_rtn_line,
            ssize_t a_nr,
            ssize_t a_size
        )
{
void    *l_ptr;

        if ( !a_size || !a_nr )
            return  NULL;

        if ( !(l_ptr = calloc(a_nr, a_size)) )
        {
            assert ( l_ptr );
            return  NULL;
        }

        if ( a_size > MEMSTAT$K_MINTOLOG )
            log_it(L_DEBUG, "Allocated ....: [%p] %zd octets, nr: %zd (total:%zd), at %s:%d", l_ptr, a_size, a_nr, a_nr * a_size, a_rtn_name, a_rtn_line);

        return  l_ptr;
}



static inline void *s_vm_extend (
        const char *a_rtn_name,
                int a_rtn_line,
            void *a_ptr,
            ssize_t a_size
            )
{
void    *l_ptr;

        if ( !a_size )
            return  NULL;

        if ( !(l_ptr = realloc(a_ptr, a_size)) )
        {
            assert ( l_ptr );
            return  NULL;
        }

        if ( a_size > MEMSTAT$K_MINTOLOG )
            log_it(L_DEBUG, "Extended .....: [%p] -> [%p %zd octets], at %s:%d", a_ptr, l_ptr, a_size, a_rtn_name, a_rtn_line);

        return  l_ptr;
}




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

int get_select_breaker(void);
int send_select_break(void);
int exec_with_ret(char**, const char*);
char * exec_with_ret_multistring(const char * a_cmd);
char * dap_random_string_create_alloc(size_t a_length);
void dap_random_string_fill(char *str, size_t length);
void dap_dump_hex(const void* data, size_t size);

size_t dap_hex2bin(uint8_t *a_out, const char *a_in, size_t a_len);
size_t dap_bin2hex(char *a_out, const void *a_in, size_t a_len);
void dap_digit_from_string(const char *num_str, void *raw, size_t raw_len);
void dap_digit_from_string2(const char *num_str, void *raw, size_t raw_len);

dap_interval_timer_t dap_interval_timer_create(unsigned int a_msec, dap_timer_callback_t a_callback, void *a_param);
void dap_interval_timer_delete(dap_interval_timer_t a_timer);
int dap_interval_timer_disable(dap_interval_timer_t a_timer);
void dap_interval_timer_init();
void dap_interval_timer_deinit();

uint16_t dap_lendian_get16(const uint8_t *a_buf);
void dap_lendian_put16(uint8_t *a_buf, uint16_t a_val);
uint32_t dap_lendian_get32(const uint8_t *a_buf);
void dap_lendian_put32(uint8_t *a_buf, uint32_t a_val);
uint64_t dap_lendian_get64(const uint8_t *a_buf);
void dap_lendian_put64(uint8_t *a_buf, uint64_t a_val);


static inline void * dap_mempcpy(void * a_dest,const void * a_src,size_t n)
{
    return ((byte_t*) memcpy(a_dest,a_src,n))+n;
}

int dap_is_alpha_and_(char e);
int dap_is_alpha(char e);
int dap_is_digit(char e);
char **dap_parse_items(const char *a_str, char a_delimiter, int *a_count, const int a_only_digit);

#ifdef __MINGW32__
int exec_silent(const char *a_cmd);
#endif

#ifdef __cplusplus
}
#endif
