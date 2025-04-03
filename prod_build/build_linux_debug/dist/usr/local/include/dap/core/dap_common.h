/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * Anatolii Kurotych <akurotych@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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
#pragma once
#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#ifdef DAP_OS_WINDOWS
#ifndef _WINSOCKAPI_
#include <winsock2.h>
#endif
#include <fcntl.h>
#define pipe(pfds) _pipe(pfds, 4096, _O_BINARY)
#define strerror_r(arg1, arg2, arg3) strerror_s(arg2, arg3, arg1)
#define popen _popen
#define pclose _pclose
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#ifdef __USE_GNU
# undef __USE_GNU
# define NEED_GNU_REENABLE
#endif
#include <string.h>
#ifdef NEED_GNU_REENABLE
# define __USE_GNU
#endif
#include <assert.h>
#include <ctype.h>
#include <pthread.h>

#ifndef __cplusplus
# include <stdatomic.h>
#else
#include <atomic>
#define _Atomic(X) std::atomic< X >
#define atomic_bool _Atomic(bool)
#define atomic_uint _Atomic(uint)
#define atomic_int _Atomic(int)
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

#if defined(__GNUC__) || defined (__clang__)
  #define DAP_ALIGN_PACKED  __attribute__((aligned(1),packed))
  #define DAP_PACKED  __attribute__((packed))
#else
  #define DAP_ALIGN_PACKED  __attribute__((aligned(1),packed))
  #define DAP_PACKED  __attribute__((packed))
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

#define UNUSED_ARG __attribute__((__unused__))
#define LAST_ERROR_MAX  256

// TODO pipelines fix to enable this macros
/*#ifndef likely
#   if (defined(__GNUC__) || __has_builtin(__builtin_expect)) && !defined(__COVERITY__)
#       define likely(cond) __builtin_expect(!!(cond), 1)
#   else
#       define likely(x) (!!(x))
#   endif
#endif // likely

#ifndef unlikely
#   if (defined(__GNUC__) || __has_builtin(__builtin_expect)) && !defined(__COVERITY__)
#       define unlikely(cond) __builtin_expect(!!(cond), 0)
#   else
#       define unlikely(x) (!!(x))
#   endif
#endif // unlikely
 */

#ifndef ROUNDUP
  #define ROUNDUP(n,width) (((n) + (width) - 1) & ~(unsigned)((width) - 1))
#endif

#ifdef __cplusplus
#define DAP_CAST(t,v) reinterpret_cast<t>(v)
#define DAP_CAST_PTR(t,v) DAP_CAST(t*,v)
#else
#define DAP_CAST(t,v) v
#define DAP_CAST_PTR(t,v) v
#endif

#define HASH_LAST(head) ( (head) ? ELMT_FROM_HH((head)->hh.tbl, (head)->hh.tbl->tail) : NULL );

extern const char *c_error_memory_alloc, *c_error_sanity_check, doof;
/* Don't use these function directly! Rather use the corresponding macro's */
void dap_delete_multy(size_t, ...);
uint8_t *dap_serialize_multy(uint8_t *a_data, uint64_t a_size, ...);
int dap_deserialize_multy(const uint8_t *a_data, uint64_t a_size, ...);

#if   DAP_SYS_DEBUG
#include    <assert.h>

#define     MEMSTAT$SZ_NAME     63            dap_global_db_del_sync(l_gdb_group, l_objs[i].key);
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
    #define DAP_NEW_STACK( a )        DAP_CAST_REINT(a, alloca(sizeof(a)) )
    #define DAP_NEW_STACK_SIZE(a, b)  DAP_CAST_REINT(a, alloca(b) )
    #define DAP_NEW_Z( a )        DAP_CAST_REINT(a, s_vm_get_z(__func__, __LINE__, 1,sizeof(a)))
    #define DAP_NEW_Z_SIZE(a, b)  DAP_CAST_REINT(a, s_vm_get_z(__func__, __LINE__, 1,b))
    #define DAP_REALLOC(a, b)     s_vm_extend(__func__, __LINE__, a,b)

    #define DAP_DUP(a)            memcpy(s_vm_get(__func__, __LINE__, sizeof(*a)), a, sizeof(*a))
    #define DAP_DUP_SIZE(a, s)    memcpy(s_vm_get(__func__, __LINE__, s), a, s)

#else
#ifdef DAP_USE_RPMALLOC
#include "rpmalloc.h"
#endif
#define DAP_TYPE_SIZE(p)      (intmax_t)sizeof( *(__typeof__(p)){ 0 } )
#define DAP_MALLOC(s)         ({ intmax_t _s = (intmax_t)(s); _s > 0 ? malloc(_s) : NULL; })
#define DAP_FREE(p)           free((void*)(p))
#define DAP_CALLOC(n, s)      ({ intmax_t _s = (intmax_t)(s), _n = (intmax_t)(n); _s > 0 && _n > 0 ? calloc(_n, _s) : NULL; })
#define DAP_REALLOC(p, s)     ({ intmax_t _s = (intmax_t)(s); _s >= DAP_TYPE_SIZE(p) ? realloc(p, _s) : NULL; })
#define DAP_ALMALLOC(a, s)    ({ intmax_t _s = (intmax_t)(s), _a = (intmax_t)(a); _s > 0 && _a >= 0 ? _dap_aligned_alloc(_a, _s) : NULL; })
#define DAP_ALREALLOC(p, s)   ({ intmax_t _s = (intmax_t)(s); _s >= DAP_TYPE_SIZE(p) ? _dap_aligned_realloc(p, _s) : NULL; })
#define DAP_ALFREE(p)         _dap_aligned_free(p)
#define DAP_PAGE_ALMALLOC(p)  _dap_page_aligned_alloc(p)
#define DAP_PAGE_ALFREE(p)    _dap_page_aligned_free(p)
#define DAP_NEW(t)            DAP_CAST_PTR( t, malloc(sizeof(t)) )
#define DAP_NEW_SIZE(t, s)    ({ intmax_t _s = (intmax_t)(s); _s >= (intmax_t)(sizeof(t)) ? DAP_CAST_PTR(t, malloc(_s)) : NULL; })
/* Auto memory! Do not inline! Do not modify the size in-call! */
#define DAP_NEW_STACK(t)       &(t){ }
#define DAP_NEW_STACK_SIZE(t, s) DAP_CAST_PTR( t, (intmax_t)(s) >= (intmax_t)(sizeof(t)) && (intmax_t)(s) < (1 << 15) ? alloca((intmax_t)(s)) : NULL )
/* ... */
#define DAP_NEW_Z(t)          DAP_CAST_PTR( t, calloc(1, sizeof(t)) )
#define DAP_NEW_Z_SIZE(t, s)  DAP_CAST_PTR( t, DAP_CALLOC(1, s) )
#define DAP_NEW_Z_COUNT(t, c) DAP_CAST_PTR( t, DAP_CALLOC(c, sizeof(t)) )
#define DAP_REALLOC_COUNT(p, c) DAP_CAST_PTR( t, DAP_REALLOC(p, (c) * DAP_TYPE_SIZE(p)) )
#define DAP_DELETE(p)         free((void*)(p))
#define DAP_DEL_Z(p)          do { DAP_FREE(p); (p) = NULL; } while (0);
#define DAP_DEL_ARRAY(p, c)   for ( intmax_t _c = p ? (intmax_t)(c) : 0; _c > 0; DAP_DELETE(p[--_c]) );
#define DAP_DUP_SIZE(p, s)    ({ intmax_t _s = (intmax_t)(s); __typeof__(p) _p = ( (uintptr_t)(p) && _s >= DAP_TYPE_SIZE(p) ) ? DAP_CAST(__typeof__(p), calloc(1, _s)) : NULL; _p ? DAP_CAST(__typeof__(p), memcpy(_p, (p), _s)) : NULL; })
#define DAP_DUP(p)            ({ __typeof__(p) _p = p; _p = (uintptr_t)_p ? calloc(1, sizeof(*(p))) : NULL; if (_p) *_p = *(p); _p; })

#endif

#define DOOF_PTR (void*)&doof
#define DAP_NARGS_PTRS(...)  ( sizeof( (void*[]){NULL, ##__VA_ARGS__} ) / sizeof(void*) - 1 )
#define DAP_DEL_MULTY(...) dap_delete_multy(DAP_NARGS_PTRS(__VA_ARGS__), ##__VA_ARGS__)
#define DAP_VA_SERIALIZE(data, size, ...) dap_serialize_multy(data, size, ##__VA_ARGS__, DOOF_PTR)
#define DAP_VA_SERIALIZE_NEW(size, ...) DAP_VA_SERIALIZE(NULL, size, __VA_ARGS__)
#define DAP_VA_DESERIALIZE(data, size, ...) dap_deserialize_multy(data, size, ##__VA_ARGS__, DOOF_PTR)

#define DAP_NEW_Z_RET_VAL_IF_FAIL(t, r, ...) ({ \
    t *_p = DAP_NEW_Z(t); if (!_p) { log_it(L_CRITICAL, "%s", c_error_memory_alloc); DAP_DEL_MULTY(__VA_ARGS__); return r; } _p; \
})
#define DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(t, s, r, ...) ({ \
    t *_p = DAP_NEW_Z_SIZE(t, s); if (!_p) { log_it(L_CRITICAL, "%s", c_error_memory_alloc); DAP_DEL_MULTY(__VA_ARGS__); return r; } _p; \
})
#define DAP_NEW_Z_COUNT_RET_VAL_IF_FAIL(t, c, r, ...) ({ \
    t *_p = DAP_NEW_Z_COUNT(t, c); if (!_p) { log_it(L_CRITICAL, "%s", c_error_memory_alloc); DAP_DEL_MULTY(__VA_ARGS__); return r; } _p; \
})
#define DAP_DUP_SIZE_RET_VAL_IF_FAIL(p, s, r, ...) ({ \
    void *_p = DAP_DUP_SIZE(p, s); if (!_p) { log_it(L_CRITICAL, "%s", c_error_memory_alloc); DAP_DEL_MULTY(__VA_ARGS__); return r; } _p; \
})
#define DAP_REALLOC_RET_VAL_IF_FAIL(p, s, r, ...) ({ \
    void *_p = DAP_REALLOC(p, s); if (!_p) { log_it(L_CRITICAL, "%s", c_error_memory_alloc); DAP_DEL_MULTY(__VA_ARGS__); return r; } _p; \
})
#define DAP_REALLOC_COUNT_RET_VAL_IF_FAIL(p, c, r, ...) ({ \
    void *_p = DAP_REALLOC_COUNT(p, c); if (!_p) { log_it(L_CRITICAL, "%s", c_error_memory_alloc); DAP_DEL_MULTY(__VA_ARGS__); return r; } _p; \
})

#define DAP_NEW_Z_RET_IF_FAIL(t, ...)           DAP_NEW_Z_RET_VAL_IF_FAIL(t, , __VA_ARGS__)
#define DAP_NEW_Z_SIZE_RET_IF_FAIL(t, s, ...)   DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(t, s, , __VA_ARGS__)
#define DAP_NEW_Z_COUNT_RET_IF_FAIL(t, c, ...)  DAP_NEW_Z_COUNT_RET_VAL_IF_FAIL(t, c, , __VA_ARGS__)
#define DAP_DUP_SIZE_RET_IF_FAIL(p, s, ...)     DAP_DUP_SIZE_RET_VAL_IF_FAIL(p, s, , __VA_ARGS__)
#define DAP_REALLOC_RET_IF_FAIL(p, s, ...)      DAP_REALLOC_RET_VAL_IF_FAIL(p, s, , __VA_ARGS__)
#define DAP_REALLOC_COUNT_RET_IF_FAIL(p, c, ...) DAP_REALLOC_COUNT_RET_VAL_IF_FAIL(p, c, , __VA_ARGS__)

#define dap_return_val_if_pass_err(e, r, s) do { if (e) { _log_it(__FUNCTION__, __LINE__, LOG_TAG, L_WARNING, "%s", s); return r; } } while(0);
#define dap_return_val_if_fail_err(e, r, s) dap_return_val_if_pass_err(!(e), r, s)
#define dap_return_val_if_pass(e, r)    dap_return_val_if_pass_err(e, r, c_error_sanity_check)
#define dap_return_val_if_fail(e, r)    dap_return_val_if_fail_err(e, r, c_error_sanity_check)
#define dap_return_if_pass_err(e, s)    dap_return_val_if_pass_err(e, , s)
#define dap_return_if_fail_err(e, s)    dap_return_val_if_fail_err(e, , s)
#define dap_return_if_pass(e)   dap_return_if_pass_err(e, c_error_sanity_check)
#define dap_return_if_fail(e)   dap_return_if_fail_err(e, c_error_sanity_check)

#ifndef __cplusplus
#define DAP_IS_ALIGNED(p) !((uintptr_t)DAP_CAST_PTR(void, p) % _Alignof(typeof(p)))
#endif

/**
  * @struct Node address
  */
typedef union dap_stream_node_addr {
    uint64_t uint64;
    uint16_t words[sizeof(uint64_t)/2];
    uint8_t raw[sizeof(uint64_t)];  // Access to selected octects
} DAP_ALIGN_PACKED dap_stream_node_addr_t;

#define DAP_STRINGIFY_1(s) #s
#define DAP_STRINGIFY(s) DAP_STRINGIFY_1(s)

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define NODE_ADDR_FP_STR      "%04hX::%04hX::%04hX::%04hX"
#define NODE_ADDR_FP_ARGS(a)  a->words[2],a->words[3],a->words[0],a->words[1]
#define NODE_ADDR_FPS_ARGS(a)  &a->words[2],&a->words[3],&a->words[0],&a->words[1]
#define NODE_ADDR_FP_ARGS_S(a)  a.words[2],a.words[3],a.words[0],a.words[1]
#define NODE_ADDR_FPS_ARGS_S(a)  &a.words[2],&a.words[3],&a.words[0],&a.words[1]
#else
#define NODE_ADDR_FP_STR      "%04hX::%04hX::%04hX::%04hX"
#define NODE_ADDR_FP_ARGS(a)  (a)->words[3],(a)->words[2],(a)->words[1],(a)->words[0]
#define NODE_ADDR_FPS_ARGS(a)  &(a)->words[3],&(a)->words[2],&(a)->words[1],&(a)->words[0]
#define NODE_ADDR_FP_ARGS_S(a)  (a).words[3],(a).words[2],(a).words[1],(a).words[0]
#define NODE_ADDR_FPS_ARGS_S(a)  &(a).words[3],&(a).words[2],&(a).words[1],&(a).words[0]
#endif

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

DAP_STATIC_INLINE uint64_t dap_page_roundup(uint64_t a) {
    return ( a + dap_pagesize() - 1 ) & ( ~(dap_pagesize() - 1) ); 
}

DAP_STATIC_INLINE uint64_t dap_page_rounddown(uint64_t a) {
    return a & ( ~(dap_pagesize() - 1) ); 
}

typedef union dap_error_str {
    const char s[LAST_ERROR_MAX];
} dap_error_str_t;

#ifdef DAP_OS_WINDOWS
#define SIZE_64KB ( 1 << 16 )
DAP_STATIC_INLINE uint64_t dap_64k_rounddown(uint64_t a) {
    return a & ( ~(SIZE_64KB - 1) ); 
}
typedef struct iovec {
    void    *iov_base; /* Data */
    size_t  iov_len; /* ... and its' size */
} iovec_t;
#define HAVE_STRUCT_IOVEC 1
typedef HANDLE dap_file_handle_t;
typedef DWORD dap_errnum_t;
#define dap_fileclose CloseHandle
#else
typedef int dap_file_handle_t;
typedef struct iovec iovec_t;
typedef int dap_errnum_t;
#define INVALID_HANDLE_VALUE -1
#define dap_fileclose close
#endif

ssize_t dap_readv(dap_file_handle_t a_hf, iovec_t const *a_bufs, int a_bufs_num, dap_errnum_t *a_err);
ssize_t dap_writev(dap_file_handle_t a_hf, const char* a_filename, iovec_t const *a_bufs, int a_bufs_num, dap_errnum_t *a_err);

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
    uintptr_t ptr = (uintptr_t) DAP_REALLOC((uint8_t*)bptr, size + (alignment * 2) + sizeof(void *) );

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
#ifdef __ANDROID__
    return memalign(getpagesize(), size);
#elif !defined(DAP_OS_WINDOWS)
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
 * 25: Added node sign
 * 26: Change MSRLN to KYBER512
*/
#define DAP_PROTOCOL_VERSION          26
#define DAP_PROTOCOL_VERSION_DEFAULT  24 // used if version is not explicitly specified

#define DAP_CLIENT_PROTOCOL_VERSION   26

/* Crossplatform print formats for integers and others */

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
#define DAP_FORMAT_ERRNUM "lu"
#else
#define DAP_FORMAT_SOCKET "d"
#define DAP_FORMAT_HANDLE "d"
#define DAP_FORMAT_ERRNUM "d"
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

typedef uint8_t byte_t;
typedef int dap_spinlock_t;

#if defined (__GNUC__) || defined (__clang__)
#ifdef __MINGW_PRINTF_FORMAT
#define DAP_PRINTF_ATTR(format_index, args_index) \
    __attribute__ ((format (__MINGW_PRINTF_FORMAT, format_index, args_index)))
#else
#define DAP_PRINTF_ATTR(format_index, args_index) \
    __attribute__ ((format (printf, format_index, args_index)))
#endif
#else /* __GNUC__ */
#define DAP_PRINTF_ATTR(format_index, args_index)
#endif /* __GNUC__ */

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
#ifdef DAP_TPS_TEST
  L_TPS  = 15,
#endif
} dap_log_level_t;

typedef void *dap_interval_timer_t;
typedef void (*dap_timer_callback_t)(void *param);

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MAX_PATH
#define MAX_PATH 1024
#endif

#ifndef dap_max
#define dap_max(a,b)        \
({                          \
    __typeof__(a) _a = (a); \
    __typeof__(b) _b = (b); \
    _a > _b ? _a : _b;      \
})
#endif
#ifndef dap_min
#define dap_min(a,b)        \
({                          \
    __typeof__(a) _a = (a); \
    __typeof__(b) _b = (b); \
    _a < _b ? _a : _b;      \
})
#endif

#include <limits.h>

#define dap_abs(a) ( (a) >= 0 ? (a) : -(a) )

#define dap_maxval(v) _Generic( (v),                            \
    signed char : SCHAR_MAX,                                    \
           char : CHAR_MAX,       unsigned char : UCHAR_MAX,    \
          short : SHRT_MAX,      unsigned short : USHRT_MAX,    \
            int : INT_MAX,         unsigned int : UINT_MAX,     \
           long : LONG_MAX,       unsigned long : ULONG_MAX,    \
      long long : LLONG_MAX, unsigned long long : ULLONG_MAX,   \
        default : 0 )

#define dap_minval(v) _Generic( (v),\
    signed char : SCHAR_MIN,        \
           char : CHAR_MIN,         \
          short : SHRT_MIN,         \
            int : INT_MIN,          \
           long : LONG_MIN,         \
      long long : LLONG_MIN,        \
        default : 0 )

#define dap_maxuval(v) _Generic( (v),                           \
    signed char : UCHAR_MAX,                                    \
           char : UCHAR_MAX,       unsigned char : UCHAR_MAX,   \
          short : USHRT_MAX,      unsigned short : USHRT_MAX,   \
            int : UINT_MAX,         unsigned int : UINT_MAX,    \
           long : ULONG_MAX,       unsigned long : ULONG_MAX,   \
      long long : ULLONG_MAX, unsigned long long : ULLONG_MAX,  \
        default : 0 )

#define dap_is_signed(v) ( dap_minval(v) < 0 )
#define DAP_HUGE_SIGNED_TYPE long long int
#define DAP_HUGE_UNSIGNED_TYPE unsigned long long int
#define DAP_HUGE_NATURAL_TYPE long double
#define DAP_HUGE_SIGNED_SIZE __SIZEOF_LONG_LONG__
#define DAP_HUGE_NATURAL_SIZE __SIZEOF_LONG_DOUBLE__

#if !defined (DAP_CORE_TESTS) && (defined (__GNUC__) || defined (__clang__))
    #define dap_add(a,b)                                        \
    ({                                                          \
        __typeof__(a) _a = (a); __typeof__(b) _b = (b);         \
        if (!__builtin_add_overflow_p(_a,_b,_a)) {              \
            _a += b;                                            \
        }                                                       \
        _a;                                                     \
    })

    #define dap_sub(a,b)                                        \
    ({                                                          \
        __typeof__(a) _a = (a); __typeof__(b) _b = (b);         \
        if (!__builtin_sub_overflow_p(_a,_b,_a)) {              \
            _a -= b;                                            \
        }                                                       \
        _a;                                                     \
    })

    #define dap_mul(a,b)                                        \
    ({                                                          \
        __typeof__(a) _a = (a); __typeof__(b) _b = (b);         \
        if (!__builtin_mul_overflow_p(_a,_b,_a)) {              \
            _a *= b;                                            \
        }                                                       \
        _a;                                                     \
    })
#else
    #ifdef DAP_CORE_TESTS
        #define dap_add_builtin(a,b)                            \
        ({                                                      \
            __typeof__(a) _a = (a); __typeof__(b) _b = (b);     \
            if (!__builtin_add_overflow_p(_a,_b,_a)) {          \
                (_a += b);                                        \
            }                                                   \
            (_a);                                                 \
        })

        #define dap_sub_builtin(a,b)                            \
        ({                                                      \
            __typeof__(a) _a = (a); __typeof__(b) _b = (b);     \
            if (!__builtin_sub_overflow_p(_a,_b,_a)) {          \
                (_a -= b);                                        \
            }                                                   \
            (_a);                                                 \
        })

        #define dap_mul_builtin(a,b)                            \
        ({                                                      \
            __typeof__(a) _a = (a); __typeof__(b) _b = (b);     \
            if (!__builtin_mul_overflow_p(_a,_b,_a)) {          \
                (_a *= b);                                        \
            }                                                   \
            (_a);                                                 \
        })
    #endif
    
    #if ( DAP_HUGE_NATURAL_SIZE / DAP_HUGE_SIGNED_SIZE < 2 )
        #define dap_add(a,b)                                \
        ({                                                          \
            __typeof__(a) _a = (a); __typeof__(b) _b = (b);         \
            DAP_HUGE_SIGNED_TYPE l_koef = (DAP_HUGE_SIGNED_TYPE)pow(16, sizeof(a)); \
            DAP_HUGE_SIGNED_TYPE a_high = (_a) / l_koef; \
            DAP_HUGE_SIGNED_TYPE b_high = (_b) / l_koef; \
            \
            DAP_HUGE_SIGNED_TYPE a_min_high = dap_minval(_a) / l_koef; \
            DAP_HUGE_SIGNED_TYPE a_min_low = dap_minval(_a) - a_min_high * l_koef; \
            DAP_HUGE_SIGNED_TYPE a_max_high = dap_maxval(_a) / l_koef; \
            DAP_HUGE_SIGNED_TYPE a_max_low = dap_maxval(_a) - a_max_high * l_koef; \
            \
            DAP_HUGE_SIGNED_TYPE a_b_delta = (_a - a_high * l_koef) + (_b - b_high * l_koef); \
            DAP_HUGE_SIGNED_TYPE a_b_delta_hight = a_b_delta / l_koef; \
            DAP_HUGE_SIGNED_TYPE a_b_delta_low = a_b_delta - a_b_delta_hight * l_koef; \
            \
            DAP_HUGE_SIGNED_TYPE a_b_hight = a_high + b_high + a_b_delta_hight; \
            if (a_b_hight > 0 && a_b_delta_low < 0) { \
                a_b_hight--; \
                a_b_delta_low += l_koef; \
            } else if (a_b_hight < 0 && a_b_delta_low > 0) { \
                a_b_hight++; \
                a_b_delta_low -= l_koef; \
            } \
            if (!( \
                (a_b_hight < a_min_high) || \
                (a_b_hight > a_max_high) || \
                (a_b_hight == a_min_high && a_b_delta_low < a_min_low) \
            )) { (_a += _b); } \
            (_a); \
        })

        #define dap_sub(a,b)                                \
        ({                                                          \
            __typeof__(a) _a = (a); __typeof__(b) _b = (b);         \
            DAP_HUGE_SIGNED_TYPE l_koef = (DAP_HUGE_SIGNED_TYPE)pow(16.0, (double)sizeof(a)); \
            DAP_HUGE_SIGNED_TYPE a_high = (_a) / l_koef; \
            DAP_HUGE_SIGNED_TYPE b_high = (_b) / l_koef; \
            \
            DAP_HUGE_SIGNED_TYPE a_min_high = dap_minval(_a) / l_koef; \
            DAP_HUGE_SIGNED_TYPE a_min_low = dap_minval(_a) - a_min_high * l_koef; \
            DAP_HUGE_SIGNED_TYPE a_max_high = dap_maxval(_a) / l_koef; \
            DAP_HUGE_SIGNED_TYPE a_max_low = dap_maxval(_a) - a_max_high * l_koef; \
            \
            DAP_HUGE_SIGNED_TYPE a_b_delta = (_a - a_high * l_koef) - (_b - b_high * l_koef); \
            DAP_HUGE_SIGNED_TYPE a_b_delta_hight = a_b_delta / l_koef; \
            DAP_HUGE_SIGNED_TYPE a_b_delta_low = a_b_delta - a_b_delta_hight * l_koef; \
            \
            DAP_HUGE_SIGNED_TYPE a_b_hight = a_high - b_high + a_b_delta_hight; \
            if (a_b_hight > 0 && a_b_delta_low < 0) { \
                a_b_hight--; \
                a_b_delta_low += l_koef; \
            } else if (a_b_hight < 0 && a_b_delta_low > 0) { \
                a_b_hight++; \
                a_b_delta_low -= l_koef; \
            } \
            if (!( \
                (a_b_hight < a_min_high) || \
                (a_b_hight > a_max_high) || \
                (a_b_hight == a_min_high && a_b_delta_low < a_min_low) \
            )) { (_a -= _b); } \
            (_a); \
        })
        
        #define dap_mul(a,b)                                \
        ({                                                  \
            __typeof__(a) _a = (a); __typeof__(b) _b = (b); \
            bool a_negative = _a < 0; \
            bool b_negative = _b < 0; \
            DAP_HUGE_SIGNED_TYPE l_koef = (DAP_HUGE_SIGNED_TYPE)pow(16.0, sizeof(_a)); \
            DAP_HUGE_UNSIGNED_TYPE a_high = llabs((_a) / l_koef); \
            DAP_HUGE_UNSIGNED_TYPE b_high = llabs((_b) / l_koef); \
            DAP_HUGE_SIGNED_TYPE a_high_not_abs = (_a) / l_koef; \
            DAP_HUGE_SIGNED_TYPE b_high_not_abs = (_b) / l_koef; \
            DAP_HUGE_UNSIGNED_TYPE a_b_high_hight = a_high * b_high; \
            DAP_HUGE_UNSIGNED_TYPE a_low = llabs(_a - a_high_not_abs * l_koef); \
            DAP_HUGE_UNSIGNED_TYPE b_low = llabs(_b - b_high_not_abs * l_koef); \
            \
            DAP_HUGE_UNSIGNED_TYPE a_min_high = llabs(dap_minval(_a) / l_koef); \
            DAP_HUGE_UNSIGNED_TYPE a_min_low = llabs(dap_minval(_a) + a_min_high * l_koef); \
            \
            DAP_HUGE_UNSIGNED_TYPE a_max_high = dap_maxval(_a) / l_koef; \
            DAP_HUGE_UNSIGNED_TYPE a_max_low = dap_maxval(_a) - a_max_high * l_koef; \
            \
            DAP_HUGE_UNSIGNED_TYPE a_b_delta = a_low * b_low; \
            DAP_HUGE_UNSIGNED_TYPE a_b_delta_hight = a_b_delta / l_koef; \
            DAP_HUGE_UNSIGNED_TYPE a_b_delta_low = a_b_delta - a_b_delta_hight * l_koef; \
            \
            DAP_HUGE_UNSIGNED_TYPE a_b_hight = a_high * b_low + b_high * a_low +  a_b_delta_hight; \
            if (!( \
                (a_b_high_hight > a_min_high / l_koef) || \
                (a_b_high_hight > a_max_high / l_koef) || \
                (a_negative != b_negative && a_b_hight > a_min_high) || \
                (a_negative == b_negative && a_b_hight > a_max_high) || \
                (a_negative != b_negative && a_b_hight == a_min_high && a_b_delta_low > a_min_low) \
            )) { (_a *= _b); } \
            (_a); \
        })
    #else
        #define dap_add(a,b)                                \
        ({                                                          \
            __typeof__(a) _a = (a); __typeof__(b) _b = (b);         \
            if (!( \
                (((DAP_HUGE_NATURAL_TYPE)_b > 0 && (DAP_HUGE_NATURAL_TYPE)_a > (DAP_HUGE_NATURAL_TYPE)dap_maxval(_a) - (DAP_HUGE_NATURAL_TYPE)_b) || \
                ((DAP_HUGE_NATURAL_TYPE)_b < 0 && (DAP_HUGE_NATURAL_TYPE)_a < (DAP_HUGE_NATURAL_TYPE)dap_minval(_a) - (DAP_HUGE_NATURAL_TYPE)_b)) \
            )) { (_a += _b); } \
            (_a); \
        })
    
        #define dap_sub(a,b)                                \
        ({                                                          \
            __typeof__(a) _a = (a); __typeof__(b) _b = (b);         \
            if (!( \
                ((DAP_HUGE_NATURAL_TYPE)_b < 0 && (DAP_HUGE_NATURAL_TYPE)_a > (DAP_HUGE_NATURAL_TYPE)dap_maxval(_a) + (DAP_HUGE_NATURAL_TYPE)_b) || \
                ((DAP_HUGE_NATURAL_TYPE)_b > 0 && (DAP_HUGE_NATURAL_TYPE)_a < (DAP_HUGE_NATURAL_TYPE)dap_minval(_a) + (DAP_HUGE_NATURAL_TYPE)_b) \
            )) { (_a -= _b); } \
            (_a); \
        })
        
        #define dap_mul(a,b)                                \
        ({                                                  \
            __typeof__(a) _a = (a); __typeof__(b) _b = (b); \
            if (!( \
                /*_a positive*/\
                ((DAP_HUGE_NATURAL_TYPE)_a > 0 && ( \
                    ((DAP_HUGE_NATURAL_TYPE)_b > 0 && (DAP_HUGE_NATURAL_TYPE)_a > (DAP_HUGE_NATURAL_TYPE)((DAP_HUGE_NATURAL_TYPE)dap_maxval(_a) / (DAP_HUGE_NATURAL_TYPE)_b)) || \
                    ((DAP_HUGE_NATURAL_TYPE)_b < 0 && ((DAP_HUGE_NATURAL_TYPE)_b < (DAP_HUGE_NATURAL_TYPE)((DAP_HUGE_NATURAL_TYPE)dap_minval(_a) / (DAP_HUGE_NATURAL_TYPE)_a))))\
                ) || \
                /*_a negative*/\
                (_a <= 0 && ( \
                    ((DAP_HUGE_NATURAL_TYPE)_b > 0 && (DAP_HUGE_NATURAL_TYPE)_a < (DAP_HUGE_NATURAL_TYPE)((DAP_HUGE_NATURAL_TYPE)dap_minval(_a) / (DAP_HUGE_NATURAL_TYPE)_b)) || \
                    (_a != 0 && (DAP_HUGE_NATURAL_TYPE)_b < 0 && (DAP_HUGE_NATURAL_TYPE)_b < (DAP_HUGE_NATURAL_TYPE)((DAP_HUGE_NATURAL_TYPE)dap_maxval(_a) / (DAP_HUGE_NATURAL_TYPE)_a))) \
                ) \
            )) { (_a *= _b); } \
            _a; \
        })
    #endif
#endif


static const DAP_ALIGNED(16) uint16_t htoa_lut256[ 256 ] = {

  0x3030, 0x3130, 0x3230, 0x3330, 0x3430, 0x3530, 0x3630, 0x3730, 0x3830, 0x3930, 0x4130, 0x4230, 0x4330, 0x4430, 0x4530,
  0x4630, 0x3031, 0x3131, 0x3231, 0x3331, 0x3431, 0x3531, 0x3631, 0x3731, 0x3831, 0x3931, 0x4131, 0x4231, 0x4331, 0x4431,
  0x4531, 0x4631, 0x3032, 0x3132, 0x3232, 0x3332, 0x3432, 0x3532, 0x3632, 0x3732, 0x3832, 0x3932, 0x4132, 0x4232, 0x4332,
  0x4432, 0x4532, 0x4632, 0x3033, 0x3133, 0x3233, 0x3333, 0x3433, 0x3533, 0x3633, 0x3733, 0x3833, 0x3933, 0x4133, 0x4233,
  0x4333, 0x4433, 0x4533, 0x4633, 0x3034, 0x3134, 0x3234, 0x3334, 0x3434, 0x3534, 0x3634, 0x3734, 0x3834, 0x3934, 0x4134,
  0x4234, 0x4334, 0x4434, 0x4534, 0x4634, 0x3035, 0x3135, 0x3235, 0x3335, 0x3435, 0x3535, 0x3635, 0x3735, 0x3835, 0x3935,
  0x4135, 0x4235, 0x4335, 0x4435, 0x4535, 0x4635, 0x3036, 0x3136, 0x3236, 0x3336, 0x3436, 0x3536, 0x3636, 0x3736, 0x3836,
  0x3936, 0x4136, 0x4236, 0x4336, 0x4436, 0x4536, 0x4636, 0x3037, 0x3137, 0x3237, 0x3337, 0x3437, 0x3537, 0x3637, 0x3737,
  0x3837, 0x3937, 0x4137, 0x4237, 0x4337, 0x4437, 0x4537, 0x4637, 0x3038, 0x3138, 0x3238, 0x3338, 0x3438, 0x3538, 0x3638,
  0x3738, 0x3838, 0x3938, 0x4138, 0x4238, 0x4338, 0x4438, 0x4538, 0x4638, 0x3039, 0x3139, 0x3239, 0x3339, 0x3439, 0x3539,
  0x3639, 0x3739, 0x3839, 0x3939, 0x4139, 0x4239, 0x4339, 0x4439, 0x4539, 0x4639, 0x3041, 0x3141, 0x3241, 0x3341, 0x3441,
  0x3541, 0x3641, 0x3741, 0x3841, 0x3941, 0x4141, 0x4241, 0x4341, 0x4441, 0x4541, 0x4641, 0x3042, 0x3142, 0x3242, 0x3342,
  0x3442, 0x3542, 0x3642, 0x3742, 0x3842, 0x3942, 0x4142, 0x4242, 0x4342, 0x4442, 0x4542, 0x4642, 0x3043, 0x3143, 0x3243,
  0x3343, 0x3443, 0x3543, 0x3643, 0x3743, 0x3843, 0x3943, 0x4143, 0x4243, 0x4343, 0x4443, 0x4543, 0x4643, 0x3044, 0x3144,
  0x3244, 0x3344, 0x3444, 0x3544, 0x3644, 0x3744, 0x3844, 0x3944, 0x4144, 0x4244, 0x4344, 0x4444, 0x4544, 0x4644, 0x3045,
  0x3145, 0x3245, 0x3345, 0x3445, 0x3545, 0x3645, 0x3745, 0x3845, 0x3945, 0x4145, 0x4245, 0x4345, 0x4445, 0x4545, 0x4645,
  0x3046, 0x3146, 0x3246, 0x3346, 0x3446, 0x3546, 0x3646, 0x3746, 0x3846, 0x3946, 0x4146, 0x4246, 0x4346, 0x4446, 0x4546,
  0x4646
};

#define dap_htoa64( out, in, len ) \
{\
  uintptr_t  _len = len, _shift = 0; \
  byte_t *__restrict _in  = (byte_t *__restrict)in, *__restrict _out = (byte_t *__restrict)out;\
\
  while ( _len ) {\
    uint64_t _val; \
    memcpy(&_val, _in, sizeof(uint64_t));\
    uint16_t _out2[] = { \
        htoa_lut256[  _val & 0x00000000000000FF ], htoa_lut256[ (_val & 0x000000000000FF00) >> 8 ], \
        htoa_lut256[ (_val & 0x0000000000FF0000) >> 16 ], htoa_lut256[ (_val & 0x00000000FF000000) >> 24 ], \
        htoa_lut256[ (_val & 0x000000FF00000000) >> 32 ], htoa_lut256[ (_val & 0x0000FF0000000000) >> 40 ], \
        htoa_lut256[ (_val & 0x00FF000000000000) >> 48 ], htoa_lut256[ (_val & 0xFF00000000000000) >> 56 ] \
    }; \
    memcpy(_out + _shift, _out2, 16); \
    _in += 8;\
    _len -= 8;\
    _shift += 16;\
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
#define dap_ascii_isprint(c) (s_ascii_table_data[(unsigned char) (c)] & DAP_ASCII_PRINT)
#define dap_ascii_isxdigit(c) (s_ascii_table_data[(unsigned char) (c)] & DAP_ASCII_XDIGIT)

#define DAP_FLAG_ADD(a, flag) ((a) | (flag))
#define DAP_FLAG_REMOVE(a, flag) ((a) & ~(flag))
#define DAP_FLAG_CHECK(a, flag) ((a) & (flag))

static void * ( *const volatile memset_safe ) (void*, int, size_t) = memset;

DAP_STATIC_INLINE void DAP_AtomicLock( dap_spinlock_t *lock )
{
    __sync_lock_test_and_set(lock, 1);
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
int dap_common_init( const char *console_title, const char *a_log_file );
int wdap_common_init( const char *console_title, const wchar_t *a_wlog_file );

typedef enum 
{
    LOGGER_OUTPUT_NONE,
    LOGGER_OUTPUT_STDOUT,
    LOGGER_OUTPUT_STDERR,
    LOGGER_OUTPUT_FD,

    #ifdef ANDROID
        LOGGER_OUTPUT_ALOG,
    #endif

} LOGGER_EXTERNAL_OUTPUT;

void dap_log_set_external_output (LOGGER_EXTERNAL_OUTPUT output, void *param);

void dap_common_deinit(void);

// set max items in log list
void dap_log_set_max_item(unsigned int a_max);
// get logs from list
char *dap_log_get_item(time_t a_start_time, int a_limit);

DAP_PRINTF_ATTR(5, 6) void _log_it(const char * func_name, int line_num, const char * log_tag, enum dap_log_level, const char * format, ... );
#define log_it_fl(_log_level, ...) _log_it(__FUNCTION__, __LINE__, LOG_TAG, _log_level, ##__VA_ARGS__)
#define log_it(_log_level, ...) _log_level == L_CRITICAL ? _log_it(__FUNCTION__, __LINE__, LOG_TAG, _log_level, ##__VA_ARGS__) : _log_it(NULL, 0, LOG_TAG, _log_level, ##__VA_ARGS__)
#define debug_if(flg, lvl, ...) _log_it(NULL, 0, ((flg) ? LOG_TAG : NULL), (lvl), ##__VA_ARGS__)

char *dap_dump_hex(byte_t *a_data, size_t a_size);

#ifdef DAP_SYS_DEBUG
void    _log_it_ext (const char *, unsigned, enum dap_log_level, const char * format, ... );
void    _dump_it    (const char *, unsigned, const char *a_var_name, const void *src, unsigned short srclen);
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

dap_error_str_t dap_strerror_(long long err);
#define dap_strerror(e) dap_strerror_(e).s

#ifdef DAP_OS_WINDOWS
dap_error_str_t dap_str_ntstatus_(DWORD err);
#define dap_str_ntstatus(e) dap_str_ntstatus_(e).s
#endif
void dap_log_level_set(enum dap_log_level ll);
enum dap_log_level dap_log_level_get(void);
void dap_set_log_tag_width(size_t width);

const char * dap_get_appname();
void dap_set_appname(const char * a_appname);

#define INT_DIGITS 19   /* enough for 64 bit integer */
typedef union dap_maxint_str {
    const char s[INT_DIGITS + 2];
} dap_maxint_str_t;
dap_maxint_str_t dap_itoa_(long long i);
#define dap_itoa(i) (char*)dap_itoa_(i).s

unsigned dap_gettid();

int get_select_breaker(void);
int send_select_break(void);
int exec_with_ret(char**, const char*);
char* exec_with_ret_multistring(const char* a_cmd);
char * dap_random_string_create_alloc(size_t a_length);
void dap_random_string_fill(char *str, size_t length);

size_t dap_hex2bin(uint8_t *a_out, const char *a_in, size_t a_len);
size_t dap_bin2hex(char *a_out, const void *a_in, size_t a_len);
int dap_is_hex_string(const char *a_in, size_t a_len);
void dap_digit_from_string(const char *num_str, void *raw, size_t raw_len);
void dap_digit_from_string2(const char *num_str, void *raw, size_t raw_len);

dap_interval_timer_t dap_interval_timer_create(unsigned int a_msec, dap_timer_callback_t a_callback, void *a_param);
void dap_interval_timer_delete(dap_interval_timer_t a_timer);
int dap_interval_timer_disable(dap_interval_timer_t a_timer);
void dap_interval_timer_init();
void dap_interval_timer_deinit();

static inline void *dap_mempcpy(void *a_dest, const void *a_src, size_t n)
{
    return n ? (byte_t*)memcpy(a_dest, a_src, n) + n : a_dest;
}

DAP_STATIC_INLINE int dap_is_letter(char c) { return dap_ascii_isalpha(c); }
DAP_STATIC_INLINE int dap_is_alpha(char c) { return dap_ascii_isalnum(c); }
DAP_STATIC_INLINE int dap_is_digit(char c) { return dap_ascii_isdigit(c); }
DAP_STATIC_INLINE int dap_is_xdigit(char c) {return dap_ascii_isxdigit(c);}
DAP_STATIC_INLINE int dap_is_alpha_and_(char c) { return dap_is_alpha(c) || c == '_'; }
char **dap_parse_items(const char *a_str, char a_delimiter, int *a_count, const int a_only_digit);

static inline const char *dap_get_arch()
{ //Get current architecture, detectx nearly every architecture. Coded by Freak
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

DAP_STATIC_INLINE int dap_stream_node_addr_from_str(dap_stream_node_addr_t *a_addr, const char *a_addr_str)
{
    if (!a_addr || !a_addr_str)
        return -2;
    return sscanf(a_addr_str, NODE_ADDR_FP_STR, NODE_ADDR_FPS_ARGS(a_addr)) == 4
        || sscanf(a_addr_str, "0x%016" DAP_UINT64_FORMAT_x, (uint64_t*)a_addr) == 1
        ? 0 : -1;
}

DAP_STATIC_INLINE bool dap_stream_node_addr_is_blank(dap_stream_node_addr_t *a_addr) { return !a_addr->uint64; }

#define DAP_NODE_ADDR_LEN 23
typedef union dap_node_addr_str {
    const char s[DAP_NODE_ADDR_LEN];
} dap_node_addr_str_t;
dap_node_addr_str_t dap_stream_node_addr_to_str_static_(dap_stream_node_addr_t a_address);
#define dap_stream_node_addr_to_str_static(a) dap_stream_node_addr_to_str_static_(a).s

void dap_common_enable_cleaner_log(size_t a_timeout, size_t a_max_size);
