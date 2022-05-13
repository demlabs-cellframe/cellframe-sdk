/* https://en.wikipedia.org/wiki/Operating_system_abstraction_layer */

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

#include "internals.h"

#if defined(_WIN32) || defined(_WIN64)

#include <winioctl.h>

static int waitstatus2errcode(DWORD result) {
  switch (result) {
  case WAIT_OBJECT_0:
    return MDBX_SUCCESS;
  case WAIT_FAILED:
    return (int)GetLastError();
  case WAIT_ABANDONED:
    return ERROR_ABANDONED_WAIT_0;
  case WAIT_IO_COMPLETION:
    return ERROR_USER_APC;
  case WAIT_TIMEOUT:
    return ERROR_TIMEOUT;
  default:
    return ERROR_UNHANDLED_ERROR;
  }
}

/* Map a result from an NTAPI call to WIN32 error code. */
static int ntstatus2errcode(NTSTATUS status) {
  DWORD dummy;
  OVERLAPPED ov;
  memset(&ov, 0, sizeof(ov));
  ov.Internal = status;
  return GetOverlappedResult(NULL, &ov, &dummy, FALSE) ? MDBX_SUCCESS
                                                       : (int)GetLastError();
}

/* We use native NT APIs to setup the memory map, so that we can
 * let the DB file grow incrementally instead of always preallocating
 * the full size. These APIs are defined in <wdm.h> and <ntifs.h>
 * but those headers are meant for driver-level development and
 * conflict with the regular user-level headers, so we explicitly
 * declare them here. Using these APIs also means we must link to
 * ntdll.dll, which is not linked by default in user code. */

extern NTSTATUS NTAPI NtCreateSection(
    OUT PHANDLE SectionHandle, IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL PLARGE_INTEGER MaximumSize, IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes, IN OPTIONAL HANDLE FileHandle);

typedef struct _SECTION_BASIC_INFORMATION {
  ULONG Unknown;
  ULONG SectionAttributes;
  LARGE_INTEGER SectionSize;
} SECTION_BASIC_INFORMATION, *PSECTION_BASIC_INFORMATION;

extern NTSTATUS NTAPI NtMapViewOfSection(
    IN HANDLE SectionHandle, IN HANDLE ProcessHandle, IN OUT PVOID *BaseAddress,
    IN ULONG_PTR ZeroBits, IN SIZE_T CommitSize,
    IN OUT OPTIONAL PLARGE_INTEGER SectionOffset, IN OUT PSIZE_T ViewSize,
    IN SECTION_INHERIT InheritDisposition, IN ULONG AllocationType,
    IN ULONG Win32Protect);

extern NTSTATUS NTAPI NtUnmapViewOfSection(IN HANDLE ProcessHandle,
                                           IN OPTIONAL PVOID BaseAddress);

extern NTSTATUS NTAPI NtClose(HANDLE Handle);

extern NTSTATUS NTAPI NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle, IN OUT PVOID *BaseAddress, IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);

extern NTSTATUS NTAPI NtFreeVirtualMemory(IN HANDLE ProcessHandle,
                                          IN PVOID *BaseAddress,
                                          IN OUT PSIZE_T RegionSize,
                                          IN ULONG FreeType);

#ifndef WOF_CURRENT_VERSION
typedef struct _WOF_EXTERNAL_INFO {
  DWORD Version;
  DWORD Provider;
} WOF_EXTERNAL_INFO, *PWOF_EXTERNAL_INFO;
#endif /* WOF_CURRENT_VERSION */

#ifndef WIM_PROVIDER_CURRENT_VERSION
#define WIM_PROVIDER_HASH_SIZE 20

typedef struct _WIM_PROVIDER_EXTERNAL_INFO {
  DWORD Version;
  DWORD Flags;
  LARGE_INTEGER DataSourceId;
  BYTE ResourceHash[WIM_PROVIDER_HASH_SIZE];
} WIM_PROVIDER_EXTERNAL_INFO, *PWIM_PROVIDER_EXTERNAL_INFO;
#endif /* WIM_PROVIDER_CURRENT_VERSION */

#ifndef FILE_PROVIDER_CURRENT_VERSION
typedef struct _FILE_PROVIDER_EXTERNAL_INFO_V1 {
  ULONG Version;
  ULONG Algorithm;
  ULONG Flags;
} FILE_PROVIDER_EXTERNAL_INFO_V1, *PFILE_PROVIDER_EXTERNAL_INFO_V1;
#endif /* FILE_PROVIDER_CURRENT_VERSION */

#ifndef STATUS_OBJECT_NOT_EXTERNALLY_BACKED
#define STATUS_OBJECT_NOT_EXTERNALLY_BACKED ((NTSTATUS)0xC000046DL)
#endif
#ifndef STATUS_INVALID_DEVICE_REQUEST
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xC0000010L)
#endif
#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BBL)
#endif

#ifndef FILE_DEVICE_FILE_SYSTEM
#define FILE_DEVICE_FILE_SYSTEM 0x00000009
#endif

#ifndef FSCTL_GET_EXTERNAL_BACKING
#define FSCTL_GET_EXTERNAL_BACKING                                             \
  CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 196, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#ifndef ERROR_NOT_CAPABLE
#define ERROR_NOT_CAPABLE 775L
#endif

#endif /* _WIN32 || _WIN64 */

/*----------------------------------------------------------------------------*/

#if defined(__UCLIBC__)
__extern_C void __assert(const char *, const char *, unsigned int, const char *)
#ifdef __THROW
    __THROW
#else
    __nothrow
#endif /* __THROW */
    MDBX_NORETURN;
#define __assert_fail(assertion, file, line, function)                         \
  __assert(assertion, file, line, function)

#elif _POSIX_C_SOURCE > 200212 &&                                              \
    /* workaround for avoid musl libc wrong prototype */ (                     \
        defined(__GLIBC__) || defined(__GNU_LIBRARY__))
/* Prototype should match libc runtime. ISO POSIX (2003) & LSB 1.x-3.x */
__extern_C void __assert_fail(const char *assertion, const char *file,
                              unsigned line, const char *function)
#ifdef __THROW
    __THROW
#else
    __nothrow
#endif /* __THROW */
    MDBX_NORETURN;

#elif defined(__APPLE__) || defined(__MACH__)
__extern_C void __assert_rtn(const char *function, const char *file, int line,
                             const char *assertion) /* __nothrow */
#ifdef __dead2
    __dead2
#else
    MDBX_NORETURN
#endif /* __dead2 */
#ifdef __disable_tail_calls
    __disable_tail_calls
#endif /* __disable_tail_calls */
    ;

#define __assert_fail(assertion, file, line, function)                         \
  __assert_rtn(function, file, line, assertion)
#elif defined(__sun) || defined(__SVR4) || defined(__svr4__)
__extern_C void __assert_c99(const char *assection, const char *file, int line,
                             const char *function) MDBX_NORETURN;
#define __assert_fail(assertion, file, line, function)                         \
  __assert_c99(assertion, file, line, function)
#elif defined(__OpenBSD__)
__extern_C __dead void __assert2(const char *file, int line,
                                 const char *function,
                                 const char *assertion) /* __nothrow */;
#define __assert_fail(assertion, file, line, function)                         \
  __assert2(file, line, function, assertion)
#elif defined(__NetBSD__)
__extern_C __dead void __assert13(const char *file, int line,
                                  const char *function,
                                  const char *assertion) /* __nothrow */;
#define __assert_fail(assertion, file, line, function)                         \
  __assert13(file, line, function, assertion)
#elif defined(__FreeBSD__) || defined(__BSD__) || defined(__bsdi__) ||         \
    defined(__DragonFly__)
__extern_C void __assert(const char *function, const char *file, int line,
                         const char *assertion) /* __nothrow */
#ifdef __dead2
    __dead2
#else
    MDBX_NORETURN
#endif /* __dead2 */
#ifdef __disable_tail_calls
    __disable_tail_calls
#endif /* __disable_tail_calls */
    ;
#define __assert_fail(assertion, file, line, function)                         \
  __assert(function, file, line, assertion)

#endif /* __assert_fail */

#if !defined(__ANDROID_API__) || MDBX_DEBUG

__cold void mdbx_assert_fail(const MDBX_env *env, const char *msg,
                             const char *func, int line) {
#if MDBX_DEBUG
  if (env && env->me_assert_func) {
    env->me_assert_func(env, msg, func, line);
    return;
  }
#else
  (void)env;
#endif /* MDBX_DEBUG */

  if (mdbx_debug_logger)
    mdbx_debug_log(MDBX_LOG_FATAL, func, line, "assert: %s\n", msg);
  else {
#if defined(_WIN32) || defined(_WIN64)
    char *message = nullptr;
    const int num = mdbx_asprintf(&message, "\r\nMDBX-ASSERTION: %s, %s:%u",
                                  msg, func ? func : "unknown", line);
    if (num < 1 || !message)
      message = "<troubles with assertion-message preparation>";
    OutputDebugStringA(message);
    if (IsDebuggerPresent())
      DebugBreak();
#elif defined(__ANDROID_API__)
    __android_log_assert(msg, "mdbx", "%s:%u", func, line);
#else
    __assert_fail(msg, "mdbx", line, func);
#endif
  }

#if defined(_WIN32) || defined(_WIN64)
  FatalExit(ERROR_UNHANDLED_ERROR);
#else
  abort();
#endif
}

#endif /* __ANDROID_API__ || MDBX_DEBUG */

__cold void mdbx_panic(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);

  char *message = nullptr;
  const int num = mdbx_vasprintf(&message, fmt, ap);
  va_end(ap);
  const char *const const_message =
      (num < 1 || !message) ? "<troubles with panic-message preparation>"
                            : message;

#if defined(_WIN32) || defined(_WIN64)
  OutputDebugStringA("\r\nMDBX-PANIC: ");
  OutputDebugStringA(const_message);
  if (IsDebuggerPresent())
    DebugBreak();
  FatalExit(ERROR_UNHANDLED_ERROR);
#else
#if defined(__ANDROID_API__)
  __android_log_assert("panic", "mdbx", "%s", const_message);
#else
  __assert_fail(const_message, "mdbx", 0, "panic");
#endif /* __ANDROID_API__ */
  abort();
#endif
}

/*----------------------------------------------------------------------------*/

#ifndef mdbx_vasprintf
MDBX_INTERNAL_FUNC int mdbx_vasprintf(char **strp, const char *fmt,
                                      va_list ap) {
  va_list ones;
  va_copy(ones, ap);
  int needed = vsnprintf(nullptr, 0, fmt, ap);

  if (unlikely(needed < 0 || needed >= INT_MAX)) {
    *strp = nullptr;
    va_end(ones);
    return needed;
  }

  *strp = mdbx_malloc(needed + 1);
  if (unlikely(*strp == nullptr)) {
    va_end(ones);
#if defined(_WIN32) || defined(_WIN64)
    SetLastError(MDBX_ENOMEM);
#else
    errno = MDBX_ENOMEM;
#endif
    return -1;
  }

  int actual = vsnprintf(*strp, needed + 1, fmt, ones);
  va_end(ones);

  assert(actual == needed);
  if (unlikely(actual < 0)) {
    mdbx_free(*strp);
    *strp = nullptr;
  }
  return actual;
}
#endif /* mdbx_vasprintf */

#ifndef mdbx_asprintf
MDBX_INTERNAL_FUNC int mdbx_asprintf(char **strp, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int rc = mdbx_vasprintf(strp, fmt, ap);
  va_end(ap);
  return rc;
}
#endif /* mdbx_asprintf */

#ifndef mdbx_memalign_alloc
MDBX_INTERNAL_FUNC int mdbx_memalign_alloc(size_t alignment, size_t bytes,
                                           void **result) {
  assert(is_powerof2(alignment) && alignment >= sizeof(void *));
#if defined(_WIN32) || defined(_WIN64)
  (void)alignment;
  *result = VirtualAlloc(NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  return *result ? MDBX_SUCCESS : MDBX_ENOMEM /* ERROR_OUTOFMEMORY */;
#elif defined(_ISOC11_SOURCE)
  *result = aligned_alloc(alignment, ceil_powerof2(bytes, alignment));
  return *result ? MDBX_SUCCESS : errno;
#elif _POSIX_VERSION >= 200112L &&                                             \
    (!defined(__ANDROID_API__) || __ANDROID_API__ >= 17)
  *result = nullptr;
  return posix_memalign(result, alignment, bytes);
#elif __GLIBC_PREREQ(2, 16) || __STDC_VERSION__ >= 201112L
  *result = memalign(alignment, bytes);
  return *result ? MDBX_SUCCESS : errno;
#else
#error FIXME
#endif
}
#endif /* mdbx_memalign_alloc */

#ifndef mdbx_memalign_free
MDBX_INTERNAL_FUNC void mdbx_memalign_free(void *ptr) {
#if defined(_WIN32) || defined(_WIN64)
  VirtualFree(ptr, 0, MEM_RELEASE);
#else
  mdbx_free(ptr);
#endif
}
#endif /* mdbx_memalign_free */

#ifndef mdbx_strdup
char *mdbx_strdup(const char *str) {
  if (!str)
    return NULL;
  size_t bytes = strlen(str) + 1;
  char *dup = mdbx_malloc(bytes);
  if (dup)
    memcpy(dup, str, bytes);
  return dup;
}
#endif /* mdbx_strdup */

/*----------------------------------------------------------------------------*/

MDBX_INTERNAL_FUNC int mdbx_condpair_init(mdbx_condpair_t *condpair) {
  int rc;
  memset(condpair, 0, sizeof(mdbx_condpair_t));
#if defined(_WIN32) || defined(_WIN64)
  if ((condpair->mutex = CreateMutexW(NULL, FALSE, NULL)) == NULL) {
    rc = (int)GetLastError();
    goto bailout_mutex;
  }
  if ((condpair->event[0] = CreateEventW(NULL, FALSE, FALSE, NULL)) == NULL) {
    rc = (int)GetLastError();
    goto bailout_event;
  }
  if ((condpair->event[1] = CreateEventW(NULL, FALSE, FALSE, NULL)) != NULL)
    return MDBX_SUCCESS;

  rc = (int)GetLastError();
  (void)CloseHandle(condpair->event[0]);
bailout_event:
  (void)CloseHandle(condpair->mutex);
#else
  rc = pthread_mutex_init(&condpair->mutex, NULL);
  if (unlikely(rc != 0))
    goto bailout_mutex;
  rc = pthread_cond_init(&condpair->cond[0], NULL);
  if (unlikely(rc != 0))
    goto bailout_cond;
  rc = pthread_cond_init(&condpair->cond[1], NULL);
  if (likely(rc == 0))
    return MDBX_SUCCESS;

  (void)pthread_cond_destroy(&condpair->cond[0]);
bailout_cond:
  (void)pthread_mutex_destroy(&condpair->mutex);
#endif
bailout_mutex:
  memset(condpair, 0, sizeof(mdbx_condpair_t));
  return rc;
}

MDBX_INTERNAL_FUNC int mdbx_condpair_destroy(mdbx_condpair_t *condpair) {
#if defined(_WIN32) || defined(_WIN64)
  int rc = CloseHandle(condpair->mutex) ? MDBX_SUCCESS : (int)GetLastError();
  rc = CloseHandle(condpair->event[0]) ? rc : (int)GetLastError();
  rc = CloseHandle(condpair->event[1]) ? rc : (int)GetLastError();
#else
  int err, rc = pthread_mutex_destroy(&condpair->mutex);
  rc = (err = pthread_cond_destroy(&condpair->cond[0])) ? err : rc;
  rc = (err = pthread_cond_destroy(&condpair->cond[1])) ? err : rc;
#endif
  memset(condpair, 0, sizeof(mdbx_condpair_t));
  return rc;
}

MDBX_INTERNAL_FUNC int mdbx_condpair_lock(mdbx_condpair_t *condpair) {
#if defined(_WIN32) || defined(_WIN64)
  DWORD code = WaitForSingleObject(condpair->mutex, INFINITE);
  return waitstatus2errcode(code);
#else
  return mdbx_pthread_mutex_lock(&condpair->mutex);
#endif
}

MDBX_INTERNAL_FUNC int mdbx_condpair_unlock(mdbx_condpair_t *condpair) {
#if defined(_WIN32) || defined(_WIN64)
  return ReleaseMutex(condpair->mutex) ? MDBX_SUCCESS : (int)GetLastError();
#else
  return pthread_mutex_unlock(&condpair->mutex);
#endif
}

MDBX_INTERNAL_FUNC int mdbx_condpair_signal(mdbx_condpair_t *condpair,
                                            bool part) {
#if defined(_WIN32) || defined(_WIN64)
  return SetEvent(condpair->event[part]) ? MDBX_SUCCESS : (int)GetLastError();
#else
  return pthread_cond_signal(&condpair->cond[part]);
#endif
}

MDBX_INTERNAL_FUNC int mdbx_condpair_wait(mdbx_condpair_t *condpair,
                                          bool part) {
#if defined(_WIN32) || defined(_WIN64)
  DWORD code = SignalObjectAndWait(condpair->mutex, condpair->event[part],
                                   INFINITE, FALSE);
  if (code == WAIT_OBJECT_0) {
    code = WaitForSingleObject(condpair->mutex, INFINITE);
    if (code == WAIT_OBJECT_0)
      return MDBX_SUCCESS;
  }
  return waitstatus2errcode(code);
#else
  return pthread_cond_wait(&condpair->cond[part], &condpair->mutex);
#endif
}

/*----------------------------------------------------------------------------*/

MDBX_INTERNAL_FUNC int mdbx_fastmutex_init(mdbx_fastmutex_t *fastmutex) {
#if defined(_WIN32) || defined(_WIN64)
  InitializeCriticalSection(fastmutex);
  return MDBX_SUCCESS;
#else
  return pthread_mutex_init(fastmutex, NULL);
#endif
}

MDBX_INTERNAL_FUNC int mdbx_fastmutex_destroy(mdbx_fastmutex_t *fastmutex) {
#if defined(_WIN32) || defined(_WIN64)
  DeleteCriticalSection(fastmutex);
  return MDBX_SUCCESS;
#else
  return pthread_mutex_destroy(fastmutex);
#endif
}

MDBX_INTERNAL_FUNC int mdbx_fastmutex_acquire(mdbx_fastmutex_t *fastmutex) {
#if defined(_WIN32) || defined(_WIN64)
  __try {
    EnterCriticalSection(fastmutex);
  } __except (
      (GetExceptionCode() ==
       0xC0000194 /* STATUS_POSSIBLE_DEADLOCK / EXCEPTION_POSSIBLE_DEADLOCK */)
          ? EXCEPTION_EXECUTE_HANDLER
          : EXCEPTION_CONTINUE_SEARCH) {
    return ERROR_POSSIBLE_DEADLOCK;
  }
  return MDBX_SUCCESS;
#else
  return mdbx_pthread_mutex_lock(fastmutex);
#endif
}

MDBX_INTERNAL_FUNC int mdbx_fastmutex_release(mdbx_fastmutex_t *fastmutex) {
#if defined(_WIN32) || defined(_WIN64)
  LeaveCriticalSection(fastmutex);
  return MDBX_SUCCESS;
#else
  return pthread_mutex_unlock(fastmutex);
#endif
}

/*----------------------------------------------------------------------------*/

MDBX_INTERNAL_FUNC int mdbx_removefile(const char *pathname) {
#if defined(_WIN32) || defined(_WIN64)
  const size_t wlen = mbstowcs(nullptr, pathname, INT_MAX);
  if (wlen < 1 || wlen > /* MAX_PATH */ INT16_MAX)
    return ERROR_INVALID_NAME;
  wchar_t *const pathnameW = _alloca((wlen + 1) * sizeof(wchar_t));
  if (wlen != mbstowcs(pathnameW, pathname, wlen + 1))
    return ERROR_INVALID_NAME;
  return DeleteFileW(pathnameW) ? MDBX_SUCCESS : (int)GetLastError();
#else
  return unlink(pathname) ? errno : MDBX_SUCCESS;
#endif
}

#if !(defined(_WIN32) || defined(_WIN64))
static bool is_valid_fd(int fd) { return !(isatty(fd) < 0 && errno == EBADF); }
#endif /*! Windows */

MDBX_INTERNAL_FUNC int mdbx_removedirectory(const char *pathname) {
#if defined(_WIN32) || defined(_WIN64)
  const size_t wlen = mbstowcs(nullptr, pathname, INT_MAX);
  if (wlen < 1 || wlen > /* MAX_PATH */ INT16_MAX)
    return ERROR_INVALID_NAME;
  wchar_t *const pathnameW = _alloca((wlen + 1) * sizeof(wchar_t));
  if (wlen != mbstowcs(pathnameW, pathname, wlen + 1))
    return ERROR_INVALID_NAME;
  return RemoveDirectoryW(pathnameW) ? MDBX_SUCCESS : (int)GetLastError();
#else
  return rmdir(pathname) ? errno : MDBX_SUCCESS;
#endif
}

MDBX_INTERNAL_FUNC int mdbx_openfile(const enum mdbx_openfile_purpose purpose,
                                     const MDBX_env *env, const char *pathname,
                                     mdbx_filehandle_t *fd,
                                     mdbx_mode_t unix_mode_bits) {
  *fd = INVALID_HANDLE_VALUE;

#if defined(_WIN32) || defined(_WIN64)
  const size_t wlen = mbstowcs(nullptr, pathname, INT_MAX);
  if (wlen < 1 || wlen > /* MAX_PATH */ INT16_MAX)
    return ERROR_INVALID_NAME;
  wchar_t *const pathnameW = _alloca((wlen + 1) * sizeof(wchar_t));
  if (wlen != mbstowcs(pathnameW, pathname, wlen + 1))
    return ERROR_INVALID_NAME;

  DWORD CreationDisposition = unix_mode_bits ? OPEN_ALWAYS : OPEN_EXISTING;
  DWORD FlagsAndAttributes =
      FILE_FLAG_POSIX_SEMANTICS | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
  DWORD DesiredAccess = FILE_READ_ATTRIBUTES;
  DWORD ShareMode = (env->me_flags & MDBX_EXCLUSIVE)
                        ? 0
                        : (FILE_SHARE_READ | FILE_SHARE_WRITE);

  switch (purpose) {
  default:
    return ERROR_INVALID_PARAMETER;
  case MDBX_OPEN_LCK:
    CreationDisposition = OPEN_ALWAYS;
    DesiredAccess |= GENERIC_READ | GENERIC_WRITE;
    FlagsAndAttributes |= FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY;
    break;
  case MDBX_OPEN_DXB_READ:
    CreationDisposition = OPEN_EXISTING;
    DesiredAccess |= GENERIC_READ;
    ShareMode |= FILE_SHARE_READ;
    break;
  case MDBX_OPEN_DXB_LAZY:
    DesiredAccess |= GENERIC_READ | GENERIC_WRITE;
    break;
  case MDBX_OPEN_DXB_DSYNC:
    CreationDisposition = OPEN_EXISTING;
    DesiredAccess |= GENERIC_WRITE;
    FlagsAndAttributes |= FILE_FLAG_WRITE_THROUGH;
    break;
  case MDBX_OPEN_COPY:
    CreationDisposition = CREATE_NEW;
    ShareMode = 0;
    DesiredAccess |= GENERIC_WRITE;
    FlagsAndAttributes |=
        (env->me_psize < env->me_os_psize) ? 0 : FILE_FLAG_NO_BUFFERING;
    break;
  case MDBX_OPEN_DELETE:
    CreationDisposition = OPEN_EXISTING;
    ShareMode |= FILE_SHARE_DELETE;
    DesiredAccess =
        FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | DELETE | SYNCHRONIZE;
    break;
  }

  *fd = CreateFileW(pathnameW, DesiredAccess, ShareMode, NULL,
                    CreationDisposition, FlagsAndAttributes, NULL);
  if (*fd == INVALID_HANDLE_VALUE)
    return (int)GetLastError();

  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle(*fd, &info)) {
    int err = (int)GetLastError();
    CloseHandle(*fd);
    *fd = INVALID_HANDLE_VALUE;
    return err;
  }
  const DWORD AttributesDiff =
      (info.dwFileAttributes ^ FlagsAndAttributes) &
      (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED |
       FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_COMPRESSED);
  if (AttributesDiff)
    (void)SetFileAttributesW(pathnameW, info.dwFileAttributes ^ AttributesDiff);

#else
  int flags = unix_mode_bits ? O_CREAT : 0;
  switch (purpose) {
  default:
    return EINVAL;
  case MDBX_OPEN_LCK:
    flags |= O_RDWR;
    break;
  case MDBX_OPEN_DXB_READ:
    flags = O_RDONLY;
    break;
  case MDBX_OPEN_DXB_LAZY:
    flags |= O_RDWR;
    break;
  case MDBX_OPEN_COPY:
    flags = O_CREAT | O_WRONLY | O_EXCL;
    break;
  case MDBX_OPEN_DXB_DSYNC:
    flags |= O_WRONLY;
#if defined(O_DSYNC)
    flags |= O_DSYNC;
#elif defined(O_SYNC)
    flags |= O_SYNC;
#elif defined(O_FSYNC)
    flags |= O_FSYNC;
#endif
    break;
  case MDBX_OPEN_DELETE:
    flags = O_RDWR;
    break;
  }

  const bool direct_nocache_for_copy =
      env->me_psize >= env->me_os_psize && purpose == MDBX_OPEN_COPY;
  if (direct_nocache_for_copy) {
#if defined(O_DIRECT)
    flags |= O_DIRECT;
#endif /* O_DIRECT */
#if defined(O_NOCACHE)
    flags |= O_NOCACHE;
#endif /* O_NOCACHE */
  }

#ifdef O_CLOEXEC
  flags |= O_CLOEXEC;
#endif /* O_CLOEXEC */

  /* Safeguard for todo4recovery://erased_by_github/libmdbx/issues/144 */
#if STDIN_FILENO == 0 && STDOUT_FILENO == 1 && STDERR_FILENO == 2
  int stub_fd0 = -1, stub_fd1 = -1, stub_fd2 = -1;
  static const char dev_null[] = "/dev/null";
  if (!is_valid_fd(STDIN_FILENO)) {
    mdbx_warning("STD%s_FILENO/%d is invalid, open %s for temporary stub", "IN",
                 STDIN_FILENO, dev_null);
    stub_fd0 = open(dev_null, O_RDONLY | O_NOCTTY);
  }
  if (!is_valid_fd(STDOUT_FILENO)) {
    mdbx_warning("STD%s_FILENO/%d is invalid, open %s for temporary stub",
                 "OUT", STDOUT_FILENO, dev_null);
    stub_fd1 = open(dev_null, O_WRONLY | O_NOCTTY);
  }
  if (!is_valid_fd(STDERR_FILENO)) {
    mdbx_warning("STD%s_FILENO/%d is invalid, open %s for temporary stub",
                 "ERR", STDERR_FILENO, dev_null);
    stub_fd2 = open(dev_null, O_WRONLY | O_NOCTTY);
  }
#else
#error "Unexpected or unsupported UNIX or POSIX system"
#endif /* STDIN_FILENO == 0 && STDERR_FILENO == 2 */

  *fd = open(pathname, flags, unix_mode_bits);
#if defined(O_DIRECT)
  if (*fd < 0 && (flags & O_DIRECT) &&
      (errno == EINVAL || errno == EAFNOSUPPORT)) {
    flags &= ~(O_DIRECT | O_EXCL);
    *fd = open(pathname, flags, unix_mode_bits);
  }
#endif /* O_DIRECT */

  /* Safeguard for todo4recovery://erased_by_github/libmdbx/issues/144 */
#if STDIN_FILENO == 0 && STDOUT_FILENO == 1 && STDERR_FILENO == 2
  if (*fd == STDIN_FILENO) {
    mdbx_warning("Got STD%s_FILENO/%d, avoid using it by dup(fd)", "IN",
                 STDIN_FILENO);
    assert(stub_fd0 == -1);
    *fd = dup(stub_fd0 = *fd);
  }
  if (*fd == STDOUT_FILENO) {
    mdbx_warning("Got STD%s_FILENO/%d, avoid using it by dup(fd)", "OUT",
                 STDOUT_FILENO);
    assert(stub_fd1 == -1);
    *fd = dup(stub_fd1 = *fd);
  }
  if (*fd == STDERR_FILENO) {
    mdbx_warning("Got STD%s_FILENO/%d, avoid using it by dup(fd)", "ERR",
                 STDERR_FILENO);
    assert(stub_fd2 == -1);
    *fd = dup(stub_fd2 = *fd);
  }
  if (stub_fd0 != -1)
    close(stub_fd0);
  if (stub_fd1 != -1)
    close(stub_fd1);
  if (stub_fd2 != -1)
    close(stub_fd2);
  if (*fd >= STDIN_FILENO && *fd <= STDERR_FILENO) {
    mdbx_error(
        "Rejecting the use of a FD in the range "
        "STDIN_FILENO/%d..STDERR_FILENO/%d to prevent database corruption",
        STDIN_FILENO, STDERR_FILENO);
    close(*fd);
    return EBADF;
  }
#else
#error "Unexpected or unsupported UNIX or POSIX system"
#endif /* STDIN_FILENO == 0 && STDERR_FILENO == 2 */

  if (*fd < 0)
    return errno;

#if defined(FD_CLOEXEC) && !defined(O_CLOEXEC)
  const int fd_flags = fcntl(*fd, F_GETFD);
  if (fd_flags != -1)
    (void)fcntl(*fd, F_SETFD, fd_flags | FD_CLOEXEC);
#endif /* FD_CLOEXEC && !O_CLOEXEC */

  if (direct_nocache_for_copy) {
#if defined(F_NOCACHE) && !defined(O_NOCACHE)
    (void)fcntl(*fd, F_NOCACHE, 1);
#endif /* F_NOCACHE */
  }

#endif
  return MDBX_SUCCESS;
}

MDBX_INTERNAL_FUNC int mdbx_closefile(mdbx_filehandle_t fd) {
#if defined(_WIN32) || defined(_WIN64)
  return CloseHandle(fd) ? MDBX_SUCCESS : (int)GetLastError();
#else
  assert(fd > STDERR_FILENO);
  return (close(fd) == 0) ? MDBX_SUCCESS : errno;
#endif
}

MDBX_INTERNAL_FUNC int mdbx_pread(mdbx_filehandle_t fd, void *buf, size_t bytes,
                                  uint64_t offset) {
  if (bytes > MAX_WRITE)
    return MDBX_EINVAL;
#if defined(_WIN32) || defined(_WIN64)
  OVERLAPPED ov;
  ov.hEvent = 0;
  ov.Offset = (DWORD)offset;
  ov.OffsetHigh = HIGH_DWORD(offset);

  DWORD read = 0;
  if (unlikely(!ReadFile(fd, buf, (DWORD)bytes, &read, &ov))) {
    int rc = (int)GetLastError();
    return (rc == MDBX_SUCCESS) ? /* paranoia */ ERROR_READ_FAULT : rc;
  }
#else
  STATIC_ASSERT_MSG(sizeof(off_t) >= sizeof(size_t),
                    "libmdbx requires 64-bit file I/O on 64-bit systems");
  intptr_t read = pread(fd, buf, bytes, offset);
  if (read < 0) {
    int rc = errno;
    return (rc == MDBX_SUCCESS) ? /* paranoia */ MDBX_EIO : rc;
  }
#endif
  return (bytes == (size_t)read) ? MDBX_SUCCESS : MDBX_ENODATA;
}

MDBX_INTERNAL_FUNC int mdbx_pwrite(mdbx_filehandle_t fd, const void *buf,
                                   size_t bytes, uint64_t offset) {
  while (true) {
#if defined(_WIN32) || defined(_WIN64)
    OVERLAPPED ov;
    ov.hEvent = 0;
    ov.Offset = (DWORD)offset;
    ov.OffsetHigh = HIGH_DWORD(offset);

    DWORD written;
    if (unlikely(!WriteFile(
            fd, buf, likely(bytes <= MAX_WRITE) ? (DWORD)bytes : MAX_WRITE,
            &written, &ov)))
      return (int)GetLastError();
    if (likely(bytes == written))
      return MDBX_SUCCESS;
#else
    STATIC_ASSERT_MSG(sizeof(off_t) >= sizeof(size_t),
                      "libmdbx requires 64-bit file I/O on 64-bit systems");
    const intptr_t written =
        pwrite(fd, buf, likely(bytes <= MAX_WRITE) ? bytes : MAX_WRITE, offset);
    if (likely(bytes == (size_t)written))
      return MDBX_SUCCESS;
    if (written < 0) {
      const int rc = errno;
      if (rc != EINTR)
        return rc;
      continue;
    }
#endif
    bytes -= written;
    offset += written;
    buf = (char *)buf + written;
  }
}

MDBX_INTERNAL_FUNC int mdbx_write(mdbx_filehandle_t fd, const void *buf,
                                  size_t bytes) {
  while (true) {
#if defined(_WIN32) || defined(_WIN64)
    DWORD written;
    if (unlikely(!WriteFile(
            fd, buf, likely(bytes <= MAX_WRITE) ? (DWORD)bytes : MAX_WRITE,
            &written, nullptr)))
      return (int)GetLastError();
    if (likely(bytes == written))
      return MDBX_SUCCESS;
#else
    STATIC_ASSERT_MSG(sizeof(off_t) >= sizeof(size_t),
                      "libmdbx requires 64-bit file I/O on 64-bit systems");
    const intptr_t written =
        write(fd, buf, likely(bytes <= MAX_WRITE) ? bytes : MAX_WRITE);
    if (likely(bytes == (size_t)written))
      return MDBX_SUCCESS;
    if (written < 0) {
      const int rc = errno;
      if (rc != EINTR)
        return rc;
      continue;
    }
#endif
    bytes -= written;
    buf = (char *)buf + written;
  }
}

int mdbx_pwritev(mdbx_filehandle_t fd, struct iovec *iov, int iovcnt,
                 uint64_t offset, size_t expected_written) {
#if defined(_WIN32) || defined(_WIN64) || defined(__APPLE__) ||                \
    (defined(__ANDROID_API__) && __ANDROID_API__ < 24)
  size_t written = 0;
  for (int i = 0; i < iovcnt; ++i) {
    int rc = mdbx_pwrite(fd, iov[i].iov_base, iov[i].iov_len, offset);
    if (unlikely(rc != MDBX_SUCCESS))
      return rc;
    written += iov[i].iov_len;
    offset += iov[i].iov_len;
  }
  return (expected_written == written) ? MDBX_SUCCESS
                                       : MDBX_EIO /* ERROR_WRITE_FAULT */;
#else
  int rc;
  intptr_t written;
  do {
    STATIC_ASSERT_MSG(sizeof(off_t) >= sizeof(size_t),
                      "libmdbx requires 64-bit file I/O on 64-bit systems");
    written = pwritev(fd, iov, iovcnt, offset);
    if (likely(expected_written == (size_t)written))
      return MDBX_SUCCESS;
    rc = errno;
  } while (rc == EINTR);
  return (written < 0) ? rc : MDBX_EIO /* Use which error code? */;
#endif
}

MDBX_INTERNAL_FUNC int mdbx_fsync(mdbx_filehandle_t fd,
                                  enum mdbx_syncmode_bits mode_bits) {
#if defined(_WIN32) || defined(_WIN64)
  if ((mode_bits & (MDBX_SYNC_DATA | MDBX_SYNC_IODQ)) && !FlushFileBuffers(fd))
    return (int)GetLastError();
  return MDBX_SUCCESS;
#else

#if defined(__APPLE__) &&                                                      \
    MDBX_OSX_SPEED_INSTEADOF_DURABILITY == MDBX_OSX_WANNA_DURABILITY
  if (mode_bits & MDBX_SYNC_IODQ)
    return likely(fcntl(fd, F_FULLFSYNC) != -1) ? MDBX_SUCCESS : errno;
#endif /* MacOS */

  /* LY: This approach is always safe and without appreciable performance
   * degradation, even on a kernel with fdatasync's bug.
   *
   * For more info about of a corresponding fdatasync() bug
   * see http://www.spinics.net/lists/linux-ext4/msg33714.html */
  while (1) {
    switch (mode_bits & (MDBX_SYNC_DATA | MDBX_SYNC_SIZE)) {
    case MDBX_SYNC_NONE:
      return MDBX_SUCCESS /* nothing to do */;
#if defined(_POSIX_SYNCHRONIZED_IO) && _POSIX_SYNCHRONIZED_IO > 0
    case MDBX_SYNC_DATA:
      if (fdatasync(fd) == 0)
        return MDBX_SUCCESS;
      break /* error */;
#if defined(__linux__) || defined(__gnu_linux__)
    case MDBX_SYNC_SIZE:
      if (mdbx_linux_kernel_version >= 0x03060000)
        return MDBX_SUCCESS;
      __fallthrough /* fall through */;
#endif /* Linux */
#endif /* _POSIX_SYNCHRONIZED_IO > 0 */
    default:
      if (fsync(fd) == 0)
        return MDBX_SUCCESS;
    }

    int rc = errno;
    if (rc != EINTR)
      return rc;
  }
#endif
}

int mdbx_filesize(mdbx_filehandle_t fd, uint64_t *length) {
#if defined(_WIN32) || defined(_WIN64)
  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle(fd, &info))
    return (int)GetLastError();
  *length = info.nFileSizeLow | (uint64_t)info.nFileSizeHigh << 32;
#else
  struct stat st;

  STATIC_ASSERT_MSG(sizeof(off_t) <= sizeof(uint64_t),
                    "libmdbx requires 64-bit file I/O on 64-bit systems");
  if (fstat(fd, &st))
    return errno;

  *length = st.st_size;
#endif
  return MDBX_SUCCESS;
}

MDBX_INTERNAL_FUNC int mdbx_is_pipe(mdbx_filehandle_t fd) {
#if defined(_WIN32) || defined(_WIN64)
  switch (GetFileType(fd)) {
  case FILE_TYPE_DISK:
    return MDBX_RESULT_FALSE;
  case FILE_TYPE_CHAR:
  case FILE_TYPE_PIPE:
    return MDBX_RESULT_TRUE;
  default:
    return (int)GetLastError();
  }
#else
  struct stat info;
  if (fstat(fd, &info))
    return errno;
  switch (info.st_mode & S_IFMT) {
  case S_IFBLK:
  case S_IFREG:
    return MDBX_RESULT_FALSE;
  case S_IFCHR:
  case S_IFIFO:
  case S_IFSOCK:
    return MDBX_RESULT_TRUE;
  case S_IFDIR:
  case S_IFLNK:
  default:
    return MDBX_INCOMPATIBLE;
  }
#endif
}

MDBX_INTERNAL_FUNC int mdbx_ftruncate(mdbx_filehandle_t fd, uint64_t length) {
#if defined(_WIN32) || defined(_WIN64)
  if (mdbx_SetFileInformationByHandle) {
    FILE_END_OF_FILE_INFO EndOfFileInfo;
    EndOfFileInfo.EndOfFile.QuadPart = length;
    return mdbx_SetFileInformationByHandle(fd, FileEndOfFileInfo,
                                           &EndOfFileInfo,
                                           sizeof(FILE_END_OF_FILE_INFO))
               ? MDBX_SUCCESS
               : (int)GetLastError();
  } else {
    LARGE_INTEGER li;
    li.QuadPart = length;
    return (SetFilePointerEx(fd, li, NULL, FILE_BEGIN) && SetEndOfFile(fd))
               ? MDBX_SUCCESS
               : (int)GetLastError();
  }
#else
  STATIC_ASSERT_MSG(sizeof(off_t) >= sizeof(size_t),
                    "libmdbx requires 64-bit file I/O on 64-bit systems");
  return ftruncate(fd, length) == 0 ? MDBX_SUCCESS : errno;
#endif
}

MDBX_INTERNAL_FUNC int mdbx_fseek(mdbx_filehandle_t fd, uint64_t pos) {
#if defined(_WIN32) || defined(_WIN64)
  LARGE_INTEGER li;
  li.QuadPart = pos;
  return SetFilePointerEx(fd, li, NULL, FILE_BEGIN) ? MDBX_SUCCESS
                                                    : (int)GetLastError();
#else
  STATIC_ASSERT_MSG(sizeof(off_t) >= sizeof(size_t),
                    "libmdbx requires 64-bit file I/O on 64-bit systems");
  return (lseek(fd, pos, SEEK_SET) < 0) ? errno : MDBX_SUCCESS;
#endif
}

/*----------------------------------------------------------------------------*/

MDBX_INTERNAL_FUNC int
mdbx_thread_create(mdbx_thread_t *thread,
                   THREAD_RESULT(THREAD_CALL *start_routine)(void *),
                   void *arg) {
#if defined(_WIN32) || defined(_WIN64)
  *thread = CreateThread(NULL, 0, start_routine, arg, 0, NULL);
  return *thread ? MDBX_SUCCESS : (int)GetLastError();
#else
  return pthread_create(thread, NULL, start_routine, arg);
#endif
}

MDBX_INTERNAL_FUNC int mdbx_thread_join(mdbx_thread_t thread) {
#if defined(_WIN32) || defined(_WIN64)
  DWORD code = WaitForSingleObject(thread, INFINITE);
  return waitstatus2errcode(code);
#else
  void *unused_retval = &unused_retval;
  return pthread_join(thread, &unused_retval);
#endif
}

/*----------------------------------------------------------------------------*/

MDBX_INTERNAL_FUNC int mdbx_msync(mdbx_mmap_t *map, size_t offset,
                                  size_t length,
                                  enum mdbx_syncmode_bits mode_bits) {
  uint8_t *ptr = (uint8_t *)map->address + offset;
#if defined(_WIN32) || defined(_WIN64)
  if (!FlushViewOfFile(ptr, length))
    return (int)GetLastError();
#else
#if defined(__linux__) || defined(__gnu_linux__)
  if (mode_bits == MDBX_SYNC_NONE && mdbx_linux_kernel_version > 0x02061300)
    /* Since Linux 2.6.19, MS_ASYNC is in fact a no-op. The kernel properly
     * tracks dirty pages and flushes them to storage as necessary. */
    return MDBX_SUCCESS;
#endif /* Linux */
  if (msync(ptr, length, (mode_bits & MDBX_SYNC_DATA) ? MS_SYNC : MS_ASYNC))
    return errno;
  mode_bits &= ~MDBX_SYNC_DATA;
#endif
  return mdbx_fsync(map->fd, mode_bits);
}

MDBX_INTERNAL_FUNC int mdbx_check_fs_rdonly(mdbx_filehandle_t handle,
                                            const char *pathname, int err) {
#if defined(_WIN32) || defined(_WIN64)
  (void)pathname;
  (void)err;
  if (!mdbx_GetVolumeInformationByHandleW)
    return MDBX_ENOSYS;
  DWORD unused, flags;
  if (!mdbx_GetVolumeInformationByHandleW(handle, nullptr, 0, nullptr, &unused,
                                          &flags, nullptr, 0))
    return (int)GetLastError();
  if ((flags & FILE_READ_ONLY_VOLUME) == 0)
    return MDBX_EACCESS;
#else
  struct statvfs info;
  if (err != MDBX_ENOFILE) {
    if (statvfs(pathname, &info))
      return errno;
    if ((info.f_flag & ST_RDONLY) == 0)
      return err;
  }
  if (fstatvfs(handle, &info))
    return errno;
  if ((info.f_flag & ST_RDONLY) == 0)
    return (err == MDBX_ENOFILE) ? MDBX_EACCESS : err;
#endif /* !Windows */
  return MDBX_SUCCESS;
}

static int mdbx_check_fs_local(mdbx_filehandle_t handle, int flags) {
#if defined(_WIN32) || defined(_WIN64)
  if (mdbx_RunningUnderWine() && !(flags & MDBX_EXCLUSIVE))
    return ERROR_NOT_CAPABLE /* workaround for Wine */;

  if (GetFileType(handle) != FILE_TYPE_DISK)
    return ERROR_FILE_OFFLINE;

  if (mdbx_GetFileInformationByHandleEx) {
    FILE_REMOTE_PROTOCOL_INFO RemoteProtocolInfo;
    if (mdbx_GetFileInformationByHandleEx(handle, FileRemoteProtocolInfo,
                                          &RemoteProtocolInfo,
                                          sizeof(RemoteProtocolInfo))) {
      if ((RemoteProtocolInfo.Flags & REMOTE_PROTOCOL_INFO_FLAG_OFFLINE) &&
          !(flags & MDBX_RDONLY))
        return ERROR_FILE_OFFLINE;
      if (!(RemoteProtocolInfo.Flags & REMOTE_PROTOCOL_INFO_FLAG_LOOPBACK) &&
          !(flags & MDBX_EXCLUSIVE))
        return ERROR_REMOTE_STORAGE_MEDIA_ERROR;
    }
  }

  if (mdbx_NtFsControlFile) {
    NTSTATUS rc;
    struct {
      WOF_EXTERNAL_INFO wof_info;
      union {
        WIM_PROVIDER_EXTERNAL_INFO wim_info;
        FILE_PROVIDER_EXTERNAL_INFO_V1 file_info;
      };
      size_t reserved_for_microsoft_madness[42];
    } GetExternalBacking_OutputBuffer;
    IO_STATUS_BLOCK StatusBlock;
    rc = mdbx_NtFsControlFile(handle, NULL, NULL, NULL, &StatusBlock,
                              FSCTL_GET_EXTERNAL_BACKING, NULL, 0,
                              &GetExternalBacking_OutputBuffer,
                              sizeof(GetExternalBacking_OutputBuffer));
    if (NT_SUCCESS(rc)) {
      if (!(flags & MDBX_EXCLUSIVE))
        return ERROR_REMOTE_STORAGE_MEDIA_ERROR;
    } else if (rc != STATUS_OBJECT_NOT_EXTERNALLY_BACKED &&
               rc != STATUS_INVALID_DEVICE_REQUEST &&
               rc != STATUS_NOT_SUPPORTED)
      return ntstatus2errcode(rc);
  }

  if (mdbx_GetVolumeInformationByHandleW && mdbx_GetFinalPathNameByHandleW) {
    WCHAR *PathBuffer = mdbx_malloc(sizeof(WCHAR) * INT16_MAX);
    if (!PathBuffer)
      return MDBX_ENOMEM;

    int rc = MDBX_SUCCESS;
    DWORD VolumeSerialNumber, FileSystemFlags;
    if (!mdbx_GetVolumeInformationByHandleW(handle, PathBuffer, INT16_MAX,
                                            &VolumeSerialNumber, NULL,
                                            &FileSystemFlags, NULL, 0)) {
      rc = (int)GetLastError();
      goto bailout;
    }

    if ((flags & MDBX_RDONLY) == 0) {
      if (FileSystemFlags &
          (FILE_SEQUENTIAL_WRITE_ONCE | FILE_READ_ONLY_VOLUME |
           FILE_VOLUME_IS_COMPRESSED)) {
        rc = ERROR_REMOTE_STORAGE_MEDIA_ERROR;
        goto bailout;
      }
    }

    if (!mdbx_GetFinalPathNameByHandleW(handle, PathBuffer, INT16_MAX,
                                        FILE_NAME_NORMALIZED |
                                            VOLUME_NAME_NT)) {
      rc = (int)GetLastError();
      goto bailout;
    }

    if (_wcsnicmp(PathBuffer, L"\\Device\\Mup\\", 12) == 0) {
      if (!(flags & MDBX_EXCLUSIVE)) {
        rc = ERROR_REMOTE_STORAGE_MEDIA_ERROR;
        goto bailout;
      }
    } else if (mdbx_GetFinalPathNameByHandleW(handle, PathBuffer, INT16_MAX,
                                              FILE_NAME_NORMALIZED |
                                                  VOLUME_NAME_DOS)) {
      UINT DriveType = GetDriveTypeW(PathBuffer);
      if (DriveType == DRIVE_NO_ROOT_DIR &&
          _wcsnicmp(PathBuffer, L"\\\\?\\", 4) == 0 &&
          _wcsnicmp(PathBuffer + 5, L":\\", 2) == 0) {
        PathBuffer[7] = 0;
        DriveType = GetDriveTypeW(PathBuffer + 4);
      }
      switch (DriveType) {
      case DRIVE_CDROM:
        if (flags & MDBX_RDONLY)
          break;
      // fall through
      case DRIVE_UNKNOWN:
      case DRIVE_NO_ROOT_DIR:
      case DRIVE_REMOTE:
      default:
        if (!(flags & MDBX_EXCLUSIVE))
          rc = ERROR_REMOTE_STORAGE_MEDIA_ERROR;
      // fall through
      case DRIVE_REMOVABLE:
      case DRIVE_FIXED:
      case DRIVE_RAMDISK:
        break;
      }
    }
  bailout:
    mdbx_free(PathBuffer);
    return rc;
  }

#else

  struct statvfs statvfs_info;
  if (fstatvfs(handle, &statvfs_info))
    return errno;
#if defined(ST_LOCAL) || defined(ST_EXPORTED)
  const unsigned long st_flags = statvfs_info.f_flag;
#endif /* ST_LOCAL || ST_EXPORTED */

#if defined(__NetBSD__)
  const unsigned type = 0;
  const char *const name = statvfs_info.f_fstypename;
  const size_t name_len = VFS_NAMELEN;
#elif defined(_AIX) || defined(__OS400__)
  const char *const name = statvfs_info.f_basetype;
  const size_t name_len = sizeof(statvfs_info.f_basetype);
  struct stat st;
  if (fstat(handle, &st))
    return errno;
  const unsigned type = st.st_vfstype;
  if ((st.st_flag & FS_REMOTE) != 0 && !(flags & MDBX_EXCLUSIVE))
    return MDBX_EREMOTE;
#elif defined(FSTYPSZ) || defined(_FSTYPSZ)
  const unsigned type = 0;
  const char *const name = statvfs_info.f_basetype;
  const size_t name_len = sizeof(statvfs_info.f_basetype);
#elif defined(__sun) || defined(__SVR4) || defined(__svr4__) ||                \
    defined(ST_FSTYPSZ) || defined(_ST_FSTYPSZ)
  const unsigned type = 0;
  struct stat st;
  if (fstat(handle, &st))
    return errno;
  const char *const name = st.st_fstype;
  const size_t name_len = strlen(name);
#else
  struct statfs statfs_info;
  if (fstatfs(handle, &statfs_info))
    return errno;
#if defined(__OpenBSD__)
  const unsigned type = 0;
#else
  const unsigned type = statfs_info.f_type;
#endif
#if defined(MNT_LOCAL) || defined(MNT_EXPORTED)
  const unsigned long mnt_flags = statfs_info.f_flags;
#endif /* MNT_LOCAL || MNT_EXPORTED */
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) ||     \
    defined(__BSD__) || defined(__bsdi__) || defined(__DragonFly__) ||         \
    defined(__APPLE__) || defined(__MACH__) || defined(MFSNAMELEN) ||          \
    defined(MFSTYPENAMELEN) || defined(VFS_NAMELEN)
  const char *const name = statfs_info.f_fstypename;
  const size_t name_len = sizeof(statfs_info.f_fstypename);
#elif defined(__ANDROID_API__) && __ANDROID_API__ < 21
  const char *const name = "";
  const unsigned name_len = 0;
#else

  const char *name = "";
  unsigned name_len = 0;

  struct stat st;
  if (fstat(handle, &st))
    return errno;

  char pathbuf[PATH_MAX];
  FILE *mounted = nullptr;
#if defined(__linux__) || defined(__gnu_linux__)
  mounted = setmntent("/proc/mounts", "r");
#endif /* Linux */
  if (!mounted)
    mounted = setmntent("/etc/mtab", "r");
  if (mounted) {
    const struct mntent *ent;
#if defined(_BSD_SOURCE) || defined(_SVID_SOURCE) || defined(__BIONIC__) ||    \
    (defined(_DEFAULT_SOURCE) && __GLIBC_PREREQ(2, 19))
    struct mntent entbuf;
    const bool should_copy = false;
    while (nullptr !=
           (ent = getmntent_r(mounted, &entbuf, pathbuf, sizeof(pathbuf))))
#else
    const bool should_copy = true;
    while (nullptr != (ent = getmntent(mounted)))
#endif
    {
      struct stat mnt;
      if (!stat(ent->mnt_dir, &mnt) && mnt.st_dev == st.st_dev) {
        if (should_copy) {
          name =
              strncpy(pathbuf, ent->mnt_fsname, name_len = sizeof(pathbuf) - 1);
          pathbuf[name_len] = 0;
        } else {
          name = ent->mnt_fsname;
          name_len = strlen(name);
        }
        break;
      }
    }
    endmntent(mounted);
  }
#endif /* !xBSD && !Android/Bionic */
#endif

  if (name_len) {
    if (((name_len > 2 && strncasecmp("nfs", name, 3) == 0) ||
         strncasecmp("cifs", name, name_len) == 0 ||
         strncasecmp("ncpfs", name, name_len) == 0 ||
         strncasecmp("smbfs", name, name_len) == 0 ||
         strcasecmp("9P" /* WSL2 */, name) == 0 ||
         ((name_len > 3 && strncasecmp("fuse", name, 4) == 0) &&
          strncasecmp("fuseblk", name, name_len) != 0)) &&
        !(flags & MDBX_EXCLUSIVE))
      return MDBX_EREMOTE;
    if (strcasecmp("ftp", name) == 0 || strcasecmp("http", name) == 0 ||
        strcasecmp("sshfs", name) == 0)
      return MDBX_EREMOTE;
  }

#ifdef ST_LOCAL
  if ((st_flags & ST_LOCAL) == 0 && !(flags & MDBX_EXCLUSIVE))
    return MDBX_EREMOTE;
#elif defined(MNT_LOCAL)
  if ((mnt_flags & MNT_LOCAL) == 0 && !(flags & MDBX_EXCLUSIVE))
    return MDBX_EREMOTE;
#endif /* ST/MNT_LOCAL */

#ifdef ST_EXPORTED
  if ((st_flags & ST_EXPORTED) != 0 && !(flags & MDBX_RDONLY))
    return MDBX_EREMOTE;
#elif defined(MNT_EXPORTED)
  if ((mnt_flags & MNT_EXPORTED) != 0 && !(flags & MDBX_RDONLY))
    return MDBX_EREMOTE;
#endif /* ST/MNT_EXPORTED */

  switch (type) {
  case 0xFF534D42 /* CIFS_MAGIC_NUMBER */:
  case 0x6969 /* NFS_SUPER_MAGIC */:
  case 0x564c /* NCP_SUPER_MAGIC */:
  case 0x517B /* SMB_SUPER_MAGIC */:
#if defined(__digital__) || defined(__osf__) || defined(__osf)
  case 0x0E /* Tru64 NFS */:
#endif
#ifdef ST_FST_NFS
  case ST_FST_NFS:
#endif
    if ((flags & MDBX_EXCLUSIVE) == 0)
      return MDBX_EREMOTE;
  case 0:
  default:
    break;
  }
#endif /* Unix */

  return MDBX_SUCCESS;
}

static int check_mmap_limit(const size_t limit) {
  const bool should_check =
#if defined(__SANITIZE_ADDRESS__)
      true;
#else
      RUNNING_ON_VALGRIND;
#endif /* __SANITIZE_ADDRESS__ */

  if (should_check) {
    intptr_t pagesize, total_ram_pages, avail_ram_pages;
    int err =
        mdbx_get_sysraminfo(&pagesize, &total_ram_pages, &avail_ram_pages);
    if (unlikely(err != MDBX_SUCCESS))
      return err;

    const int log2page = log2n_powerof2(pagesize);
    if ((limit >> (log2page + 7)) > (size_t)total_ram_pages ||
        (limit >> (log2page + 6)) > (size_t)avail_ram_pages) {
      mdbx_error(
          "%s (%zu pages) is too large for available (%zu pages) or total "
          "(%zu pages) system RAM",
          "database upper size limit", limit >> log2page, avail_ram_pages,
          total_ram_pages);
      return MDBX_TOO_LARGE;
    }
  }

  return MDBX_SUCCESS;
}

MDBX_INTERNAL_FUNC int mdbx_mmap(const int flags, mdbx_mmap_t *map,
                                 const size_t size, const size_t limit,
                                 const unsigned options) {
  assert(size <= limit);
  map->limit = 0;
  map->current = 0;
  map->address = nullptr;
  map->filesize = 0;
#if defined(_WIN32) || defined(_WIN64)
  map->section = NULL;
#endif /* Windows */

  int err = mdbx_check_fs_local(map->fd, flags);
  if (unlikely(err != MDBX_SUCCESS))
    return err;

  err = check_mmap_limit(limit);
  if (unlikely(err != MDBX_SUCCESS))
    return err;

  if ((flags & MDBX_RDONLY) == 0 && (options & MMAP_OPTION_TRUNCATE) != 0) {
    err = mdbx_ftruncate(map->fd, size);
    if (err != MDBX_SUCCESS)
      return err;
    map->filesize = size;
#if !(defined(_WIN32) || defined(_WIN64))
    map->current = size;
#endif /* !Windows */
  } else {
    err = mdbx_filesize(map->fd, &map->filesize);
    if (err != MDBX_SUCCESS)
      return err;
#if !(defined(_WIN32) || defined(_WIN64))
    map->current = (map->filesize > limit) ? limit : (size_t)map->filesize;
#endif /* !Windows */
  }

#if defined(_WIN32) || defined(_WIN64)
  LARGE_INTEGER SectionSize;
  SectionSize.QuadPart = size;
  err = NtCreateSection(
      &map->section,
      /* DesiredAccess */
      (flags & MDBX_WRITEMAP)
          ? SECTION_QUERY | SECTION_MAP_READ | SECTION_EXTEND_SIZE |
                SECTION_MAP_WRITE
          : SECTION_QUERY | SECTION_MAP_READ | SECTION_EXTEND_SIZE,
      /* ObjectAttributes */ NULL, /* MaximumSize (InitialSize) */ &SectionSize,
      /* SectionPageProtection */
      (flags & MDBX_RDONLY) ? PAGE_READONLY : PAGE_READWRITE,
      /* AllocationAttributes */ SEC_RESERVE, map->fd);
  if (!NT_SUCCESS(err))
    return ntstatus2errcode(err);

  SIZE_T ViewSize = (flags & MDBX_RDONLY)     ? 0
                    : mdbx_RunningUnderWine() ? size
                                              : limit;
  err = NtMapViewOfSection(
      map->section, GetCurrentProcess(), &map->address,
      /* ZeroBits */ 0,
      /* CommitSize */ 0,
      /* SectionOffset */ NULL, &ViewSize,
      /* InheritDisposition */ ViewUnmap,
      /* AllocationType */ (flags & MDBX_RDONLY) ? 0 : MEM_RESERVE,
      /* Win32Protect */
      (flags & MDBX_WRITEMAP) ? PAGE_READWRITE : PAGE_READONLY);
  if (!NT_SUCCESS(err)) {
    NtClose(map->section);
    map->section = 0;
    map->address = nullptr;
    return ntstatus2errcode(err);
  }
  assert(map->address != MAP_FAILED);

  map->current = (size_t)SectionSize.QuadPart;
  map->limit = ViewSize;

#else /* Windows */

#ifndef MAP_TRYFIXED
#define MAP_TRYFIXED 0
#endif

#ifndef MAP_HASSEMAPHORE
#define MAP_HASSEMAPHORE 0
#endif

#ifndef MAP_CONCEAL
#define MAP_CONCEAL 0
#endif

#ifndef MAP_NOSYNC
#define MAP_NOSYNC 0
#endif

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0
#endif

#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

  map->address = mmap(
      NULL, limit, (flags & MDBX_WRITEMAP) ? PROT_READ | PROT_WRITE : PROT_READ,
      MAP_SHARED | MAP_FILE | MAP_NORESERVE |
          (F_ISSET(flags, MDBX_UTTERLY_NOSYNC) ? MAP_NOSYNC : 0) |
          ((options & MMAP_OPTION_SEMAPHORE) ? MAP_HASSEMAPHORE | MAP_NOSYNC
                                             : MAP_CONCEAL),
      map->fd, 0);

  if (unlikely(map->address == MAP_FAILED)) {
    map->limit = 0;
    map->current = 0;
    map->address = nullptr;
    return errno;
  }
  map->limit = limit;

#if MDBX_ENABLE_MADVISE
#ifdef MADV_DONTFORK
  if (unlikely(madvise(map->address, map->limit, MADV_DONTFORK) != 0))
    return errno;
#endif /* MADV_DONTFORK */
#ifdef MADV_NOHUGEPAGE
  (void)madvise(map->address, map->limit, MADV_NOHUGEPAGE);
#endif /* MADV_NOHUGEPAGE */
#endif /* MDBX_ENABLE_MADVISE */

#endif /* ! Windows */

  VALGRIND_MAKE_MEM_DEFINED(map->address, map->current);
  MDBX_ASAN_UNPOISON_MEMORY_REGION(map->address, map->current);
  return MDBX_SUCCESS;
}

MDBX_INTERNAL_FUNC int mdbx_munmap(mdbx_mmap_t *map) {
  VALGRIND_MAKE_MEM_NOACCESS(map->address, map->current);
  /* Unpoisoning is required for ASAN to avoid false-positive diagnostic
   * when this memory will re-used by malloc or another mmapping.
   * See todo4recovery://erased_by_github/libmdbx/pull/93#issuecomment-613687203
   */
  MDBX_ASAN_UNPOISON_MEMORY_REGION(map->address,
                                   (map->filesize && map->filesize < map->limit)
                                       ? map->filesize
                                       : map->limit);
#if defined(_WIN32) || defined(_WIN64)
  if (map->section)
    NtClose(map->section);
  NTSTATUS rc = NtUnmapViewOfSection(GetCurrentProcess(), map->address);
  if (!NT_SUCCESS(rc))
    ntstatus2errcode(rc);
#else
  if (unlikely(munmap(map->address, map->limit)))
    return errno;
#endif /* ! Windows */

  map->limit = 0;
  map->current = 0;
  map->address = nullptr;
  return MDBX_SUCCESS;
}

MDBX_INTERNAL_FUNC int mdbx_mresize(const int flags, mdbx_mmap_t *map,
                                    size_t size, size_t limit) {
  assert(size <= limit);
#if defined(_WIN32) || defined(_WIN64)
  assert(size != map->current || limit != map->limit || size < map->filesize);

  NTSTATUS status;
  LARGE_INTEGER SectionSize;
  int err, rc = MDBX_SUCCESS;

  if (!(flags & MDBX_RDONLY) && limit == map->limit && size > map->current &&
      /* workaround for Wine */ mdbx_NtExtendSection) {
    /* growth rw-section */
    SectionSize.QuadPart = size;
    status = mdbx_NtExtendSection(map->section, &SectionSize);
    if (!NT_SUCCESS(status))
      return ntstatus2errcode(status);
    map->current = size;
    if (map->filesize < size)
      map->filesize = size;
    return MDBX_SUCCESS;
  }

  if (limit > map->limit) {
    err = check_mmap_limit(limit);
    if (unlikely(err != MDBX_SUCCESS))
      return err;

    /* check ability of address space for growth before unmap */
    PVOID BaseAddress = (PBYTE)map->address + map->limit;
    SIZE_T RegionSize = limit - map->limit;
    status = NtAllocateVirtualMemory(GetCurrentProcess(), &BaseAddress, 0,
                                     &RegionSize, MEM_RESERVE, PAGE_NOACCESS);
    if (status == (NTSTATUS) /* STATUS_CONFLICTING_ADDRESSES */ 0xC0000018)
      return MDBX_UNABLE_EXTEND_MAPSIZE;
    if (!NT_SUCCESS(status))
      return ntstatus2errcode(status);

    status = NtFreeVirtualMemory(GetCurrentProcess(), &BaseAddress, &RegionSize,
                                 MEM_RELEASE);
    if (!NT_SUCCESS(status))
      return ntstatus2errcode(status);
  }

  /* Windows unable:
   *  - shrink a mapped file;
   *  - change size of mapped view;
   *  - extend read-only mapping;
   * Therefore we should unmap/map entire section. */
  if ((flags & MDBX_MRESIZE_MAY_UNMAP) == 0)
    return MDBX_EPERM;

  /* Unpoisoning is required for ASAN to avoid false-positive diagnostic
   * when this memory will re-used by malloc or another mmapping.
   * See todo4recovery://erased_by_github/libmdbx/pull/93#issuecomment-613687203
   */
  MDBX_ASAN_UNPOISON_MEMORY_REGION(map->address, map->limit);
  status = NtUnmapViewOfSection(GetCurrentProcess(), map->address);
  if (!NT_SUCCESS(status))
    return ntstatus2errcode(status);
  status = NtClose(map->section);
  map->section = NULL;
  PVOID ReservedAddress = NULL;
  SIZE_T ReservedSize = limit;

  if (!NT_SUCCESS(status)) {
  bailout_ntstatus:
    err = ntstatus2errcode(status);
  bailout:
    map->address = NULL;
    map->current = map->limit = 0;
    if (ReservedAddress) {
      ReservedSize = 0;
      status = NtFreeVirtualMemory(GetCurrentProcess(), &ReservedAddress,
                                   &ReservedSize, MEM_RELEASE);
      assert(NT_SUCCESS(status));
      (void)status;
    }
    return err;
  }

retry_file_and_section:
  /* resizing of the file may take a while,
   * therefore we reserve address space to avoid occupy it by other threads */
  ReservedAddress = map->address;
  status = NtAllocateVirtualMemory(GetCurrentProcess(), &ReservedAddress, 0,
                                   &ReservedSize, MEM_RESERVE, PAGE_NOACCESS);
  if (!NT_SUCCESS(status)) {
    ReservedAddress = NULL;
    if (status != (NTSTATUS) /* STATUS_CONFLICTING_ADDRESSES */ 0xC0000018)
      goto bailout_ntstatus /* no way to recovery */;

    if (flags & MDBX_MRESIZE_MAY_MOVE)
      /* the base address could be changed */
      map->address = NULL;
  }

  err = mdbx_filesize(map->fd, &map->filesize);
  if (err != MDBX_SUCCESS)
    goto bailout;

  if ((flags & MDBX_RDONLY) == 0 && map->filesize != size) {
    err = mdbx_ftruncate(map->fd, size);
    if (err == MDBX_SUCCESS)
      map->filesize = size;
    /* ignore error, because Windows unable shrink file
     * that already mapped (by another process) */
  }

  SectionSize.QuadPart = size;
  status = NtCreateSection(
      &map->section,
      /* DesiredAccess */
      (flags & MDBX_WRITEMAP)
          ? SECTION_QUERY | SECTION_MAP_READ | SECTION_EXTEND_SIZE |
                SECTION_MAP_WRITE
          : SECTION_QUERY | SECTION_MAP_READ | SECTION_EXTEND_SIZE,
      /* ObjectAttributes */ NULL,
      /* MaximumSize (InitialSize) */ &SectionSize,
      /* SectionPageProtection */
      (flags & MDBX_RDONLY) ? PAGE_READONLY : PAGE_READWRITE,
      /* AllocationAttributes */ SEC_RESERVE, map->fd);

  if (!NT_SUCCESS(status))
    goto bailout_ntstatus;

  if (ReservedAddress) {
    /* release reserved address space */
    ReservedSize = 0;
    status = NtFreeVirtualMemory(GetCurrentProcess(), &ReservedAddress,
                                 &ReservedSize, MEM_RELEASE);
    ReservedAddress = NULL;
    if (!NT_SUCCESS(status))
      goto bailout_ntstatus;
  }

retry_mapview:;
  SIZE_T ViewSize = (flags & MDBX_RDONLY) ? size : limit;
  status = NtMapViewOfSection(
      map->section, GetCurrentProcess(), &map->address,
      /* ZeroBits */ 0,
      /* CommitSize */ 0,
      /* SectionOffset */ NULL, &ViewSize,
      /* InheritDisposition */ ViewUnmap,
      /* AllocationType */ (flags & MDBX_RDONLY) ? 0 : MEM_RESERVE,
      /* Win32Protect */
      (flags & MDBX_WRITEMAP) ? PAGE_READWRITE : PAGE_READONLY);

  if (!NT_SUCCESS(status)) {
    if (status == (NTSTATUS) /* STATUS_CONFLICTING_ADDRESSES */ 0xC0000018 &&
        map->address && (flags & MDBX_MRESIZE_MAY_MOVE) != 0) {
      /* try remap at another base address */
      map->address = NULL;
      goto retry_mapview;
    }
    NtClose(map->section);
    map->section = NULL;

    if (map->address && (size != map->current || limit != map->limit)) {
      /* try remap with previously size and limit,
       * but will return MDBX_UNABLE_EXTEND_MAPSIZE on success */
      rc = (limit > map->limit) ? MDBX_UNABLE_EXTEND_MAPSIZE : MDBX_EPERM;
      size = map->current;
      ReservedSize = limit = map->limit;
      goto retry_file_and_section;
    }

    /* no way to recovery */
    goto bailout_ntstatus;
  }
  assert(map->address != MAP_FAILED);

  map->current = (size_t)SectionSize.QuadPart;
  map->limit = ViewSize;

#else /* Windows */

  map->filesize = 0;
  int rc = mdbx_filesize(map->fd, &map->filesize);
  if (rc != MDBX_SUCCESS)
    return rc;

  if (flags & MDBX_RDONLY) {
    map->current = (map->filesize > limit) ? limit : (size_t)map->filesize;
    if (map->current != size)
      rc = (size > map->current) ? MDBX_UNABLE_EXTEND_MAPSIZE : MDBX_EPERM;
  } else {
    if (map->filesize != size) {
      rc = mdbx_ftruncate(map->fd, size);
      if (rc != MDBX_SUCCESS)
        return rc;
      map->filesize = size;
    }

    if (map->current > size) {
      /* Clearing asan's bitmask for the region which released in shrinking,
       * since:
       *  - after the shrinking we will get an exception when accessing
       *    this region and (therefore) do not need the help of ASAN.
       *  - this allows us to clear the mask only within the file size
       *    when closing the mapping. */
      MDBX_ASAN_UNPOISON_MEMORY_REGION(
          (char *)map->address + size,
          ((map->current < map->limit) ? map->current : map->limit) - size);
    }
    map->current = size;
  }

  if (limit == map->limit)
    return rc;

  if (limit < map->limit) {
    /* unmap an excess at end of mapping. */
    // coverity[offset_free : FALSE]
    if (unlikely(munmap(map->dxb + limit, map->limit - limit)))
      return errno;
    map->limit = limit;
    return rc;
  }

  int err = check_mmap_limit(limit);
  if (unlikely(err != MDBX_SUCCESS))
    return err;

  assert(limit > map->limit);
  uint8_t *ptr = MAP_FAILED;

#if defined(MREMAP_MAYMOVE)
  ptr = mremap(map->address, map->limit, limit,
               (flags & MDBX_MRESIZE_MAY_MOVE) ? MREMAP_MAYMOVE : 0);
  if (ptr == MAP_FAILED) {
    err = errno;
    switch (err) {
    default:
      return err;
    case EAGAIN:
    case ENOMEM:
      return MDBX_UNABLE_EXTEND_MAPSIZE;
    case EFAULT /* MADV_DODUMP / MADV_DONTDUMP are mixed for mmap-range */:
      break;
    }
  }
#endif /* MREMAP_MAYMOVE */

  const unsigned mmap_flags =
      MAP_CONCEAL | MAP_SHARED | MAP_FILE | MAP_NORESERVE |
      (F_ISSET(flags, MDBX_UTTERLY_NOSYNC) ? MAP_NOSYNC : 0);
  const unsigned mmap_prot =
      (flags & MDBX_WRITEMAP) ? PROT_READ | PROT_WRITE : PROT_READ;

  if (ptr == MAP_FAILED) {
    /* Try to mmap additional space beyond the end of mapping. */
    ptr = mmap(map->dxb + map->limit, limit - map->limit, mmap_prot,
               mmap_flags | MAP_FIXED_NOREPLACE, map->fd, map->limit);
    if (ptr == map->dxb + map->limit)
      ptr = map->dxb;
    else if (ptr != MAP_FAILED) {
      /* the desired address is busy, unmap unsuitable one */
      if (unlikely(munmap(ptr, limit - map->limit)))
        return errno;
      ptr = MAP_FAILED;
    } else {
      err = errno;
      switch (err) {
      default:
        return err;
      case EAGAIN:
      case ENOMEM:
        return MDBX_UNABLE_EXTEND_MAPSIZE;
      case EEXIST: /* address busy */
      case EINVAL: /* kernel don't support MAP_FIXED_NOREPLACE */
        break;
      }
    }
  }

  if (ptr == MAP_FAILED) {
    /* unmap and map again whole region */
    if ((flags & MDBX_MRESIZE_MAY_UNMAP) == 0) {
      /* TODO: Perhaps here it is worth to implement suspend/resume threads
       * and perform unmap/map as like for Windows. */
      return MDBX_UNABLE_EXTEND_MAPSIZE;
    }

    if (unlikely(munmap(map->address, map->limit)))
      return errno;

    // coverity[pass_freed_arg : FALSE]
    ptr = mmap(map->address, limit, mmap_prot,
               (flags & MDBX_MRESIZE_MAY_MOVE)
                   ? mmap_flags
                   : mmap_flags | (MAP_FIXED_NOREPLACE ? MAP_FIXED_NOREPLACE
                                                       : MAP_FIXED),
               map->fd, 0);
    if (MAP_FIXED_NOREPLACE != 0 && MAP_FIXED_NOREPLACE != MAP_FIXED &&
        unlikely(ptr == MAP_FAILED) && !(flags & MDBX_MRESIZE_MAY_MOVE) &&
        errno == /* kernel don't support MAP_FIXED_NOREPLACE */ EINVAL)
      // coverity[pass_freed_arg : FALSE]
      ptr = mmap(map->address, limit, mmap_prot, mmap_flags | MAP_FIXED,
                 map->fd, 0);

    if (unlikely(ptr == MAP_FAILED)) {
      /* try to restore prev mapping */
      // coverity[pass_freed_arg : FALSE]
      ptr = mmap(map->address, map->limit, mmap_prot,
                 (flags & MDBX_MRESIZE_MAY_MOVE)
                     ? mmap_flags
                     : mmap_flags | (MAP_FIXED_NOREPLACE ? MAP_FIXED_NOREPLACE
                                                         : MAP_FIXED),
                 map->fd, 0);
      if (MAP_FIXED_NOREPLACE != 0 && MAP_FIXED_NOREPLACE != MAP_FIXED &&
          unlikely(ptr == MAP_FAILED) && !(flags & MDBX_MRESIZE_MAY_MOVE) &&
          errno == /* kernel don't support MAP_FIXED_NOREPLACE */ EINVAL)
        // coverity[pass_freed_arg : FALSE]
        ptr = mmap(map->address, map->limit, mmap_prot, mmap_flags | MAP_FIXED,
                   map->fd, 0);
      if (unlikely(ptr == MAP_FAILED)) {
        VALGRIND_MAKE_MEM_NOACCESS(map->address, map->current);
        /* Unpoisoning is required for ASAN to avoid false-positive diagnostic
         * when this memory will re-used by malloc or another mmapping.
         * See
         * todo4recovery://erased_by_github/libmdbx/pull/93#issuecomment-613687203
         */
        MDBX_ASAN_UNPOISON_MEMORY_REGION(
            map->address,
            (map->current < map->limit) ? map->current : map->limit);
        map->limit = 0;
        map->current = 0;
        map->address = nullptr;
        return errno;
      }
      rc = MDBX_UNABLE_EXTEND_MAPSIZE;
      limit = map->limit;
    }
  }

  assert(ptr && ptr != MAP_FAILED);
  if (map->address != ptr) {
    VALGRIND_MAKE_MEM_NOACCESS(map->address, map->current);
    /* Unpoisoning is required for ASAN to avoid false-positive diagnostic
     * when this memory will re-used by malloc or another mmapping.
     * See
     * todo4recovery://erased_by_github/libmdbx/pull/93#issuecomment-613687203
     */
    MDBX_ASAN_UNPOISON_MEMORY_REGION(
        map->address, (map->current < map->limit) ? map->current : map->limit);

    VALGRIND_MAKE_MEM_DEFINED(ptr, map->current);
    MDBX_ASAN_UNPOISON_MEMORY_REGION(ptr, map->current);
    map->address = ptr;
  }
  map->limit = limit;

#if MDBX_ENABLE_MADVISE
#ifdef MADV_DONTFORK
  if (unlikely(madvise(map->address, map->limit, MADV_DONTFORK) != 0))
    return errno;
#endif /* MADV_DONTFORK */
#ifdef MADV_NOHUGEPAGE
  (void)madvise(map->address, map->limit, MADV_NOHUGEPAGE);
#endif /* MADV_NOHUGEPAGE */
#endif /* MDBX_ENABLE_MADVISE */

#endif /* POSIX / Windows */

  return rc;
}

/*----------------------------------------------------------------------------*/

__cold MDBX_INTERNAL_FUNC void mdbx_osal_jitter(bool tiny) {
  for (;;) {
#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) ||                \
    defined(__x86_64__)
    const unsigned salt = 277u * (unsigned)__rdtsc();
#elif (defined(_WIN32) || defined(_WIN64)) && MDBX_WITHOUT_MSVC_CRT
    static ULONG state;
    const unsigned salt = (unsigned)RtlRandomEx(&state);
#else
    const unsigned salt = rand();
#endif

    const unsigned coin = salt % (tiny ? 29u : 43u);
    if (coin < 43 / 3)
      break;
#if defined(_WIN32) || defined(_WIN64)
    SwitchToThread();
    if (coin > 43 * 2 / 3)
      Sleep(1);
#else
    sched_yield();
    if (coin > 43 * 2 / 3)
      usleep(coin);
#endif
  }
}

#if defined(_WIN32) || defined(_WIN64)
#elif defined(__APPLE__) || defined(__MACH__)
#include <mach/mach_time.h>
#elif defined(__linux__) || defined(__gnu_linux__)
__cold static clockid_t choice_monoclock(void) {
  struct timespec probe;
#if defined(CLOCK_BOOTTIME)
  if (clock_gettime(CLOCK_BOOTTIME, &probe) == 0)
    return CLOCK_BOOTTIME;
#elif defined(CLOCK_MONOTONIC_RAW)
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &probe) == 0)
    return CLOCK_MONOTONIC_RAW;
#elif defined(CLOCK_MONOTONIC_COARSE)
  if (clock_gettime(CLOCK_MONOTONIC_COARSE, &probe) == 0)
    return CLOCK_MONOTONIC_COARSE;
#endif
  return CLOCK_MONOTONIC;
}
#endif

/*----------------------------------------------------------------------------*/

#if defined(_WIN32) || defined(_WIN64)
static LARGE_INTEGER performance_frequency;
#elif defined(__APPLE__) || defined(__MACH__)
static uint64_t ratio_16dot16_to_monotine;
#endif

MDBX_INTERNAL_FUNC uint64_t
mdbx_osal_16dot16_to_monotime(uint32_t seconds_16dot16) {
#if defined(_WIN32) || defined(_WIN64)
  if (unlikely(performance_frequency.QuadPart == 0))
    QueryPerformanceFrequency(&performance_frequency);
  const uint64_t ratio = performance_frequency.QuadPart;
#elif defined(__APPLE__) || defined(__MACH__)
  if (unlikely(ratio_16dot16_to_monotine == 0)) {
    mach_timebase_info_data_t ti;
    mach_timebase_info(&ti);
    ratio_16dot16_to_monotine = UINT64_C(1000000000) * ti.denom / ti.numer;
  }
  const uint64_t ratio = ratio_16dot16_to_monotine;
#else
  const uint64_t ratio = UINT64_C(1000000000);
#endif
  const uint64_t ret = (ratio * seconds_16dot16 + 32768) >> 16;
  return likely(ret || seconds_16dot16 == 0) ? ret : /* fix underflow */ 1;
}

MDBX_INTERNAL_FUNC uint32_t mdbx_osal_monotime_to_16dot16(uint64_t monotime) {
  static uint64_t limit;
  if (unlikely(monotime > limit)) {
    if (limit != 0)
      return UINT32_MAX;
    limit = mdbx_osal_16dot16_to_monotime(UINT32_MAX - 1);
    if (monotime > limit)
      return UINT32_MAX;
  }
  const uint32_t ret =
#if defined(_WIN32) || defined(_WIN64)
      (uint32_t)((monotime << 16) / performance_frequency.QuadPart);
#elif defined(__APPLE__) || defined(__MACH__)
      (uint32_t)((monotime << 16) / ratio_16dot16_to_monotine);
#else
      (uint32_t)(monotime * 128 / 1953125);
#endif
  return likely(ret || monotime == 0) ? ret : /* fix underflow */ 1;
}

MDBX_INTERNAL_FUNC uint64_t mdbx_osal_monotime(void) {
#if defined(_WIN32) || defined(_WIN64)
  LARGE_INTEGER counter;
  counter.QuadPart = 0;
  QueryPerformanceCounter(&counter);
  return counter.QuadPart;
#elif defined(__APPLE__) || defined(__MACH__)
  return mach_absolute_time();
#else

#if defined(__linux__) || defined(__gnu_linux__)
  static clockid_t posix_clockid = -1;
  if (unlikely(posix_clockid < 0))
    posix_clockid = choice_monoclock();
#elif defined(CLOCK_MONOTONIC)
#define posix_clockid CLOCK_MONOTONIC
#else
#define posix_clockid CLOCK_REALTIME
#endif

  struct timespec ts;
  if (unlikely(clock_gettime(posix_clockid, &ts) != 0)) {
    ts.tv_nsec = 0;
    ts.tv_sec = 0;
  }
  return ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
#endif
}

/*----------------------------------------------------------------------------*/

static void bootid_shake(bin128_t *p) {
  /* Bob Jenkins's PRNG: https://burtleburtle.net/bob/rand/smallprng.html */
  const uint32_t e = p->a - (p->b << 23 | p->b >> 9);
  p->a = p->b ^ (p->c << 16 | p->c >> 16);
  p->b = p->c + (p->d << 11 | p->d >> 21);
  p->c = p->d + e;
  p->d = e + p->a;
}

static void bootid_collect(bin128_t *p, const void *s, size_t n) {
  p->y += UINT64_C(64526882297375213);
  bootid_shake(p);
  for (size_t i = 0; i < n; ++i) {
    bootid_shake(p);
    p->y ^= UINT64_C(48797879452804441) * ((const uint8_t *)s)[i];
    bootid_shake(p);
    p->y += 14621231;
  }
  bootid_shake(p);

  /* minor non-linear tomfoolery */
  const unsigned z = p->x % 61;
  p->y = p->y << z | p->y >> (64 - z);
  bootid_shake(p);
  bootid_shake(p);
  const unsigned q = p->x % 59;
  p->y = p->y << q | p->y >> (64 - q);
  bootid_shake(p);
  bootid_shake(p);
  bootid_shake(p);
}

#if defined(_WIN32) || defined(_WIN64)

static uint64_t windows_systemtime_ms() {
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  return ((uint64_t)ft.dwHighDateTime << 32 | ft.dwLowDateTime) / 10000ul;
}

static uint64_t windows_bootime(void) {
  unsigned confirmed = 0;
  uint64_t boottime = 0;
  uint64_t up0 = mdbx_GetTickCount64();
  uint64_t st0 = windows_systemtime_ms();
  for (uint64_t fuse = st0; up0 && st0 < fuse + 1000 * 1000u / 42;) {
    YieldProcessor();
    const uint64_t up1 = mdbx_GetTickCount64();
    const uint64_t st1 = windows_systemtime_ms();
    if (st1 > fuse && st1 == st0 && up1 == up0) {
      uint64_t diff = st1 - up1;
      if (boottime == diff) {
        if (++confirmed > 4)
          return boottime;
      } else {
        confirmed = 0;
        boottime = diff;
      }
      fuse = st1;
      Sleep(1);
    }
    st0 = st1;
    up0 = up1;
  }
  return 0;
}

static LSTATUS mdbx_RegGetValue(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValue,
                                PVOID pvData, LPDWORD pcbData) {
  LSTATUS rc;
  if (!mdbx_RegGetValueA) {
    /* an old Windows 2000/XP */
    HKEY hSubKey;
    rc = RegOpenKeyA(hKey, lpSubKey, &hSubKey);
    if (rc == ERROR_SUCCESS) {
      rc = RegQueryValueExA(hSubKey, lpValue, NULL, NULL, pvData, pcbData);
      RegCloseKey(hSubKey);
    }
    return rc;
  }

  rc = mdbx_RegGetValueA(hKey, lpSubKey, lpValue, RRF_RT_ANY, NULL, pvData,
                         pcbData);
  if (rc != ERROR_FILE_NOT_FOUND)
    return rc;

  rc = mdbx_RegGetValueA(hKey, lpSubKey, lpValue,
                         RRF_RT_ANY | 0x00010000 /* RRF_SUBKEY_WOW6464KEY */,
                         NULL, pvData, pcbData);
  if (rc != ERROR_FILE_NOT_FOUND)
    return rc;
  return mdbx_RegGetValueA(hKey, lpSubKey, lpValue,
                           RRF_RT_ANY | 0x00020000 /* RRF_SUBKEY_WOW6432KEY */,
                           NULL, pvData, pcbData);
}
#endif

__cold MDBX_MAYBE_UNUSED static bool
bootid_parse_uuid(bin128_t *s, const void *p, const size_t n) {
  if (n > 31) {
    unsigned bits = 0;
    for (unsigned i = 0; i < n; ++i) /* try parse an UUID in text form */ {
      uint8_t c = ((const uint8_t *)p)[i];
      if (c >= '0' && c <= '9')
        c -= '0';
      else if (c >= 'a' && c <= 'f')
        c -= 'a' - 10;
      else if (c >= 'A' && c <= 'F')
        c -= 'A' - 10;
      else
        continue;
      assert(c <= 15);
      c ^= s->y >> 60;
      s->y = s->y << 4 | s->x >> 60;
      s->x = s->x << 4 | c;
      bits += 4;
    }
    if (bits > 42 * 3)
      /* UUID parsed successfully */
      return true;
  }

  if (n > 15) /* is enough handle it as a binary? */ {
    if (n == sizeof(bin128_t)) {
      bin128_t aligned;
      memcpy(&aligned, p, sizeof(bin128_t));
      s->x += aligned.x;
      s->y += aligned.y;
    } else
      bootid_collect(s, p, n);
    return true;
  }

  if (n)
    bootid_collect(s, p, n);
  return false;
}

__cold MDBX_INTERNAL_FUNC bin128_t mdbx_osal_bootid(void) {
  bin128_t bin = {{0, 0}};
  bool got_machineid = false, got_boottime = false, got_bootseq = false;

#if defined(__linux__) || defined(__gnu_linux__)
  {
    const int fd =
        open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_NOFOLLOW);
    if (fd != -1) {
      struct statfs fs;
      char buf[42];
      const ssize_t len =
          (fstatfs(fd, &fs) == 0 && fs.f_type == /* procfs */ 0x9FA0)
              ? read(fd, buf, sizeof(buf))
              : -1;
      const int err = close(fd);
      assert(err == 0);
      (void)err;
      if (len > 0 && bootid_parse_uuid(&bin, buf, len))
        return bin;
    }
  }
#endif /* Linux */

#if defined(__APPLE__) || defined(__MACH__)
  {
    char buf[42];
    size_t len = sizeof(buf);
    if (!sysctlbyname("kern.bootsessionuuid", buf, &len, nullptr, 0) &&
        bootid_parse_uuid(&bin, buf, len))
      return bin;

#if defined(__MAC_OS_X_VERSION_MIN_REQUIRED) &&                                \
    __MAC_OS_X_VERSION_MIN_REQUIRED > 1050
    uuid_t uuid;
    struct timespec wait = {0, 1000000000u / 42};
    if (!gethostuuid(uuid, &wait) &&
        bootid_parse_uuid(&bin, uuid, sizeof(uuid)))
      got_machineid = true;
#endif /* > 10.5 */

    struct timeval boottime;
    len = sizeof(boottime);
    if (!sysctlbyname("kern.boottime", &boottime, &len, nullptr, 0) &&
        len == sizeof(boottime) && boottime.tv_sec)
      got_boottime = true;
  }
#endif /* Apple/Darwin */

#if defined(_WIN32) || defined(_WIN64)
  {
    union buf {
      DWORD BootId;
      DWORD BaseTime;
      SYSTEM_TIMEOFDAY_INFORMATION SysTimeOfDayInfo;
      struct {
        LARGE_INTEGER BootTime;
        LARGE_INTEGER CurrentTime;
        LARGE_INTEGER TimeZoneBias;
        ULONG TimeZoneId;
        ULONG Reserved;
        ULONGLONG BootTimeBias;
        ULONGLONG SleepTimeBias;
      } SysTimeOfDayInfoHacked;
      wchar_t MachineGuid[42];
      char DigitalProductId[248];
    } buf;

    static const char HKLM_MicrosoftCryptography[] =
        "SOFTWARE\\Microsoft\\Cryptography";
    DWORD len = sizeof(buf);
    /* Windows is madness and must die */
    if (mdbx_RegGetValue(HKEY_LOCAL_MACHINE, HKLM_MicrosoftCryptography,
                         "MachineGuid", &buf.MachineGuid,
                         &len) == ERROR_SUCCESS &&
        len < sizeof(buf))
      got_machineid = bootid_parse_uuid(&bin, &buf.MachineGuid, len);

    if (!got_machineid) {
      /* again, Windows is madness */
      static const char HKLM_WindowsNT[] =
          "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
      static const char HKLM_WindowsNT_DPK[] =
          "SOFTWARE\\Microsoft\\Windows "
          "NT\\CurrentVersion\\DefaultProductKey";
      static const char HKLM_WindowsNT_DPK2[] =
          "SOFTWARE\\Microsoft\\Windows "
          "NT\\CurrentVersion\\DefaultProductKey2";

      len = sizeof(buf);
      if (mdbx_RegGetValue(HKEY_LOCAL_MACHINE, HKLM_WindowsNT,
                           "DigitalProductId", &buf.DigitalProductId,
                           &len) == ERROR_SUCCESS &&
          len > 42 && len < sizeof(buf)) {
        bootid_collect(&bin, &buf.DigitalProductId, len);
        got_machineid = true;
      }
      len = sizeof(buf);
      if (mdbx_RegGetValue(HKEY_LOCAL_MACHINE, HKLM_WindowsNT_DPK,
                           "DigitalProductId", &buf.DigitalProductId,
                           &len) == ERROR_SUCCESS &&
          len > 42 && len < sizeof(buf)) {
        bootid_collect(&bin, &buf.DigitalProductId, len);
        got_machineid = true;
      }
      len = sizeof(buf);
      if (mdbx_RegGetValue(HKEY_LOCAL_MACHINE, HKLM_WindowsNT_DPK2,
                           "DigitalProductId", &buf.DigitalProductId,
                           &len) == ERROR_SUCCESS &&
          len > 42 && len < sizeof(buf)) {
        bootid_collect(&bin, &buf.DigitalProductId, len);
        got_machineid = true;
      }
    }

    static const char HKLM_PrefetcherParams[] =
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory "
        "Management\\PrefetchParameters";
    len = sizeof(buf);
    if (mdbx_RegGetValue(HKEY_LOCAL_MACHINE, HKLM_PrefetcherParams, "BootId",
                         &buf.BootId, &len) == ERROR_SUCCESS &&
        len > 1 && len < sizeof(buf)) {
      bootid_collect(&bin, &buf.BootId, len);
      got_bootseq = true;
    }

    len = sizeof(buf);
    if (mdbx_RegGetValue(HKEY_LOCAL_MACHINE, HKLM_PrefetcherParams, "BaseTime",
                         &buf.BaseTime, &len) == ERROR_SUCCESS &&
        len >= sizeof(buf.BaseTime) && buf.BaseTime) {
      bootid_collect(&bin, &buf.BaseTime, len);
      got_boottime = true;
    }

    /* BootTime from SYSTEM_TIMEOFDAY_INFORMATION */
    NTSTATUS status = NtQuerySystemInformation(
        0x03 /* SystemTmeOfDayInformation */, &buf.SysTimeOfDayInfo,
        sizeof(buf.SysTimeOfDayInfo), &len);
    if (NT_SUCCESS(status) &&
        len >= offsetof(union buf, SysTimeOfDayInfoHacked.BootTimeBias) +
                   sizeof(buf.SysTimeOfDayInfoHacked.BootTimeBias) &&
        buf.SysTimeOfDayInfoHacked.BootTime.QuadPart) {
      const uint64_t UnbiasedBootTime =
          buf.SysTimeOfDayInfoHacked.BootTime.QuadPart -
          buf.SysTimeOfDayInfoHacked.BootTimeBias;
      if (UnbiasedBootTime) {
        bootid_collect(&bin, &UnbiasedBootTime, sizeof(UnbiasedBootTime));
        got_boottime = true;
      }
    }

    if (!got_boottime) {
      uint64_t boottime = windows_bootime();
      if (boottime) {
        bootid_collect(&bin, &boottime, sizeof(boottime));
        got_boottime = true;
      }
    }
  }
#endif /* Windows */

#if defined(CTL_HW) && defined(HW_UUID)
  if (!got_machineid) {
    static const int mib[] = {CTL_HW, HW_UUID};
    char buf[42];
    size_t len = sizeof(buf);
    if (sysctl(
#ifdef SYSCTL_LEGACY_NONCONST_MIB
            (int *)
#endif
                mib,
            ARRAY_LENGTH(mib), &buf, &len, NULL, 0) == 0)
      got_machineid = bootid_parse_uuid(&bin, buf, len);
  }
#endif /* CTL_HW && HW_UUID */

#if defined(CTL_KERN) && defined(KERN_HOSTUUID)
  if (!got_machineid) {
    static const int mib[] = {CTL_KERN, KERN_HOSTUUID};
    char buf[42];
    size_t len = sizeof(buf);
    if (sysctl(
#ifdef SYSCTL_LEGACY_NONCONST_MIB
            (int *)
#endif
                mib,
            ARRAY_LENGTH(mib), &buf, &len, NULL, 0) == 0)
      got_machineid = bootid_parse_uuid(&bin, buf, len);
  }
#endif /* CTL_KERN && KERN_HOSTUUID */

#if defined(__NetBSD__)
  if (!got_machineid) {
    char buf[42];
    size_t len = sizeof(buf);
    if (sysctlbyname("machdep.dmi.system-uuid", buf, &len, NULL, 0) == 0)
      got_machineid = bootid_parse_uuid(&bin, buf, len);
  }
#endif /* __NetBSD__ */

#if _XOPEN_SOURCE_EXTENDED
  if (!got_machineid) {
    const int hostid = gethostid();
    if (hostid > 0) {
      bootid_collect(&bin, &hostid, sizeof(hostid));
      got_machineid = true;
    }
  }
#endif /* _XOPEN_SOURCE_EXTENDED */

  if (!got_machineid) {
  lack:
    bin.x = bin.y = 0;
    return bin;
  }

  /*--------------------------------------------------------------------------*/

#if defined(CTL_KERN) && defined(KERN_BOOTTIME)
  if (!got_boottime) {
    static const int mib[] = {CTL_KERN, KERN_BOOTTIME};
    struct timeval boottime;
    size_t len = sizeof(boottime);
    if (sysctl(
#ifdef SYSCTL_LEGACY_NONCONST_MIB
            (int *)
#endif
                mib,
            ARRAY_LENGTH(mib), &boottime, &len, NULL, 0) == 0 &&
        len == sizeof(boottime) && boottime.tv_sec) {
      bootid_collect(&bin, &boottime, len);
      got_boottime = true;
    }
  }
#endif /* CTL_KERN && KERN_BOOTTIME */

#if defined(__sun) || defined(__SVR4) || defined(__svr4__)
  if (!got_boottime) {
    kstat_ctl_t *kc = kstat_open();
    if (kc) {
      kstat_t *kp = kstat_lookup(kc, "unix", 0, "system_misc");
      if (kp && kstat_read(kc, kp, 0) != -1) {
        kstat_named_t *kn = (kstat_named_t *)kstat_data_lookup(kp, "boot_time");
        if (kn) {
          switch (kn->data_type) {
          case KSTAT_DATA_INT32:
          case KSTAT_DATA_UINT32:
            bootid_collect(&bin, &kn->value, sizeof(int32_t));
            got_boottime = true;
          case KSTAT_DATA_INT64:
          case KSTAT_DATA_UINT64:
            bootid_collect(&bin, &kn->value, sizeof(int64_t));
            got_boottime = true;
          }
        }
      }
      kstat_close(kc);
    }
  }
#endif /* SunOS / Solaris */

#if _XOPEN_SOURCE_EXTENDED && defined(BOOT_TIME)
  if (!got_boottime) {
    setutxent();
    const struct utmpx id = {.ut_type = BOOT_TIME};
    const struct utmpx *entry = getutxid(&id);
    if (entry) {
      bootid_collect(&bin, entry, sizeof(*entry));
      got_boottime = true;
      while (unlikely((entry = getutxid(&id)) != nullptr)) {
        /* have multiple reboot records, assuming we can distinguish next
         * bootsession even if RTC is wrong or absent */
        bootid_collect(&bin, entry, sizeof(*entry));
        got_bootseq = true;
      }
    }
    endutxent();
  }
#endif /* _XOPEN_SOURCE_EXTENDED && BOOT_TIME */

  if (!got_bootseq) {
    if (!got_boottime || !MDBX_TRUST_RTC)
      goto lack;

#if defined(_WIN32) || defined(_WIN64)
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    if (0x1CCCCCC > now.dwHighDateTime)
#else
    struct timespec mono, real;
    if (clock_gettime(CLOCK_MONOTONIC, &mono) ||
        clock_gettime(CLOCK_REALTIME, &real) ||
        /* wrong time, RTC is mad or absent */
        1555555555l > real.tv_sec ||
        /* seems no adjustment by RTC/NTP, i.e. a fake time */
        real.tv_sec < mono.tv_sec || 1234567890l > real.tv_sec - mono.tv_sec ||
        (real.tv_sec - mono.tv_sec) % 900u == 0)
#endif
      goto lack;
  }

  return bin;
}

__cold int mdbx_get_sysraminfo(intptr_t *page_size, intptr_t *total_pages,
                               intptr_t *avail_pages) {
  if (!page_size && !total_pages && !avail_pages)
    return MDBX_EINVAL;
  if (total_pages)
    *total_pages = -1;
  if (avail_pages)
    *avail_pages = -1;

  const intptr_t pagesize = mdbx_syspagesize();
  if (page_size)
    *page_size = pagesize;
  if (unlikely(pagesize < MIN_PAGESIZE || !is_powerof2(pagesize)))
    return MDBX_INCOMPATIBLE;

  MDBX_MAYBE_UNUSED const int log2page = log2n_powerof2(pagesize);
  assert(pagesize == (INT64_C(1) << log2page));
  (void)log2page;

#if defined(_WIN32) || defined(_WIN64)
  MEMORYSTATUSEX info;
  memset(&info, 0, sizeof(info));
  info.dwLength = sizeof(info);
  if (!GlobalMemoryStatusEx(&info))
    return (int)GetLastError();
#endif

  if (total_pages) {
#if defined(_WIN32) || defined(_WIN64)
    const intptr_t total_ram_pages = (intptr_t)(info.ullTotalPhys >> log2page);
#elif defined(_SC_PHYS_PAGES)
    const intptr_t total_ram_pages = sysconf(_SC_PHYS_PAGES);
    if (total_ram_pages == -1)
      return errno;
#elif defined(_SC_AIX_REALMEM)
    const intptr_t total_ram_Kb = sysconf(_SC_AIX_REALMEM);
    if (total_ram_Kb == -1)
      return errno;
    const intptr_t total_ram_pages = (total_ram_Kb << 10) >> log2page;
#elif defined(HW_USERMEM) || defined(HW_PHYSMEM64) || defined(HW_MEMSIZE) ||   \
    defined(HW_PHYSMEM)
    size_t ram, len = sizeof(ram);
    static const int mib[] = {
      CTL_HW,
#if defined(HW_USERMEM)
      HW_USERMEM
#elif defined(HW_PHYSMEM64)
      HW_PHYSMEM64
#elif defined(HW_MEMSIZE)
      HW_MEMSIZE
#else
      HW_PHYSMEM
#endif
    };
    if (sysctl(
#ifdef SYSCTL_LEGACY_NONCONST_MIB
            (int *)
#endif
                mib,
            ARRAY_LENGTH(mib), &ram, &len, NULL, 0) != 0)
      return errno;
    if (len != sizeof(ram))
      return MDBX_ENOSYS;
    const intptr_t total_ram_pages = (intptr_t)(ram >> log2page);
#else
#error "FIXME: Get User-accessible or physical RAM"
#endif
    *total_pages = total_ram_pages;
    if (total_ram_pages < 1)
      return MDBX_ENOSYS;
  }

  if (avail_pages) {
#if defined(_WIN32) || defined(_WIN64)
    const intptr_t avail_ram_pages = (intptr_t)(info.ullAvailPhys >> log2page);
#elif defined(_SC_AVPHYS_PAGES)
    const intptr_t avail_ram_pages = sysconf(_SC_AVPHYS_PAGES);
    if (avail_ram_pages == -1)
      return errno;
#elif defined(__MACH__)
    mach_msg_type_number_t count = HOST_VM_INFO_COUNT;
    vm_statistics_data_t vmstat;
    mach_port_t mport = mach_host_self();
    kern_return_t kerr = host_statistics(mach_host_self(), HOST_VM_INFO,
                                         (host_info_t)&vmstat, &count);
    mach_port_deallocate(mach_task_self(), mport);
    if (unlikely(kerr != KERN_SUCCESS))
      return MDBX_ENOSYS;
    const intptr_t avail_ram_pages = vmstat.free_count;
#elif defined(VM_TOTAL) || defined(VM_METER)
    struct vmtotal info;
    size_t len = sizeof(info);
    static const int mib[] = {
      CTL_VM,
#if defined(VM_TOTAL)
      VM_TOTAL
#elif defined(VM_METER)
      VM_METER
#endif
    };
    if (sysctl(
#ifdef SYSCTL_LEGACY_NONCONST_MIB
            (int *)
#endif
                mib,
            ARRAY_LENGTH(mib), &info, &len, NULL, 0) != 0)
      return errno;
    if (len != sizeof(info))
      return MDBX_ENOSYS;
    const intptr_t avail_ram_pages = info.t_free;
#else
#error "FIXME: Get Available RAM"
#endif
    *avail_pages = avail_ram_pages;
    if (avail_ram_pages < 1)
      return MDBX_ENOSYS;
  }

  return MDBX_SUCCESS;
}
