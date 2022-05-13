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

#if defined(_WIN32) || defined(_WIN64) /* Windows LCK-implementation */

/* PREAMBLE FOR WINDOWS:
 *
 * We are not concerned for performance here.
 * If you are running Windows a performance could NOT be the goal.
 * Otherwise please use Linux. */

#include "internals.h"

static void mdbx_winnt_import(void);

#if MDBX_BUILD_SHARED_LIBRARY
#if MDBX_WITHOUT_MSVC_CRT && defined(NDEBUG)
/* DEBUG/CHECKED builds still require MSVC's CRT for runtime checks.
 *
 * Define dll's entry point only for Release build when NDEBUG is defined and
 * MDBX_WITHOUT_MSVC_CRT=ON. if the entry point isn't defined then MSVC's will
 * automatically use DllMainCRTStartup() from CRT library, which also
 * automatically call DllMain() from our mdbx.dll */
#pragma comment(linker, "/ENTRY:DllMain")
#endif /* MDBX_WITHOUT_MSVC_CRT */

BOOL APIENTRY DllMain(HANDLE module, DWORD reason, LPVOID reserved)
#else
#if !MDBX_MANUAL_MODULE_HANDLER
static
#endif /* !MDBX_MANUAL_MODULE_HANDLER */
    void NTAPI
    mdbx_module_handler(PVOID module, DWORD reason, PVOID reserved)
#endif /* MDBX_BUILD_SHARED_LIBRARY */
{
  (void)reserved;
  switch (reason) {
  case DLL_PROCESS_ATTACH:
    mdbx_winnt_import();
    mdbx_rthc_global_init();
    break;
  case DLL_PROCESS_DETACH:
    mdbx_rthc_global_dtor();
    break;

  case DLL_THREAD_ATTACH:
    break;
  case DLL_THREAD_DETACH:
    mdbx_rthc_thread_dtor(module);
    break;
  }
#if MDBX_BUILD_SHARED_LIBRARY
  return TRUE;
#endif
}

#if !MDBX_BUILD_SHARED_LIBRARY && !MDBX_MANUAL_MODULE_HANDLER
/* *INDENT-OFF* */
/* clang-format off */
#if defined(_MSC_VER)
#  pragma const_seg(push)
#  pragma data_seg(push)

#  ifndef _M_IX86
     /* kick a linker to create the TLS directory if not already done */
#    pragma comment(linker, "/INCLUDE:_tls_used")
     /* Force some symbol references. */
#    pragma comment(linker, "/INCLUDE:mdbx_tls_anchor")
     /* specific const-segment for WIN64 */
#    pragma const_seg(".CRT$XLB")
     const
#  else
     /* kick a linker to create the TLS directory if not already done */
#    pragma comment(linker, "/INCLUDE:__tls_used")
     /* Force some symbol references. */
#    pragma comment(linker, "/INCLUDE:_mdbx_tls_anchor")
     /* specific data-segment for WIN32 */
#    pragma data_seg(".CRT$XLB")
#  endif

   __declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK mdbx_tls_anchor = mdbx_module_handler;
#  pragma data_seg(pop)
#  pragma const_seg(pop)

#elif defined(__GNUC__)
#  ifndef _M_IX86
     const
#  endif
   PIMAGE_TLS_CALLBACK mdbx_tls_anchor __attribute__((__section__(".CRT$XLB"), used)) = mdbx_module_handler;
#else
#  error FIXME
#endif
/* *INDENT-ON* */
/* clang-format on */
#endif /* !MDBX_BUILD_SHARED_LIBRARY && !MDBX_MANUAL_MODULE_HANDLER */

/*----------------------------------------------------------------------------*/

#define LCK_SHARED 0
#define LCK_EXCLUSIVE LOCKFILE_EXCLUSIVE_LOCK
#define LCK_WAITFOR 0
#define LCK_DONTWAIT LOCKFILE_FAIL_IMMEDIATELY

static __inline BOOL flock(mdbx_filehandle_t fd, DWORD flags, uint64_t offset,
                           size_t bytes) {
  OVERLAPPED ov;
  ov.hEvent = 0;
  ov.Offset = (DWORD)offset;
  ov.OffsetHigh = HIGH_DWORD(offset);
  return LockFileEx(fd, flags, 0, (DWORD)bytes, HIGH_DWORD(bytes), &ov);
}

static __inline BOOL funlock(mdbx_filehandle_t fd, uint64_t offset,
                             size_t bytes) {
  return UnlockFile(fd, (DWORD)offset, HIGH_DWORD(offset), (DWORD)bytes,
                    HIGH_DWORD(bytes));
}

/*----------------------------------------------------------------------------*/
/* global `write` lock for write-txt processing,
 * exclusive locking both meta-pages) */

#define LCK_MAXLEN (1u + ((~(size_t)0) >> 1))
#define LCK_META_OFFSET 0
#define LCK_META_LEN (MAX_PAGESIZE * NUM_METAS)
#define LCK_BODY_OFFSET LCK_META_LEN
#define LCK_BODY_LEN (LCK_MAXLEN - LCK_BODY_OFFSET)
#define LCK_BODY LCK_BODY_OFFSET, LCK_BODY_LEN
#define LCK_WHOLE 0, LCK_MAXLEN

int mdbx_txn_lock(MDBX_env *env, bool dontwait) {
  if (dontwait) {
    if (!TryEnterCriticalSection(&env->me_windowsbug_lock))
      return MDBX_BUSY;
  } else {
    __try {
      EnterCriticalSection(&env->me_windowsbug_lock);
    }
    __except ((GetExceptionCode() ==
                 0xC0000194 /* STATUS_POSSIBLE_DEADLOCK / EXCEPTION_POSSIBLE_DEADLOCK */)
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH) {
      return ERROR_POSSIBLE_DEADLOCK;
    }
  }

  if ((env->me_flags & MDBX_EXCLUSIVE) ||
      flock(env->me_lazy_fd,
            dontwait ? (LCK_EXCLUSIVE | LCK_DONTWAIT)
                     : (LCK_EXCLUSIVE | LCK_WAITFOR),
            LCK_BODY))
    return MDBX_SUCCESS;
  int rc = (int)GetLastError();
  LeaveCriticalSection(&env->me_windowsbug_lock);
  return (!dontwait || rc != ERROR_LOCK_VIOLATION) ? rc : MDBX_BUSY;
}

void mdbx_txn_unlock(MDBX_env *env) {
  int rc = (env->me_flags & MDBX_EXCLUSIVE)
               ? TRUE
               : funlock(env->me_lazy_fd, LCK_BODY);
  LeaveCriticalSection(&env->me_windowsbug_lock);
  if (!rc)
    mdbx_panic("%s failed: err %u", __func__, (int)GetLastError());
}

/*----------------------------------------------------------------------------*/
/* global `read` lock for readers registration,
 * exclusive locking `mti_numreaders` (second) cacheline */

#define LCK_LO_OFFSET 0
#define LCK_LO_LEN offsetof(MDBX_lockinfo, mti_numreaders)
#define LCK_UP_OFFSET LCK_LO_LEN
#define LCK_UP_LEN (sizeof(MDBX_lockinfo) - LCK_UP_OFFSET)
#define LCK_LOWER LCK_LO_OFFSET, LCK_LO_LEN
#define LCK_UPPER LCK_UP_OFFSET, LCK_UP_LEN

MDBX_INTERNAL_FUNC int mdbx_rdt_lock(MDBX_env *env) {
  mdbx_srwlock_AcquireShared(&env->me_remap_guard);
  if (env->me_lfd == INVALID_HANDLE_VALUE)
    return MDBX_SUCCESS; /* readonly database in readonly filesystem */

  /* transition from S-? (used) to S-E (locked),
   * e.g. exclusive lock upper-part */
  if ((env->me_flags & MDBX_EXCLUSIVE) ||
      flock(env->me_lfd, LCK_EXCLUSIVE | LCK_WAITFOR, LCK_UPPER))
    return MDBX_SUCCESS;

  int rc = (int)GetLastError();
  mdbx_srwlock_ReleaseShared(&env->me_remap_guard);
  return rc;
}

MDBX_INTERNAL_FUNC void mdbx_rdt_unlock(MDBX_env *env) {
  if (env->me_lfd != INVALID_HANDLE_VALUE) {
    /* transition from S-E (locked) to S-? (used), e.g. unlock upper-part */
    if ((env->me_flags & MDBX_EXCLUSIVE) == 0 &&
        !funlock(env->me_lfd, LCK_UPPER))
      mdbx_panic("%s failed: err %u", __func__, (int)GetLastError());
  }
  mdbx_srwlock_ReleaseShared(&env->me_remap_guard);
}

MDBX_INTERNAL_FUNC int mdbx_lockfile(mdbx_filehandle_t fd, bool wait) {
  return flock(fd,
               wait ? LCK_EXCLUSIVE | LCK_WAITFOR
                    : LCK_EXCLUSIVE | LCK_DONTWAIT,
               0, LCK_MAXLEN)
             ? MDBX_SUCCESS
             : (int)GetLastError();
}

static int suspend_and_append(mdbx_handle_array_t **array,
                              const DWORD ThreadId) {
  const unsigned limit = (*array)->limit;
  if ((*array)->count == limit) {
    void *ptr = mdbx_realloc(
        (limit > ARRAY_LENGTH((*array)->handles))
            ? *array
            : /* don't free initial array on the stack */ NULL,
        sizeof(mdbx_handle_array_t) +
            sizeof(HANDLE) * (limit * 2 - ARRAY_LENGTH((*array)->handles)));
    if (!ptr)
      return MDBX_ENOMEM;
    if (limit == ARRAY_LENGTH((*array)->handles))
      memcpy(ptr, *array, sizeof(mdbx_handle_array_t));
    *array = (mdbx_handle_array_t *)ptr;
    (*array)->limit = limit * 2;
  }

  HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                              FALSE, ThreadId);
  if (hThread == NULL)
    return (int)GetLastError();

  if (SuspendThread(hThread) == (DWORD)-1) {
    int err = (int)GetLastError();
    DWORD ExitCode;
    if (err == /* workaround for Win10 UCRT bug */ ERROR_ACCESS_DENIED ||
        !GetExitCodeThread(hThread, &ExitCode) || ExitCode != STILL_ACTIVE)
      err = MDBX_SUCCESS;
    CloseHandle(hThread);
    return err;
  }

  (*array)->handles[(*array)->count++] = hThread;
  return MDBX_SUCCESS;
}

MDBX_INTERNAL_FUNC int
mdbx_suspend_threads_before_remap(MDBX_env *env, mdbx_handle_array_t **array) {
  mdbx_assert(env, (env->me_flags & MDBX_NOTLS) == 0);
  const uintptr_t CurrentTid = GetCurrentThreadId();
  int rc;
  if (env->me_lck_mmap.lck) {
    /* Scan LCK for threads of the current process */
    const MDBX_reader *const begin = env->me_lck_mmap.lck->mti_readers;
    const MDBX_reader *const end =
        begin +
        atomic_load32(&env->me_lck_mmap.lck->mti_numreaders, mo_AcquireRelease);
    const uintptr_t WriteTxnOwner = env->me_txn0 ? env->me_txn0->mt_owner : 0;
    for (const MDBX_reader *reader = begin; reader < end; ++reader) {
      if (reader->mr_pid.weak != env->me_pid || !reader->mr_tid.weak) {
      skip_lck:
        continue;
      }
      if (reader->mr_tid.weak == CurrentTid ||
          reader->mr_tid.weak == WriteTxnOwner)
        goto skip_lck;

      rc = suspend_and_append(array, (mdbx_tid_t)reader->mr_tid.weak);
      if (rc != MDBX_SUCCESS) {
      bailout_lck:
        (void)mdbx_resume_threads_after_remap(*array);
        return rc;
      }
    }
    if (WriteTxnOwner && WriteTxnOwner != CurrentTid) {
      rc = suspend_and_append(array, (mdbx_tid_t)WriteTxnOwner);
      if (rc != MDBX_SUCCESS)
        goto bailout_lck;
    }
  } else {
    /* Without LCK (i.e. read-only mode).
     * Walk through a snapshot of all running threads */
    mdbx_assert(env, env->me_flags & (MDBX_EXCLUSIVE | MDBX_RDONLY));
    const HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
      return (int)GetLastError();

    THREADENTRY32 entry;
    entry.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &entry)) {
      rc = (int)GetLastError();
    bailout_toolhelp:
      CloseHandle(hSnapshot);
      (void)mdbx_resume_threads_after_remap(*array);
      return rc;
    }

    do {
      if (entry.th32OwnerProcessID != env->me_pid ||
          entry.th32ThreadID == CurrentTid)
        continue;

      rc = suspend_and_append(array, entry.th32ThreadID);
      if (rc != MDBX_SUCCESS)
        goto bailout_toolhelp;

    } while (Thread32Next(hSnapshot, &entry));

    rc = (int)GetLastError();
    if (rc != ERROR_NO_MORE_FILES)
      goto bailout_toolhelp;
    CloseHandle(hSnapshot);
  }

  return MDBX_SUCCESS;
}

MDBX_INTERNAL_FUNC int
mdbx_resume_threads_after_remap(mdbx_handle_array_t *array) {
  int rc = MDBX_SUCCESS;
  for (unsigned i = 0; i < array->count; ++i) {
    const HANDLE hThread = array->handles[i];
    if (ResumeThread(hThread) == (DWORD)-1) {
      const int err = (int)GetLastError();
      DWORD ExitCode;
      if (err != /* workaround for Win10 UCRT bug */ ERROR_ACCESS_DENIED &&
          GetExitCodeThread(hThread, &ExitCode) && ExitCode == STILL_ACTIVE)
        rc = err;
    }
    CloseHandle(hThread);
  }
  return rc;
}

/*----------------------------------------------------------------------------*/
/* global `initial` lock for lockfile initialization,
 * exclusive/shared locking first cacheline */

/* Briefly description of locking schema/algorithm:
 *  - Windows does not support upgrading or downgrading for file locking.
 *  - Therefore upgrading/downgrading is emulated by shared and exclusive
 *    locking of upper and lower halves.
 *  - In other words, we have FSM with possible 9 states,
 *    i.e. free/shared/exclusive x free/shared/exclusive == 9.
 *    Only 6 states of FSM are used, which 2 of ones are transitive.
 *
 * States:
 *   ?-?  = free, i.e. unlocked
 *   S-?  = used, i.e. shared lock
 *   E-?  = exclusive-read, i.e. operational exclusive
 *   ?-S
 *   ?-E  = middle (transitive state)
 *   S-S
 *   S-E  = locked (transitive state)
 *   E-S
 *   E-E  = exclusive-write, i.e. exclusive due (re)initialization
 *
 *  The mdbx_lck_seize() moves the locking-FSM from the initial free/unlocked
 *  state to the "exclusive write" (and returns MDBX_RESULT_TRUE) if possible,
 *  or to the "used" (and returns MDBX_RESULT_FALSE).
 *
 *  The mdbx_lck_downgrade() moves the locking-FSM from "exclusive write"
 *  state to the "used" (i.e. shared) state.
 *
 *  The mdbx_lck_upgrade() moves the locking-FSM from "used" (i.e. shared)
 *  state to the "exclusive write" state.
 */

static void lck_unlock(MDBX_env *env) {
  int err;

  if (env->me_lfd != INVALID_HANDLE_VALUE) {
    /* double `unlock` for robustly remove overlapped shared/exclusive locks */
    while (funlock(env->me_lfd, LCK_LOWER))
      ;
    err = (int)GetLastError();
    assert(err == ERROR_NOT_LOCKED ||
           (mdbx_RunningUnderWine() && err == ERROR_LOCK_VIOLATION));
    (void)err;
    SetLastError(ERROR_SUCCESS);

    while (funlock(env->me_lfd, LCK_UPPER))
      ;
    err = (int)GetLastError();
    assert(err == ERROR_NOT_LOCKED ||
           (mdbx_RunningUnderWine() && err == ERROR_LOCK_VIOLATION));
    (void)err;
    SetLastError(ERROR_SUCCESS);
  }

  if (env->me_lazy_fd != INVALID_HANDLE_VALUE) {
    /* explicitly unlock to avoid latency for other processes (windows kernel
     * releases such locks via deferred queues) */
    while (funlock(env->me_lazy_fd, LCK_BODY))
      ;
    err = (int)GetLastError();
    assert(err == ERROR_NOT_LOCKED ||
           (mdbx_RunningUnderWine() && err == ERROR_LOCK_VIOLATION));
    (void)err;
    SetLastError(ERROR_SUCCESS);

    while (funlock(env->me_lazy_fd, LCK_WHOLE))
      ;
    err = (int)GetLastError();
    assert(err == ERROR_NOT_LOCKED ||
           (mdbx_RunningUnderWine() && err == ERROR_LOCK_VIOLATION));
    (void)err;
    SetLastError(ERROR_SUCCESS);
  }
}

/* Seize state as 'exclusive-write' (E-E and returns MDBX_RESULT_TRUE)
 * or as 'used' (S-? and returns MDBX_RESULT_FALSE).
 * Otherwise returns an error. */
static int internal_seize_lck(HANDLE lfd) {
  int rc;
  assert(lfd != INVALID_HANDLE_VALUE);

  /* 1) now on ?-? (free), get ?-E (middle) */
  mdbx_jitter4testing(false);
  if (!flock(lfd, LCK_EXCLUSIVE | LCK_WAITFOR, LCK_UPPER)) {
    rc = (int)GetLastError() /* 2) something went wrong, give up */;
    mdbx_error("%s, err %u", "?-?(free) >> ?-E(middle)", rc);
    return rc;
  }

  /* 3) now on ?-E (middle), try E-E (exclusive-write) */
  mdbx_jitter4testing(false);
  if (flock(lfd, LCK_EXCLUSIVE | LCK_DONTWAIT, LCK_LOWER))
    return MDBX_RESULT_TRUE /* 4) got E-E (exclusive-write), done */;

  /* 5) still on ?-E (middle) */
  rc = (int)GetLastError();
  mdbx_jitter4testing(false);
  if (rc != ERROR_SHARING_VIOLATION && rc != ERROR_LOCK_VIOLATION) {
    /* 6) something went wrong, give up */
    if (!funlock(lfd, LCK_UPPER))
      mdbx_panic("%s(%s) failed: err %u", __func__, "?-E(middle) >> ?-?(free)",
                 (int)GetLastError());
    return rc;
  }

  /* 7) still on ?-E (middle), try S-E (locked) */
  mdbx_jitter4testing(false);
  rc = flock(lfd, LCK_SHARED | LCK_DONTWAIT, LCK_LOWER) ? MDBX_RESULT_FALSE
                                                        : (int)GetLastError();

  mdbx_jitter4testing(false);
  if (rc != MDBX_RESULT_FALSE)
    mdbx_error("%s, err %u", "?-E(middle) >> S-E(locked)", rc);

  /* 8) now on S-E (locked) or still on ?-E (middle),
   *    transition to S-? (used) or ?-? (free) */
  if (!funlock(lfd, LCK_UPPER))
    mdbx_panic("%s(%s) failed: err %u", __func__,
               "X-E(locked/middle) >> X-?(used/free)", (int)GetLastError());

  /* 9) now on S-? (used, DONE) or ?-? (free, FAILURE) */
  return rc;
}

MDBX_INTERNAL_FUNC int mdbx_lck_seize(MDBX_env *env) {
  int rc;

  assert(env->me_lazy_fd != INVALID_HANDLE_VALUE);
  if (env->me_flags & MDBX_EXCLUSIVE)
    return MDBX_RESULT_TRUE /* nope since files were must be opened
                               non-shareable */
        ;

  if (env->me_lfd == INVALID_HANDLE_VALUE) {
    /* LY: without-lck mode (e.g. on read-only filesystem) */
    mdbx_jitter4testing(false);
    if (!flock(env->me_lazy_fd, LCK_SHARED | LCK_DONTWAIT, LCK_WHOLE)) {
      rc = (int)GetLastError();
      mdbx_error("%s, err %u", "without-lck", rc);
      return rc;
    }
    return MDBX_RESULT_FALSE;
  }

  rc = internal_seize_lck(env->me_lfd);
  mdbx_jitter4testing(false);
  if (rc == MDBX_RESULT_TRUE && (env->me_flags & MDBX_RDONLY) == 0) {
    /* Check that another process don't operates in without-lck mode.
     * Doing such check by exclusive locking the body-part of db. Should be
     * noted:
     *  - we need an exclusive lock for do so;
     *  - we can't lock meta-pages, otherwise other process could get an error
     *    while opening db in valid (non-conflict) mode. */
    if (!flock(env->me_lazy_fd, LCK_EXCLUSIVE | LCK_DONTWAIT, LCK_BODY)) {
      rc = (int)GetLastError();
      mdbx_error("%s, err %u", "lock-against-without-lck", rc);
      mdbx_jitter4testing(false);
      lck_unlock(env);
    } else {
      mdbx_jitter4testing(false);
      if (!funlock(env->me_lazy_fd, LCK_BODY))
        mdbx_panic("%s(%s) failed: err %u", __func__,
                   "unlock-against-without-lck", (int)GetLastError());
    }
  }

  return rc;
}

MDBX_INTERNAL_FUNC int mdbx_lck_downgrade(MDBX_env *env) {
  /* Transite from exclusive-write state (E-E) to used (S-?) */
  assert(env->me_lazy_fd != INVALID_HANDLE_VALUE);
  assert(env->me_lfd != INVALID_HANDLE_VALUE);

  if (env->me_flags & MDBX_EXCLUSIVE)
    return MDBX_SUCCESS /* nope since files were must be opened non-shareable */
        ;
  /* 1) now at E-E (exclusive-write), transition to ?_E (middle) */
  if (!funlock(env->me_lfd, LCK_LOWER))
    mdbx_panic("%s(%s) failed: err %u", __func__,
               "E-E(exclusive-write) >> ?-E(middle)", (int)GetLastError());

  /* 2) now at ?-E (middle), transition to S-E (locked) */
  if (!flock(env->me_lfd, LCK_SHARED | LCK_DONTWAIT, LCK_LOWER)) {
    int rc = (int)GetLastError() /* 3) something went wrong, give up */;
    mdbx_error("%s, err %u", "?-E(middle) >> S-E(locked)", rc);
    return rc;
  }

  /* 4) got S-E (locked), continue transition to S-? (used) */
  if (!funlock(env->me_lfd, LCK_UPPER))
    mdbx_panic("%s(%s) failed: err %u", __func__, "S-E(locked) >> S-?(used)",
               (int)GetLastError());

  return MDBX_SUCCESS /* 5) now at S-? (used), done */;
}

MDBX_INTERNAL_FUNC int mdbx_lck_upgrade(MDBX_env *env) {
  /* Transite from used state (S-?) to exclusive-write (E-E) */
  assert(env->me_lfd != INVALID_HANDLE_VALUE);

  if (env->me_flags & MDBX_EXCLUSIVE)
    return MDBX_SUCCESS /* nope since files were must be opened non-shareable */
        ;

  int rc;
  /* 1) now on S-? (used), try S-E (locked) */
  mdbx_jitter4testing(false);
  if (!flock(env->me_lfd, LCK_EXCLUSIVE | LCK_DONTWAIT, LCK_UPPER)) {
    rc = (int)GetLastError() /* 2) something went wrong, give up */;
    mdbx_verbose("%s, err %u", "S-?(used) >> S-E(locked)", rc);
    return rc;
  }

  /* 3) now on S-E (locked), transition to ?-E (middle) */
  if (!funlock(env->me_lfd, LCK_LOWER))
    mdbx_panic("%s(%s) failed: err %u", __func__, "S-E(locked) >> ?-E(middle)",
               (int)GetLastError());

  /* 4) now on ?-E (middle), try E-E (exclusive-write) */
  mdbx_jitter4testing(false);
  if (!flock(env->me_lfd, LCK_EXCLUSIVE | LCK_DONTWAIT, LCK_LOWER)) {
    rc = (int)GetLastError() /* 5) something went wrong, give up */;
    mdbx_verbose("%s, err %u", "?-E(middle) >> E-E(exclusive-write)", rc);
    return rc;
  }

  return MDBX_SUCCESS /* 6) now at E-E (exclusive-write), done */;
}

MDBX_INTERNAL_FUNC int mdbx_lck_init(MDBX_env *env,
                                     MDBX_env *inprocess_neighbor,
                                     int global_uniqueness_flag) {
  (void)env;
  (void)inprocess_neighbor;
  (void)global_uniqueness_flag;
  return MDBX_SUCCESS;
}

MDBX_INTERNAL_FUNC int mdbx_lck_destroy(MDBX_env *env,
                                        MDBX_env *inprocess_neighbor) {
  /* LY: should unmap before releasing the locks to avoid race condition and
   * STATUS_USER_MAPPED_FILE/ERROR_USER_MAPPED_FILE */
  if (env->me_map)
    mdbx_munmap(&env->me_dxb_mmap);
  if (env->me_lck_mmap.lck) {
    const bool synced = env->me_lck_mmap.lck->mti_unsynced_pages.weak == 0;
    mdbx_munmap(&env->me_lck_mmap);
    if (synced && !inprocess_neighbor && env->me_lfd != INVALID_HANDLE_VALUE &&
        mdbx_lck_upgrade(env) == MDBX_SUCCESS)
      /* this will fail if LCK is used/mmapped by other process(es) */
      mdbx_ftruncate(env->me_lfd, 0);
  }
  lck_unlock(env);
  return MDBX_SUCCESS;
}

/*----------------------------------------------------------------------------*/
/* reader checking (by pid) */

MDBX_INTERNAL_FUNC int mdbx_rpid_set(MDBX_env *env) {
  (void)env;
  return MDBX_SUCCESS;
}

MDBX_INTERNAL_FUNC int mdbx_rpid_clear(MDBX_env *env) {
  (void)env;
  return MDBX_SUCCESS;
}

/* Checks reader by pid.
 *
 * Returns:
 *   MDBX_RESULT_TRUE, if pid is live (unable to acquire lock)
 *   MDBX_RESULT_FALSE, if pid is dead (lock acquired)
 *   or otherwise the errcode. */
MDBX_INTERNAL_FUNC int mdbx_rpid_check(MDBX_env *env, uint32_t pid) {
  (void)env;
  HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, pid);
  int rc;
  if (likely(hProcess)) {
    rc = WaitForSingleObject(hProcess, 0);
    if (unlikely(rc == (int)WAIT_FAILED))
      rc = (int)GetLastError();
    CloseHandle(hProcess);
  } else {
    rc = (int)GetLastError();
  }

  switch (rc) {
  case ERROR_INVALID_PARAMETER:
    /* pid seems invalid */
    return MDBX_RESULT_FALSE;
  case WAIT_OBJECT_0:
    /* process just exited */
    return MDBX_RESULT_FALSE;
  case ERROR_ACCESS_DENIED:
    /* The ERROR_ACCESS_DENIED would be returned for CSRSS-processes, etc.
     * assume pid exists */
    return MDBX_RESULT_TRUE;
  case WAIT_TIMEOUT:
    /* pid running */
    return MDBX_RESULT_TRUE;
  default:
    /* failure */
    return rc;
  }
}

//----------------------------------------------------------------------------
// Stub for slim read-write lock
// Copyright (C) 1995-2002 Brad Wilson

static void WINAPI stub_srwlock_Init(MDBX_srwlock *srwl) {
  srwl->readerCount = srwl->writerCount = 0;
}

static void WINAPI stub_srwlock_AcquireShared(MDBX_srwlock *srwl) {
  while (true) {
    assert(srwl->writerCount >= 0 && srwl->readerCount >= 0);

    //  If there's a writer already, spin without unnecessarily
    //  interlocking the CPUs
    if (srwl->writerCount != 0) {
      YieldProcessor();
      continue;
    }

    //  Add to the readers list
    _InterlockedIncrement(&srwl->readerCount);

    // Check for writers again (we may have been preempted). If
    // there are no writers writing or waiting, then we're done.
    if (srwl->writerCount == 0)
      break;

    // Remove from the readers list, spin, try again
    _InterlockedDecrement(&srwl->readerCount);
    YieldProcessor();
  }
}

static void WINAPI stub_srwlock_ReleaseShared(MDBX_srwlock *srwl) {
  assert(srwl->readerCount > 0);
  _InterlockedDecrement(&srwl->readerCount);
}

static void WINAPI stub_srwlock_AcquireExclusive(MDBX_srwlock *srwl) {
  while (true) {
    assert(srwl->writerCount >= 0 && srwl->readerCount >= 0);

    //  If there's a writer already, spin without unnecessarily
    //  interlocking the CPUs
    if (srwl->writerCount != 0) {
      YieldProcessor();
      continue;
    }

    // See if we can become the writer (expensive, because it inter-
    // locks the CPUs, so writing should be an infrequent process)
    if (_InterlockedExchange(&srwl->writerCount, 1) == 0)
      break;
  }

  // Now we're the writer, but there may be outstanding readers.
  // Spin until there aren't any more; new readers will wait now
  // that we're the writer.
  while (srwl->readerCount != 0) {
    assert(srwl->writerCount >= 0 && srwl->readerCount >= 0);
    YieldProcessor();
  }
}

static void WINAPI stub_srwlock_ReleaseExclusive(MDBX_srwlock *srwl) {
  assert(srwl->writerCount == 1 && srwl->readerCount >= 0);
  srwl->writerCount = 0;
}

static uint64_t WINAPI stub_GetTickCount64(void) {
  LARGE_INTEGER Counter, Frequency;
  return (QueryPerformanceFrequency(&Frequency) &&
          QueryPerformanceCounter(&Counter))
             ? Counter.QuadPart * 1000ul / Frequency.QuadPart
             : 0;
}

/*----------------------------------------------------------------------------*/

#ifndef xMDBX_ALLOY
MDBX_srwlock_function mdbx_srwlock_Init, mdbx_srwlock_AcquireShared,
    mdbx_srwlock_ReleaseShared, mdbx_srwlock_AcquireExclusive,
    mdbx_srwlock_ReleaseExclusive;

MDBX_NtExtendSection mdbx_NtExtendSection;
MDBX_GetFileInformationByHandleEx mdbx_GetFileInformationByHandleEx;
MDBX_GetVolumeInformationByHandleW mdbx_GetVolumeInformationByHandleW;
MDBX_GetFinalPathNameByHandleW mdbx_GetFinalPathNameByHandleW;
MDBX_SetFileInformationByHandle mdbx_SetFileInformationByHandle;
MDBX_NtFsControlFile mdbx_NtFsControlFile;
MDBX_PrefetchVirtualMemory mdbx_PrefetchVirtualMemory;
MDBX_GetTickCount64 mdbx_GetTickCount64;
MDBX_RegGetValueA mdbx_RegGetValueA;
#endif /* xMDBX_ALLOY */

#if __GNUC_PREREQ(8, 0)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif /* GCC/MINGW */

static void mdbx_winnt_import(void) {
  const HINSTANCE hNtdll = GetModuleHandleA("ntdll.dll");

#define GET_PROC_ADDR(dll, ENTRY)                                              \
  mdbx_##ENTRY = (MDBX_##ENTRY)GetProcAddress(dll, #ENTRY)

  if (GetProcAddress(hNtdll, "wine_get_version")) {
    assert(mdbx_RunningUnderWine());
  } else {
    GET_PROC_ADDR(hNtdll, NtFsControlFile);
    GET_PROC_ADDR(hNtdll, NtExtendSection);
    assert(!mdbx_RunningUnderWine());
  }

  const HINSTANCE hKernel32dll = GetModuleHandleA("kernel32.dll");
  GET_PROC_ADDR(hKernel32dll, GetFileInformationByHandleEx);
  GET_PROC_ADDR(hKernel32dll, GetTickCount64);
  if (!mdbx_GetTickCount64)
    mdbx_GetTickCount64 = stub_GetTickCount64;
  if (!mdbx_RunningUnderWine()) {
    GET_PROC_ADDR(hKernel32dll, SetFileInformationByHandle);
    GET_PROC_ADDR(hKernel32dll, GetVolumeInformationByHandleW);
    GET_PROC_ADDR(hKernel32dll, GetFinalPathNameByHandleW);
    GET_PROC_ADDR(hKernel32dll, PrefetchVirtualMemory);
  }

  const HINSTANCE hAdvapi32dll = GetModuleHandleA("advapi32.dll");
  GET_PROC_ADDR(hAdvapi32dll, RegGetValueA);
#undef GET_PROC_ADDR

  const MDBX_srwlock_function init =
      (MDBX_srwlock_function)GetProcAddress(hKernel32dll, "InitializeSRWLock");
  if (init != NULL) {
    mdbx_srwlock_Init = init;
    mdbx_srwlock_AcquireShared = (MDBX_srwlock_function)GetProcAddress(
        hKernel32dll, "AcquireSRWLockShared");
    mdbx_srwlock_ReleaseShared = (MDBX_srwlock_function)GetProcAddress(
        hKernel32dll, "ReleaseSRWLockShared");
    mdbx_srwlock_AcquireExclusive = (MDBX_srwlock_function)GetProcAddress(
        hKernel32dll, "AcquireSRWLockExclusive");
    mdbx_srwlock_ReleaseExclusive = (MDBX_srwlock_function)GetProcAddress(
        hKernel32dll, "ReleaseSRWLockExclusive");
  } else {
    mdbx_srwlock_Init = stub_srwlock_Init;
    mdbx_srwlock_AcquireShared = stub_srwlock_AcquireShared;
    mdbx_srwlock_ReleaseShared = stub_srwlock_ReleaseShared;
    mdbx_srwlock_AcquireExclusive = stub_srwlock_AcquireExclusive;
    mdbx_srwlock_ReleaseExclusive = stub_srwlock_ReleaseExclusive;
  }
}

#if __GNUC_PREREQ(8, 0)
#pragma GCC diagnostic pop
#endif /* GCC/MINGW */

#endif /* Windows LCK-implementation */
