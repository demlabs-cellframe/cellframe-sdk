
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <thread.h>
#include <pthread.h>

#ifdef _MSC_VER
#  define ATTRIBUTE_NORETURN
#else
#  define ATTRIBUTE_NORETURN __attribute__((noreturn))
#endif

#ifdef _WIN32
#  include <windows.h>
#  include <process.h>

static unsigned __stdcall
thread_entry(void* argptr) {
  thread_arg* arg = argptr;
  arg->fn(arg->arg);
  return 0;
}

#else
#  include <time.h>
#  include <pthread.h>
#  include <sched.h>

#if !defined(__x86_64__) && !defined(_AMD64_) && !defined(_M_AMD64) && !defined(__i386__)
#  define MEMORY_BARRIER __sync_synchronize()
#else
#  define MEMORY_BARRIER __asm__ __volatile__("":::"memory")
#endif

static void*
thread_entry(void* argptr) {
  thread_arg* arg = argptr;
  arg->fn(arg->arg);
  return 0;
}

#endif

uintptr_t
thread_run(thread_arg* arg) {
#ifdef _WIN32
  return _beginthreadex(0, 0, thread_entry, arg, 0, 0);
#else
  pthread_t id = 0;
  int err = pthread_create(&id, 0, thread_entry, arg);
  if (err)
    return 0;
  return (uintptr_t)id;
#endif
}

void ATTRIBUTE_NORETURN
thread_exit(uintptr_t value) {
#ifdef _WIN32
  _endthreadex((unsigned)value);
#else
  pthread_exit((void*)value);
#endif
}

uintptr_t
thread_join(uintptr_t handle) {
  if (!handle)
    return (uintptr_t)-1;
  uintptr_t ret;
#ifdef _WIN32
  DWORD exit_code = 0;
  WaitForSingleObject((HANDLE)handle, INFINITE);
  GetExitCodeThread((HANDLE)handle, &exit_code);
  CloseHandle((HANDLE)handle);
  ret = exit_code;
#else
  void* result = 0;
  pthread_join((pthread_t)handle, &result);
  ret = (uintptr_t)result;
#endif
  return ret;
}

void
thread_sleep(int milliseconds) {
#ifdef _WIN32
  SleepEx((DWORD)milliseconds, 0);
#else
  struct timespec ts;
  ts.tv_sec  = milliseconds / 1000;
  ts.tv_nsec = (long)(milliseconds % 1000) * 1000000L;
  nanosleep(&ts, 0);
#endif
}

void
thread_yield(void) {
#ifdef _WIN32
  Sleep(0);
  _ReadWriteBarrier();
#else
  sched_yield();
  MEMORY_BARRIER;
#endif
}

void
thread_fence(void) {
#ifdef _WIN32
  _ReadWriteBarrier();
#else
  MEMORY_BARRIER;
#endif
}
