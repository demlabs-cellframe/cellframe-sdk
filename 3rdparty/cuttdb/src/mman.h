#ifndef _MMAN_H_
#define _MMAN_H_

#include <_mingw.h>
#include <stdint.h>
#include <io.h>

#if defined(_WIN64)
typedef int64_t offset_t;
#else
typedef uint32_t offset_t;
#endif

#include <sys/types.h>
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif

#define PROT_NONE       0
#define PROT_READ       1
#define PROT_WRITE      2
#define PROT_EXEC       4

#define MAP_FILE        0
#define MAP_SHARED      1
#define MAP_PRIVATE     2
#define MAP_TYPE        0xf
#define MAP_FIXED       0x10
#define MAP_ANONYMOUS   0x20
#define MAP_ANON        MAP_ANONYMOUS

#define MAP_FAILED      ((void *)-1)

#define MS_ASYNC        1
#define MS_SYNC         2
#define MS_INVALIDATE   4

#define fdatasync(fd) _commit(fd)

void*   mmap(void *addr, size_t len, int prot, int flags, int fildes, offset_t offset);
int     munmap(void *addr, size_t len);
int     _mprotect(void *addr, size_t len, int prot);
int     msync(void *addr, size_t len, int flags);
int     mlock(const void *addr, size_t len);
int     munlock(const void *addr, size_t len);

ssize_t pread(int fd, void *buf, unsigned long count, offset_t offset);
ssize_t pwrite(int fd, const void *buf, unsigned long count, offset_t offset);

#ifdef __cplusplus
}
#endif

#endif /*  _MMAN_H_ */
