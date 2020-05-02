/*
 * mman-win32 library
 * https://code.google.com/p/mman-win32/
 * reinterpreted by Konstantin Papizh <konstantin.papizh@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 */

#include <windows.h>
#include <errno.h>
#include <stdio.h>
#include "mman.h"

static DWORD __map_mmap_prot_page(const int prot) {
    DWORD protect = 0;
    
    if (prot == PROT_NONE)
        return protect;
        
    if ((prot & PROT_EXEC) != 0) {
        protect = ((prot & PROT_WRITE) != 0) ? 
                    PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    } else {
        protect = ((prot & PROT_WRITE) != 0) ?
                    PAGE_READWRITE : PAGE_READONLY;
    }
    return protect;
}

static DWORD __map_mmap_prot_file(const int prot) {

    DWORD desiredAccess = 0;
    if (prot == PROT_NONE)
        return desiredAccess;
        
    if ((prot & PROT_READ) != 0)
        desiredAccess |= FILE_MAP_READ;
    if ((prot & PROT_WRITE) != 0)
        desiredAccess |= FILE_MAP_WRITE;
    if ((prot & PROT_EXEC) != 0)
        desiredAccess |= FILE_MAP_EXECUTE;
    
    return desiredAccess;
}

void* mmap(void *addr, size_t len, int prot, int flags, int fildes, offset_t off)
{
    HANDLE fm, h;
    void *map = MAP_FAILED;

    const DWORD dwFileOffsetLow = (sizeof(offset_t) <= sizeof(DWORD)) ?
                    (DWORD)off : (DWORD)(off & 0xFFFFFFFFL);
    const DWORD dwFileOffsetHigh = (sizeof(offset_t) <= sizeof(DWORD)) ?
                    (DWORD)0 : (DWORD)((off >> 32) & 0xFFFFFFFF00000000L);
    const DWORD protect = __map_mmap_prot_page(prot);
    const DWORD desiredAccess = __map_mmap_prot_file(prot);

    const offset_t maxSize = off + (offset_t)len;

    const DWORD dwMaxSizeLow = (sizeof(offset_t) <= sizeof(DWORD)) ?
                    (DWORD)maxSize : (DWORD)(maxSize & 0xFFFFFFFFL);
    const DWORD dwMaxSizeHigh = (sizeof(offset_t) <= sizeof(DWORD)) ?
                    (DWORD)0 : (DWORD)((maxSize >> 32) & 0xFFFFFFFF00000000L);
    _set_errno(0);
    
    if (len == 0 || prot == PROT_EXEC) {
        _set_errno(EINVAL);
        return MAP_FAILED;
    }
    
    h = ((flags & MAP_ANONYMOUS) == 0) ? 
                    (HANDLE)_get_osfhandle(fildes) : INVALID_HANDLE_VALUE;

    if ((flags & MAP_ANONYMOUS) == 0 && h == INVALID_HANDLE_VALUE) {
        _set_errno(EBADF);
        return MAP_FAILED;
    }

    fm = CreateFileMapping(h, NULL, protect, dwMaxSizeHigh, dwMaxSizeLow, NULL);

    if (fm == NULL) {
        int a = errno;
        _set_errno(GetLastError());
        a = errno;
        printf("%d", a);
        return MAP_FAILED;
    }
  
    if ((flags & MAP_FIXED) == 0) {
        map = MapViewOfFile(fm, desiredAccess, dwFileOffsetHigh, dwFileOffsetLow, len);
    }
    else {
        map = MapViewOfFileEx(fm, desiredAccess, dwFileOffsetHigh, dwFileOffsetLow, len, addr);
    }
    CloseHandle(fm);

    if (map == NULL) {
        _set_errno(GetLastError());
        return MAP_FAILED;
    }
    return map;
}

int munmap(void *addr, size_t len) {
    if (UnmapViewOfFile(addr))
        return 0;
        
    _set_errno(GetLastError());
    return -1;
}

int _mprotect(void *addr, size_t len, int prot) {
    DWORD newProtect = __map_mmap_prot_page(prot);
    DWORD oldProtect = 0;
    
    if (VirtualProtect(addr, len, newProtect, &oldProtect))
        return 0;
    _set_errno(GetLastError());
    return -1;
}

int msync(void *addr, size_t len, int flags) {
    if (FlushViewOfFile(addr, len))
        return 0;
    _set_errno(GetLastError());
    return -1;
}

int mlock(const void *addr, size_t len) {
    if (VirtualLock((LPVOID)addr, len))
        return 0;
    _set_errno(GetLastError());
    return -1;
}

int munlock(const void *addr, size_t len) {
    if (VirtualUnlock((LPVOID)addr, len))
        return 0;
    _set_errno(GetLastError());
    return -1;
}

ssize_t pread(int fd, void *buf, unsigned long count, offset_t offset) {
    unsigned long len = 0;

    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(OVERLAPPED));
    overlapped.OffsetHigh = (uint32_t)((offset & 0xFFFFFFFF00000000LL) >> 32);
    overlapped.Offset = (uint32_t)(offset & 0xFFFFFFFFLL);

    HANDLE file = (HANDLE)_get_osfhandle(fd);
    if ((!ReadFile(file, buf, count, &len, &overlapped)) && GetLastError() != ERROR_HANDLE_EOF) {
        _set_errno(GetLastError());
        return -1;
    }
    return len;
}

ssize_t pwrite(int fd, const void *buf, unsigned long count, offset_t offset) {
    long unsigned int len = 0;

    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(OVERLAPPED));
    overlapped.OffsetHigh = (uint32_t)((offset & 0xFFFFFFFF00000000LL) >> 32);
    overlapped.Offset = (uint32_t)(offset & 0xFFFFFFFFLL);

    HANDLE file = (HANDLE)_get_osfhandle(fd);
    if (!WriteFile(file, buf, count, &len, &overlapped)) {
        _set_errno(GetLastError());
        return -1;
    }
    return len;
}
