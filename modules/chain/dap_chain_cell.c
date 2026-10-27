/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
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
#include "uthash.h"
#include <unistd.h>
#include "dap_chain.h"
#include "dap_chain_cell.h"

// Absolute file offset of the atom currently being fed to the chain from a
// non-mapped cell: the consensus layer stores it in the chain-state index so the
// same thin-restore/lazy-read path works without mmap.
static _Thread_local uint64_t s_loading_atom_offset;
// The bytes the loader is feeding right now (both mapped and non-mapped paths).
// A block cache entry created during a scan stays THIN (no body pointer, no
// private copy); the parse it needs for applying datums is then served from
// these already-read bytes instead of faulting the same range in a second time.
static _Thread_local const uint8_t *s_loading_atom_body;
static _Thread_local size_t s_loading_atom_body_size;

uint64_t dap_chain_cell_load_offset(void)
{
    return s_loading_atom_offset;
}

// Body of the atom the loader is feeding right now, when the caller's request
// matches it exactly (offset and size). During a full scan every block passes
// through the loader, so this replaces a per-block mapping/read with a pointer
// to bytes that are already in cache. Returns NULL when the hint does not match.
const uint8_t *dap_chain_cell_load_hint_view(size_t a_file_offset, size_t a_size)
{
    return (s_loading_atom_body && s_loading_atom_offset == (uint64_t)a_file_offset
            && s_loading_atom_body_size == a_size) ? s_loading_atom_body : NULL;
}

// Loader hint accessors, used by dap_chain_cell.c itself. The body pointer is
// published only by the mapped loader: its bytes live in a mapping that outlives
// the callback, while the non-mapped loader frees its read buffer as soon as the
// callback returns (a cache entry that kept such a pointer would dangle - and the
// ledger keeps datum pointers when it is mmap-backed). The non-mapped path still
// publishes the OFFSET: it is what lets a cache entry stay thin and read the body
// from the cell's own read-only view when it is needed.
static inline void s_cell_load_hint_set(uint64_t a_offset, const void *a_body, size_t a_size)
{
    s_loading_atom_offset = a_offset;
    s_loading_atom_body = (const uint8_t *)a_body;
    s_loading_atom_body_size = a_size;
}

static inline void s_cell_load_hint_set_offset(uint64_t a_offset)
{
    s_loading_atom_offset = a_offset;
    s_loading_atom_body = NULL;
    s_loading_atom_body_size = 0;
}

static inline void s_cell_load_hint_clear(void)
{
    s_loading_atom_offset = 0;
    s_loading_atom_body = NULL;
    s_loading_atom_body_size = 0;
}

#include "dap_chain_cs.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#ifdef DAP_OS_WINDOWS
#include <winternl.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif
#define LOG_TAG "dap_chain_cell"

#define DAP_CHAIN_CELL_FILE_VERSION 1
#define DAP_CHAIN_CELL_FILE_SIGNATURE 0xfa340bef153eba48
#define DAP_CHAIN_CELL_FILE_TYPE_RAW 0
#define DAP_CHAIN_CELL_FILE_TYPE_COMPRESSED 1
#define DAP_MAPPED_VOLUME_LIMIT ( 1 << 28 ) // 256 MB for now, may be should be configurable?
/**
  * @struct dap_chain_cell_file_header
  */
typedef struct dap_chain_cell_file_header
{
    uint64_t signature;
    uint32_t version;
    uint8_t type;
    dap_chain_id_t chain_id;
    dap_chain_net_id_t chain_net_id;
    dap_chain_cell_id_t cell_id;
} DAP_ALIGN_PACKED dap_chain_cell_file_header_t;

size_t dap_chain_cell_first_atom_offset(void)
{
    return sizeof(dap_chain_cell_file_header_t) + sizeof(uint64_t);
}

#ifdef DAP_OS_WINDOWS
typedef NTSTATUS (*pfn_NtCreateSection)(
    OUT PHANDLE SectionHandle, IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL PLARGE_INTEGER MaximumSize, IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes, IN OPTIONAL HANDLE FileHandle);
static pfn_NtCreateSection pfnNtCreateSection;

typedef enum _SECTION_INHERIT { ViewShare = 1, ViewUnmap = 2 } SECTION_INHERIT;
typedef NTSTATUS (*pfn_NtMapViewOfSection) (
    IN HANDLE SectionHandle, IN HANDLE ProcessHandle, IN OUT PVOID *BaseAddress,
    IN ULONG_PTR ZeroBits, IN SIZE_T CommitSize,
    IN OUT OPTIONAL PLARGE_INTEGER SectionOffset, IN OUT PSIZE_T ViewSize,
    IN SECTION_INHERIT InheritDisposition, IN ULONG AllocationType,
    IN ULONG Win32Protect);
static pfn_NtMapViewOfSection pfnNtMapViewOfSection;

typedef NTSTATUS (*pfn_NtUnmapViewOfSection) (
        IN HANDLE ProcessHandle, IN PVOID BaseAddress);
static pfn_NtUnmapViewOfSection pfnNtUnmapViewOfSection;

typedef NTSTATUS (*pfn_NtExtendSection) (
    IN HANDLE SectionHandle, IN PLARGE_INTEGER NewSectionSize);
static pfn_NtExtendSection pfnNtExtendSection;
#endif

static bool s_debug_more = false;

/**
 * @brief dap_chain_cell_init
 * current version simply returns 0
 * @return
 */
int dap_chain_cell_init(void)
{
    s_debug_more = dap_config_get_item_bool_default(g_config, "chain", "debug_more", false);
#ifdef DAP_OS_WINDOWS
    if ( dap_config_get_item_bool_default(g_config, "ledger", "mapped", true) ) {
        HMODULE ntdll = GetModuleHandle("ntdll.dll");
        if ( !ntdll )
            return log_it(L_CRITICAL, "Ntdll error"), -1;
        // GetProcAddress returns FARPROC; casting it straight to a specific
        // function-pointer type trips -Werror=cast-function-type (the CI MinGW
        // job treats warnings as errors). Routing through void* is the
        // conventional way to convert between function-pointer types here.
        pfnNtCreateSection      = (pfn_NtCreateSection)     (void *)GetProcAddress(ntdll, "NtCreateSection");
        pfnNtMapViewOfSection   = (pfn_NtMapViewOfSection)  (void *)GetProcAddress(ntdll, "NtMapViewOfSection");
        pfnNtExtendSection      = (pfn_NtExtendSection)     (void *)GetProcAddress(ntdll, "NtExtendSection");
        pfnNtUnmapViewOfSection = (pfn_NtUnmapViewOfSection)(void *)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    }
    
#endif
    //s_cells_path = dap_config_get_item_str(g_config,"resources","cells_storage");
    
    return  0;
}

#ifndef DAP_OS_WINDOWS
DAP_STATIC_INLINE void s_cell_reclaim_cur_volume(dap_chain_cell_t *a_cell) {
    if (
#ifdef MADV_PAGEOUT
    //madvise(a_cell->map, (size_t)(a_cell->map_end - a_cell->map), MADV_PAGEOUT) &&
#endif
    madvise(a_cell->map, (size_t)(a_cell->map_end - a_cell->map), MADV_DONTNEED) )
        log_it(L_ERROR, "Unable to reclaim the previous volume, errno %d: \"%s\"", errno, dap_strerror(errno));
}
#endif

DAP_STATIC_INLINE int s_cell_file_write_header(dap_chain_cell_t *a_cell)
{
    dap_chain_cell_file_header_t l_hdr = {
        .signature      = DAP_CHAIN_CELL_FILE_SIGNATURE,
        .version        = DAP_CHAIN_CELL_FILE_VERSION,
        .type           = DAP_CHAIN_CELL_FILE_TYPE_RAW,
        .chain_id       = a_cell->chain->id,
        .chain_net_id   = a_cell->chain->net_id,
        .cell_id        = a_cell->id
    };
    return fwrite(&l_hdr, sizeof(l_hdr), 1, a_cell->file_storage) ? fflush(a_cell->file_storage) : -1;
}

DAP_STATIC_INLINE int s_cell_map_new_volume(dap_chain_cell_t *a_cell, size_t a_fpos, bool a_load) {
#ifdef DAP_OS_WINDOWS
    HANDLE hSection = NULL;
    if ( !a_fpos ) {
        //if (a_cell->map_range_bounds)
        //    NtClose( (HANDLE)a_cell->map_range_bounds->data );
        off_t l_ssize = !fseeko(a_cell->file_storage, 0, SEEK_END) ? ftello(a_cell->file_storage) : -1;
        if (l_ssize < 0)
            return log_it(L_ERROR, "Can't get chain size, error %d: \"%s\"", errno, dap_strerror(errno)), -1;
        LARGE_INTEGER SectionSize = { 
            .QuadPart = l_ssize 
        };
        
        NTSTATUS err = pfnNtCreateSection(&hSection, SECTION_MAP_READ | SECTION_EXTEND_SIZE,
                                          NULL, &SectionSize, PAGE_READWRITE, SEC_RESERVE, (HANDLE)_get_osfhandle(fileno(a_cell->file_storage)));
        if ( !NT_SUCCESS(err) )
            return log_it(L_ERROR, "NtCreateSection() failed, status %08X", (unsigned)err), -1;
        a_cell->map_range_bounds = dap_list_append(a_cell->map_range_bounds, hSection);
    }
#endif
    size_t  l_map_size      = dap_page_roundup(DAP_MAPPED_VOLUME_LIMIT),
#ifdef DAP_OS_WINDOWS
            l_volume_start  = a_fpos ? dap_64k_rounddown(a_fpos)    : 0,
#else               
            l_volume_start  = a_fpos ? dap_page_rounddown(a_fpos)   : 0,
#endif                  
            l_offset        = a_fpos - l_volume_start;
#ifdef DAP_OS_WINDOWS
    hSection = (HANDLE)a_cell->map_range_bounds->data;
    a_cell->map = NULL;
    int err = 0;
    LARGE_INTEGER Offset = {
        .QuadPart = l_volume_start
    };
    err = pfnNtMapViewOfSection(hSection, GetCurrentProcess(), (HANDLE)&a_cell->map, 0, 0, 
                                &Offset, &l_map_size, ViewUnmap, MEM_RESERVE, PAGE_READONLY);
    if ( !NT_SUCCESS(err) )
        // NTSTATUS is a LONG (int) here, so "%lx" mismatched its type and the CI
        // MinGW job failed the file with -Werror=format. Print it as unsigned.
        return NtClose(hSection), log_it(L_ERROR, "NtMapViewOfSection() failed, status %08X",
                                         (unsigned)err), -1;
#else
    if (a_load)
        s_cell_reclaim_cur_volume(a_cell);
    if (( a_cell->map = mmap(NULL, l_map_size, PROT_READ, MAP_PRIVATE,
                             fileno(a_cell->file_storage), l_volume_start) ) == MAP_FAILED )
        return log_it(L_ERROR, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X" cannot be mapped, errno %d",
                                a_cell->file_storage_path, a_cell->id.uint64, errno), -1;
#ifdef DAP_OS_DARWIN
    a_cell->cur_vol_start = l_volume_start;
#endif
#endif
    a_cell->map_pos = a_cell->map + l_offset;
    a_cell->cur_vol_start = l_volume_start;
    a_cell->map_range_bounds = dap_list_append(a_cell->map_range_bounds, a_cell->map);
    a_cell->map_range_bounds = dap_list_append(a_cell->map_range_bounds, a_cell->map_end = a_cell->map + l_map_size);
#ifndef DAP_OS_WINDOWS
    // The volume's FILE position, kept beside its mapping: volumes are opened at
    // dap_page_rounddown(current position) while an atom straddles the 256 MB
    // boundary, so consecutive mappings OVERLAP in the file and a volume's file
    // start cannot be derived from the pointer list by summing lengths. Consumers
    // that map file offsets to volume bytes (dap_chain_cell_volume_view,
    // dap_chain_cell_volumes_trim_upto) read this third element of the triple.
    a_cell->map_range_bounds = dap_list_append(a_cell->map_range_bounds,
                                               (char *)(uintptr_t)l_volume_start);
    if (a_load)
        madvise(a_cell->map, l_map_size, MADV_SEQUENTIAL);
#endif
    return 0;
}

/**
 * @brief dap_chain_cell_find_by_id
 * get dap_chain_cell_t object by cell (shard) id
 * @param a_chain dap_chain_t object
 * @param a_cell_id dap_chain_cell_id_t cell (shard) id
 * @return dap_chain_cell_t* 
 */
int dap_chain_cell_map_window(dap_chain_cell_t *a_cell, size_t a_file_pos)
{
    if (!a_cell || !a_cell->map || !a_cell->map_end)
        return -1;
    size_t l_off = a_file_pos - a_cell->cur_vol_start;
    if (a_file_pos >= a_cell->cur_vol_start && a_cell->map + l_off < a_cell->map_end) {
        a_cell->map_pos = a_cell->map + l_off;
        return 0;
    }
    return s_cell_map_new_volume(a_cell, a_file_pos, true);
}

int dap_chain_cell_map_window_force(dap_chain_cell_t *a_cell, size_t a_file_pos)
{
    if (!a_cell || !a_cell->map)
        return -1;
    return s_cell_map_new_volume(a_cell, a_file_pos, true);
}

/* Lazy body reads: a thin (index-restored) block's body is served in place from
 * a read-only mapping of the cell file instead of a private heap copy. One heap
 * copy per touched body pinned a whole cell file per walk - on cf-mm-0 two
 * malloc arenas held ~15 GB each (one per network) with only 300 MB of free
 * chunks, which is exactly the "all blocks end up in memory" failure this
 * avoids. The window is kept separate from map/map_pos/map_end: those are the
 * loader/append cursor mutated by the loader without the reader's knowledge. */
#ifndef DAP_OS_WINDOWS
// Drops the resident pages of every window except a_keep (the one being served),
// leaving the mappings themselves in place. Called on a window switch: without
// it a sequential walk faults each 64 MB window in and all of them stay resident.
static void s_cell_read_win_advise_others(dap_chain_cell_t *a_cell, const void *a_keep);

#define DAP_CELL_READ_WINDOW (64u << 20)
static int s_cell_read_map_window(dap_chain_cell_t *a_cell, size_t a_fpos)
{
    // A private read-only descriptor: the shared file_storage stream is seeked
    // and written by the loader/append path, so touching it here would race with
    // the loader (and its ftello would report the loader's position, not ours).
    if (a_cell->read_fd < 0) {
        a_cell->read_fd = open(a_cell->file_storage_path, O_RDONLY | O_CLOEXEC);
        if (a_cell->read_fd < 0) {
            log_it(L_WARNING, "Chain cell \"%s\": cannot open for lazy reads, errno %d",
                   a_cell->file_storage_path, errno);
            return -1;
        }
    }
    struct stat l_st = {0};
    if (fstat(a_cell->read_fd, &l_st) || l_st.st_size <= 0)
        return -1;
    size_t l_file_size = (size_t)l_st.st_size;
    size_t l_page = (size_t)sysconf(_SC_PAGESIZE);
    size_t l_start = a_fpos & ~(l_page - 1);
    if (l_start >= l_file_size)
        return -1;
    size_t l_len = l_file_size - l_start;
    if (l_len > DAP_CELL_READ_WINDOW)
        l_len = DAP_CELL_READ_WINDOW;
    size_t l_map_len = dap_page_roundup(l_len);
    if (l_map_len > l_file_size - l_start)
        l_map_len = l_file_size - l_start;   // never map past EOF: a touched page would SIGBUS
    void *l_map = mmap(NULL, l_map_len, PROT_READ, MAP_PRIVATE, a_cell->read_fd, (off_t)l_start);
    if (l_map == MAP_FAILED) {
        log_it(L_WARNING, "Chain cell \"%s\": lazy-read window at %zu (len %zu) cannot be mapped, errno %d",
               a_cell->file_storage_path, l_start, l_map_len, errno);
        return -1;
    }
    madvise(l_map, l_map_len, MADV_RANDOM);
    // Every older window has its resident pages advised away here. They are clean
    // file pages of an append-only file, so MADV_DONTNEED only drops residency -
    // the mapping and every pointer into it stay valid, and the next touch reads
    // the same bytes back from disk. Without this sweep a walk gradually faulted
    // whole windows in and kept them (live on cf-mm-0: dozens of 64 MB windows
    // per chain stayed resident, ~6 GB). The sweep runs once per window switch,
    // i.e. once per DAP_CELL_READ_WINDOW bytes walked.
    s_cell_read_win_advise_others(a_cell, l_map);
    a_cell->read_map = l_map;
    a_cell->read_map_start = l_start;
    a_cell->read_map_size = l_map_len;
    // One list entry per window with its file start, so a lookup can tell whether
    // an existing window already covers the requested range.
    dap_chain_cell_read_win_t *l_win = DAP_NEW_Z(dap_chain_cell_read_win_t);
    if (!l_win) {
        munmap(l_map, l_map_len);
        a_cell->read_map = NULL;
        a_cell->read_map_size = 0;
        return -1;
    }
    *l_win = (dap_chain_cell_read_win_t){ .ptr = l_map, .file_start = l_start, .len = l_map_len };
    a_cell->read_windows = dap_list_append(a_cell->read_windows, l_win);
    return 0;
}

// Drops the resident pages of every window except a_keep (the one being served),
// leaving the mappings themselves in place. Called on a window switch: without
// it a sequential walk faults each 64 MB window in and all of them stay resident.
static void s_cell_read_win_advise_others(dap_chain_cell_t *a_cell, const void *a_keep)
{
    for (dap_list_t *l_i = a_cell->read_windows; l_i; l_i = l_i->next) {
        dap_chain_cell_read_win_t *l_old = (dap_chain_cell_read_win_t *)l_i->data;
        if (l_old && l_old->ptr && l_old->len && l_old->ptr != a_keep)
            madvise(l_old->ptr, l_old->len, MADV_DONTNEED);
    }
}

// Reuses an existing window that already covers [a_file_offset, +a_size).
static const uint8_t *s_cell_read_win_lookup(dap_chain_cell_t *a_cell, size_t a_file_offset, size_t a_size)
{
    for (dap_list_t *l_i = a_cell->read_windows; l_i; l_i = l_i->next) {
        dap_chain_cell_read_win_t *l_w = (dap_chain_cell_read_win_t *)l_i->data;
        if (!l_w)
            continue;
        if (a_file_offset >= l_w->file_start && a_file_offset + a_size <= l_w->file_start + l_w->len) {
            if (a_cell->read_map != l_w->ptr) {
                // Switching windows: drop every other window's resident pages.
                // MADV_DONTNEED on a clean file mapping only discards residency -
                // the mapping, every pointer into it and the bytes read back are
                // unchanged (the file is append-only). Skipping this was the leak:
                // a walk that kept hitting already-mapped windows never created a
                // new one, so nothing was ever advised away and the whole chain
                // stayed resident through the view windows.
                s_cell_read_win_advise_others(a_cell, l_w->ptr);
            }
            a_cell->read_map = l_w->ptr;
            a_cell->read_map_start = l_w->file_start;
            a_cell->read_map_size = l_w->len;
            return (const uint8_t *)l_w->ptr + (a_file_offset - l_w->file_start);
        }
    }
    return NULL;
}

const uint8_t *dap_chain_cell_body_view(dap_chain_cell_t *a_cell, size_t a_file_offset, size_t a_size)
{
    if (!a_cell || !a_cell->file_storage || !a_size)
        return NULL;
    pthread_mutex_lock(&a_cell->read_map_mutex);
    const uint8_t *l_ret = s_cell_read_win_lookup(a_cell, a_file_offset, a_size);
    // Not covered: map a window at this offset. A caller alternating between two
    // distant regions (the snapshot restore and the wallet pass do) then hits the
    // lookup above on every switch instead of mapping a window per switch.
    if (!l_ret && !s_cell_read_map_window(a_cell, a_file_offset))
        l_ret = s_cell_read_win_lookup(a_cell, a_file_offset, a_size);
    pthread_mutex_unlock(&a_cell->read_map_mutex);
    return l_ret;
}

// Borrowed view of a range served from the LOADER's volumes (map_range_bounds),
// when the range lies inside one of them. Unlike the lazy-read windows these
// mappings are never unmapped while the cell lives (the loader only ever adds
// volumes, and an in-place rewrite drops the whole cache), so a pointer obtained
// here may be KEPT in a long-lived structure - that is exactly what the block
// cache does with a body it parses (entry->block). Returns NULL when no existing
// volume covers the range, which is the normal case on a no-scan start (only the
// volume it resumed in is mapped).
//
// The list keeps a (base, end, file_start) triple per volume: the volumes are
// opened at dap_page_rounddown(current position) while an atom straddles the
// volume boundary, so consecutive mappings overlap in the file and a volume's
// file start is only known from the value its open recorded.
const uint8_t *dap_chain_cell_volume_view(dap_chain_cell_t *a_cell, size_t a_file_offset, size_t a_size)
{
#ifndef DAP_OS_WINDOWS
    if (!a_cell || !a_cell->map_range_bounds || !a_size)
        return NULL;
    for (dap_list_t *l_i = a_cell->map_range_bounds; l_i && l_i->next && l_i->next->next; l_i = l_i->next->next->next) {
        char *l_base = (char *)l_i->data;
        char *l_end = (char *)l_i->next->data;
        size_t l_file_start = (size_t)(uintptr_t)l_i->next->next->data;
        if (!l_base || l_end <= l_base)
            break;   // malformed triple: stop rather than compute a bogus range
        size_t l_len = (size_t)(l_end - l_base);
        if (a_file_offset >= l_file_start && a_file_offset + a_size <= l_file_start + l_len)
            return (const uint8_t *)l_base + (a_file_offset - l_file_start);
    }
#else
    (void)a_cell; (void)a_file_offset; (void)a_size;
#endif
    return NULL;
}

void dap_chain_cell_read_window_stats(dap_chain_cell_t *a_cell, size_t *a_window_bytes, size_t *a_views)
{
    if (a_window_bytes)
        *a_window_bytes = a_cell ? a_cell->read_map_size : 0;
    if (!a_cell || !a_views) {
        if (a_views) *a_views = 0;
        return;
    }
    // Window count is the number of mapped ranges: entries are per window now,
    // and each is released only when the cell closes (or on an in-place rewrite).
    size_t l_n = 0;
    pthread_mutex_lock(&a_cell->read_map_mutex);
    for (dap_list_t *l_i = a_cell->read_windows; l_i; l_i = l_i->next)
        ++l_n;
    pthread_mutex_unlock(&a_cell->read_map_mutex);
    *a_views = l_n;
}

// Drops every lazy-read window. Called when the file is rewritten in place
// (rewind/purge): the bytes behind those mappings are gone, so serving a body
// from them would hand out stale or truncated data. A rewrite happens only on a
// purge/rollback, which clears the block cache as well - no cache entry can
// still hold a pointer into these windows afterwards.
void dap_chain_cell_read_windows_drop(dap_chain_cell_t *a_cell)
{
#ifndef DAP_OS_WINDOWS
    if (!a_cell)
        return;
    pthread_mutex_lock(&a_cell->read_map_mutex);
    for (dap_list_t *l_i = a_cell->read_windows; l_i; l_i = l_i->next) {
        dap_chain_cell_read_win_t *l_w = (dap_chain_cell_read_win_t *)l_i->data;
        if (l_w && l_w->ptr && l_w->len)
            munmap(l_w->ptr, l_w->len);
        DAP_DELETE(l_w);
    }
    dap_list_free(a_cell->read_windows);
    a_cell->read_windows = NULL;
    a_cell->read_map = NULL;
    a_cell->read_map_size = 0;
    a_cell->read_map_start = 0;
    if (a_cell->read_fd >= 0) {
        // The descriptor is dropped too: the rewrite may be a reopen of a
        // different inode (freopen), and a stale fd would keep serving the old
        // file's bytes.
        close(a_cell->read_fd);
        a_cell->read_fd = -1;
    }
    pthread_mutex_unlock(&a_cell->read_map_mutex);
#else
    (void)a_cell;
#endif
}
#else /* DAP_OS_WINDOWS */
const uint8_t *dap_chain_cell_volume_view(dap_chain_cell_t *a_cell, size_t a_file_offset, size_t a_size)
{
    (void)a_cell; (void)a_file_offset; (void)a_size;
    return NULL;
}
const uint8_t *dap_chain_cell_body_view(dap_chain_cell_t *a_cell, size_t a_file_offset, size_t a_size)
{
    (void)a_cell; (void)a_file_offset; (void)a_size;
    return NULL;   // Windows keeps the heap-copy path
}
void dap_chain_cell_read_window_stats(dap_chain_cell_t *a_cell, size_t *a_window_bytes, size_t *a_views)
{
    (void)a_cell;
    if (a_window_bytes) *a_window_bytes = 0;
    if (a_views) *a_views = 0;
}
// Windows has no lazy-read windows to drop, but the call sites are unconditional,
// so the symbol must exist here or the link fails (dap_chain_cell_close/load/
// file_append all reference it regardless of the platform).
void dap_chain_cell_read_windows_drop(dap_chain_cell_t *a_cell)
{
    (void)a_cell;
}
#endif

/* Loader volumes and residency.
 * The mapped loader maps a 256 MB volume per window and never unmaps the older
 * ones (map_range_bounds keeps every base/end pair for the cell's lifetime), so
 * a full scan of a 20 GB cell file leaves ~78 windows mapped. Mapping is cheap;
 * what costs RAM is that every atom of every block was touched during the scan,
 * so all of those pages are resident and nothing ever drops them. Measured on
 * cf-mm-0 with the scan path in use: 152 volumes / 8.68 GB RSS of cell mappings
 * on a 28 GB process - pages the process holds only because the loader once read
 * them, not state anyone still needs.
 *
 * dap_chain_cell_volumes_trim() advises those pages away (MADV_DONTNEED). The
 * mappings are private and read-only over an append-only file, so this drops
 * residency only: the mappings, every pointer into them (ledger tx items and
 * block cache bodies taken during a scan) and the bytes read back afterwards are
 * unchanged - a dropped page simply re-faults from the file. The volume that
 * holds the loader's current position is kept: the loader appends there and the
 * tail of a block being written lives in it. Callers are the whole-chain walks
 * (the wallet bulk pass and other index passes) and the end of a load pass. */
#ifndef DAP_OS_WINDOWS
// Core of the residency sweep. a_keep_ptr: the volume holding this address is
// skipped (a caller walking that range is about to touch it again). a_upto: only
// pages below this absolute file position are advised away (0 = the whole
// mapping); the loader maps a full 256 MB volume even for a shorter file, and a
// page past EOF must never be dropped - touching it afterwards is a SIGBUS.
static void s_cell_volumes_trim_common(dap_chain_cell_t *a_cell, const void *a_keep_ptr, size_t a_upto)
{
    if (!a_cell || !a_cell->map_range_bounds)
        return;
    size_t l_kept = 0, l_dropped = 0, l_bytes = 0;
    // Triples (base, end, file_start): the file position is what the volume's
    // open recorded, never a pointer distance - the mappings live at unrelated
    // addresses, and a_upto is a FILE position (the size the loader ended at).
    for (dap_list_t *l_i = a_cell->map_range_bounds;
            l_i && l_i->next && l_i->next->next; l_i = l_i->next->next->next) {
        char *l_base = (char *)l_i->data;
        char *l_end = (char *)l_i->next->data;
        size_t l_vol_start = (size_t)(uintptr_t)l_i->next->next->data;
        if (!l_base || l_end <= l_base)
            continue;
        // Keep the volume the caller is working in (its pages are about to be
        // used again) and the one holding the loader's append cursor.
        if (l_base == a_cell->map
                || ((const char *)a_keep_ptr >= l_base && (const char *)a_keep_ptr < l_end)) {
            ++l_kept;
            continue;
        }
        size_t l_len = (size_t)(l_end - l_base);
        if (a_upto) {
            // Trim only the part of this volume that lies below the file's end.
            if (l_vol_start >= a_upto)
                continue;   // the whole volume is past the end: never touch its pages
            if (l_vol_start + l_len > a_upto)
                l_len = a_upto - l_vol_start;
        }
        if (l_len && !madvise(l_base, l_len, MADV_DONTNEED)) {
            ++l_dropped;
            l_bytes += l_len;
        }
    }
    debug_if(s_debug_more, L_INFO, "Chain cell \"%s\": dropped residency of %zu loader volume(s) "
             "(%zu MB), kept %zu", a_cell->file_storage_path, l_dropped, l_bytes >> 20, l_kept);
}

void dap_chain_cell_volumes_trim(dap_chain_cell_t *a_cell, const void *a_keep_ptr)
{
    s_cell_volumes_trim_common(a_cell, a_keep_ptr, 0);
}

// Same sweep, bounded by the file's end: used right after a load pass, where the
// mappings may extend past EOF (the loader rounds the volume up to 256 MB).
void dap_chain_cell_volumes_trim_upto(dap_chain_cell_t *a_cell, size_t a_upto)
{
    s_cell_volumes_trim_common(a_cell, NULL, a_upto);
}
#else
void dap_chain_cell_volumes_trim(dap_chain_cell_t *a_cell, const void *a_keep_ptr)
{
    (void)a_cell; (void)a_keep_ptr;
}
void dap_chain_cell_volumes_trim_upto(dap_chain_cell_t *a_cell, size_t a_upto)
{
    (void)a_cell; (void)a_upto;
}
#endif

dap_chain_cell_t * dap_chain_cell_find_by_id(dap_chain_t * a_chain, dap_chain_cell_id_t a_cell_id)
{
    if (!a_chain->cells)
        return NULL;
    dap_chain_cell_t *l_cell = NULL;
    pthread_rwlock_rdlock(&a_chain->cell_rwlock);
    HASH_FIND(hh, a_chain->cells, &a_cell_id, sizeof(dap_chain_cell_id_t), l_cell);
    pthread_rwlock_unlock(&a_chain->cell_rwlock);
    return l_cell;
}

/**
 * @brief 
 * a_cell_id if < 0 then not used
 * @param a_chain dap_chain_t object
 * @param a_cell_id dap_chain_cell_id_t cell (shard) id
 * @return dap_chain_cell_t* 
 */
dap_chain_cell_t * dap_chain_cell_create_fill(dap_chain_t * a_chain, dap_chain_cell_id_t a_cell_id)
{
    dap_chain_cell_t * l_cell = NULL;
    pthread_rwlock_wrlock(&a_chain->cell_rwlock);
    HASH_FIND(hh, a_chain->cells, &a_cell_id, sizeof(dap_chain_cell_id_t), l_cell);
    if (l_cell) {
        pthread_rwlock_unlock(&a_chain->cell_rwlock);
        return l_cell;
    }
    char file_storage_path[MAX_PATH];
    snprintf(file_storage_path, MAX_PATH, "%s/%0"DAP_UINT64_FORMAT_x".dchaincell",
             DAP_CHAIN_PVT(a_chain)->file_storage_dir, a_cell_id.uint64);
    FILE *l_file = NULL;
#define CLEANUP_AND_RET return ({ if (l_file) fclose(l_file); \
    DAP_DELETE(l_cell); \
    pthread_rwlock_unlock(&a_chain->cell_rwlock); \
    NULL; })
    if ( !(l_file = fopen(file_storage_path, "a+b")) ) {
        log_it(L_ERROR, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X" cannot be opened, error %d",
                        file_storage_path, a_cell_id.uint64, errno);
        CLEANUP_AND_RET;
    }
    if ( !(l_cell = DAP_NEW_Z(dap_chain_cell_t)) )
        CLEANUP_AND_RET;
    *l_cell = (dap_chain_cell_t) {
        .id             = a_cell_id,
        .chain          = a_chain,
        .file_storage   = l_file,
        .read_fd        = -1,
        .read_map_mutex = PTHREAD_MUTEX_INITIALIZER,
        .storage_rwlock = PTHREAD_RWLOCK_INITIALIZER
    };
    off_t l_size = !fseeko(l_file, 0, SEEK_END) ? ftello(l_file) : -1;
    if (l_size < 0)
        CLEANUP_AND_RET;
    else if ( (size_t)l_size < sizeof(dap_chain_cell_file_header_t) ) {
        if ( l_size ) {
            log_it(L_INFO, "Possibly corrupt cell storage 0x%016"DAP_UINT64_FORMAT_X" \"%s\", rewriting it",
                            a_cell_id.uint64, file_storage_path);
            l_file = freopen(file_storage_path, "w+b", l_file);
        }
        if ( s_cell_file_write_header(l_cell) < 0 ) {
            log_it(L_ERROR, "Can't init file storage for cell 0x%016"DAP_UINT64_FORMAT_X" \"%s\", errno %d",
                             a_cell_id.uint64, file_storage_path, errno);
            CLEANUP_AND_RET;
        }
        log_it(L_NOTICE, "Initialized file storage for cell 0x%016"DAP_UINT64_FORMAT_X" \"%s\"",
                          a_cell_id.uint64, file_storage_path);
        fflush(l_file);
    }

    if ( a_chain->is_mapped && s_cell_map_new_volume(l_cell, 0, true) ) {
        CLEANUP_AND_RET;
    }
#undef CLEANUP_AND_RET
    memcpy(l_cell->file_storage_path, file_storage_path, sizeof(file_storage_path));
    debug_if (s_debug_more && a_chain->is_mapped, L_DEBUG, "Mapped volume size is %zu", (size_t)(l_cell->map_end - l_cell->map));
    HASH_ADD(hh, a_chain->cells, id, sizeof(dap_chain_cell_id_t), l_cell);
    pthread_rwlock_unlock(&a_chain->cell_rwlock);
    return l_cell;
}

/**
 * @brief
 * close a_cell->file_storage file object
 * @param a_cell dap_chain_cell_t object
 */
void dap_chain_cell_close(dap_chain_cell_t *a_cell)
{
    if(!a_cell)
        return;
    // Lazy-read windows: released only here (or on an in-place rewrite) - body
    // pointers handed out earlier must stay valid for the cell's lifetime.
    dap_chain_cell_read_windows_drop(a_cell);
    if(a_cell->file_storage) {
        fclose(a_cell->file_storage);
        a_cell->file_storage = NULL;
    }
    if (a_cell->chain->is_mapped) {
        dap_list_t *l_iter = a_cell->map_range_bounds;
#ifdef DAP_OS_WINDOWS
        l_iter = l_iter->next;
        for (; l_iter; l_iter = l_iter->next) {
            if (l_iter->next) {
                debug_if(s_debug_more, L_DEBUG, "Unmap volume %p (%zu bytes)", l_iter->data, (size_t)(l_iter->next->data - l_iter->data));
                pfnNtUnmapViewOfSection(GetCurrentProcess(), l_iter->data);
                l_iter = l_iter->next;
            }
        }
        NtClose(a_cell->map_range_bounds->data);
#else
        // POSIX list layout: a (base, end, file_start) triple per volume.
        for (; l_iter && l_iter->next && l_iter->next->next; l_iter = l_iter->next->next->next) {
            debug_if(s_debug_more, L_DEBUG, "Unmap volume %p (%zu bytes)", l_iter->data,
                     (size_t)(l_iter->next->data - l_iter->data));
            munmap(l_iter->data, (size_t)(l_iter->next->data - l_iter->data));
        }
#endif
        dap_list_free(a_cell->map_range_bounds);
    }
#ifdef DAP_OS_WINDOWS
    char *l_new = strstr(a_cell->file_storage_path, ".new");
    if (l_new) {
        char *l_orig = dap_strdup(a_cell->file_storage_path);
        *l_new = '\0';
        remove(a_cell->file_storage_path);
        rename(l_orig, a_cell->file_storage_path);
        DAP_DELETE(l_orig);
    }
#endif
}

/**
 * @brief 
 * free chain cell objects
 * @param a_cell dap_chain_cell_t object
 */
void dap_chain_cell_delete(dap_chain_cell_t *a_cell)
{
    if(!a_cell)
        return;
    dap_chain_cell_close(a_cell);
    if (a_cell->chain->cells) {
        dap_chain_cell_t *l_cell = NULL;
        dap_chain_cell_id_t l_cell_id = {
            .uint64 = a_cell->id.uint64
        };
        pthread_rwlock_wrlock(&a_cell->chain->cell_rwlock);
        HASH_FIND(hh, a_cell->chain->cells, &l_cell_id, sizeof(dap_chain_cell_id_t), l_cell);
        if (l_cell)
            HASH_DEL(a_cell->chain->cells, l_cell);
        pthread_rwlock_unlock(&a_cell->chain->cell_rwlock);
    }
    a_cell->chain = NULL;
    a_cell->file_storage_path[0] = '\0';
    pthread_mutex_destroy(&a_cell->read_map_mutex);
    pthread_rwlock_destroy(&a_cell->storage_rwlock);
    DAP_DELETE(a_cell);
}

void dap_chain_cell_delete_all_and_free_file(dap_chain_t *a_chain) {
    if (!a_chain)
        return;
    pthread_rwlock_wrlock(&a_chain->cell_rwlock);
    dap_chain_cell_t *l_cell, *l_tmp;
    HASH_ITER(hh, a_chain->cells, l_cell, l_tmp) {
        char *l_fsp = dap_strdup(l_cell->file_storage_path);
        dap_chain_cell_id_t l_cell_id = l_cell->id;
        dap_chain_cell_close(l_cell);

        dap_chain_cell_t * l_cell_nh = DAP_NEW_Z(dap_chain_cell_t);
        FILE *l_file = fopen(l_fsp, "w+b");
        if ( !l_file ) {
            log_it(L_ERROR, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X" cannot be opened, error %d",
                   l_fsp, l_cell_id.uint64, errno);
        }
        *l_cell_nh = (dap_chain_cell_t) {
                .id             = l_cell_id,
                .chain          = a_chain,
                .file_storage   = l_file,
                .read_fd        = -1,
                .read_map_mutex = PTHREAD_MUTEX_INITIALIZER
        };
        if ( s_cell_file_write_header(l_cell_nh) < 0 ) {
            log_it(L_ERROR, "Can't init file storage for cell 0x%016"DAP_UINT64_FORMAT_X" \"%s\", errno %d",
                   l_cell_id.uint64, l_fsp, errno);
        } else {
            log_it(L_NOTICE, "Reinitialized file storage for cell 0x%016"DAP_UINT64_FORMAT_X" \"%s\"",
                   l_cell_id.uint64, l_fsp);
        }
        dap_chain_cell_close(l_cell_nh);

        DAP_DELETE(l_fsp);
        HASH_DEL(a_chain->cells, l_cell);
        pthread_mutex_destroy(&l_cell_nh->read_map_mutex);
        DAP_DELETE(l_cell_nh);   // was leaked: built only to rewrite the file header
        pthread_rwlock_destroy(&l_cell->storage_rwlock);
        DAP_DELETE(l_cell);
    }
    pthread_rwlock_unlock(&a_chain->cell_rwlock);
}

void dap_chain_cell_delete_all(dap_chain_t *a_chain) {
    if (!a_chain)
        return;
    pthread_rwlock_wrlock(&a_chain->cell_rwlock);
    dap_chain_cell_t *l_cell, *l_tmp;
    HASH_ITER(hh, a_chain->cells, l_cell, l_tmp) {
        dap_chain_cell_close(l_cell);
        HASH_DEL(a_chain->cells, l_cell);
        pthread_mutex_destroy(&l_cell->read_map_mutex);
        pthread_rwlock_destroy(&l_cell->storage_rwlock);
        DAP_DELETE(l_cell);
    }
    pthread_rwlock_unlock(&a_chain->cell_rwlock);
}

/**
 * @brief dap_chain_cell_load
 * load cell file, which is pointed in a_cell_file_path variable, for example "0.dchaincell"
 * @param a_chain dap_chain_t object
 * @param a_cell_file_path contains name of chain, for example "0.dchaincell" 
 * @return
 */
int dap_chain_cell_load(dap_chain_t *a_chain, dap_chain_cell_t *a_cell)
{
    if (!a_cell)
        return -1;
    off_t l_full_size = !fseeko(a_cell->file_storage, 0, SEEK_END) ? ftello(a_cell->file_storage) : -1;
    if (l_full_size < 0)
        return log_it(L_ERROR, "Can't get chain size, error %d: \"%s\"", errno, dap_strerror(errno)), -1;
    if ( l_full_size < (off_t)sizeof(dap_chain_cell_file_header_t) ) {
        log_it(L_ERROR, "Chain cell \"%s\" is corrupt, create new file", a_cell->file_storage_path);
        return -1;
    }
    dap_chain_cell_file_header_t *l_hdr = NULL;
    if (a_chain->is_mapped) {
        l_hdr = (dap_chain_cell_file_header_t*)a_cell->map;
    } else {
        fseeko(a_cell->file_storage, 0, SEEK_SET);
        l_hdr = DAP_NEW(dap_chain_cell_file_header_t);
        if ( fread(l_hdr, 1, sizeof(*l_hdr), a_cell->file_storage) != sizeof(*l_hdr) ) {
            log_it(L_ERROR,"Can't read chain header \"%s\"", a_cell->file_storage_path);
            fclose(a_cell->file_storage);
            DAP_DELETE(l_hdr);
            return -2;
        }
    }
    if (l_hdr->signature != DAP_CHAIN_CELL_FILE_SIGNATURE) {
        log_it(L_ERROR, "Wrong signature in chain \"%s\", possible file corrupt", a_cell->file_storage_path);
        fclose(a_cell->file_storage);
        if (!a_chain->is_mapped) DAP_DELETE(l_hdr);
        return -3;
    }
    if (l_hdr->version < DAP_CHAIN_CELL_FILE_VERSION ){
        log_it(L_ERROR, "Too low chain version, backup files");
        fclose(a_cell->file_storage);
        if (!a_chain->is_mapped) DAP_DELETE(l_hdr);
        return -4;
    }
    off_t l_pos = sizeof(*l_hdr);
    if (a_chain->is_mapped)
        a_cell->map_pos = a_cell->map + l_pos;
    if (l_full_size == l_pos) {
        return fseeko(a_cell->file_storage, l_pos, SEEK_SET);
    }

    // No-scan startup: the consensus layer rebuilds its cache from the persisted
    // state index. It validates the index against the file size and the ledger
    // anchor itself and refuses (<0) when anything disagrees - then the regular
    // cell walk below runs. No cell-body reads happen on the accepted path.
    if (a_chain->callback_restore_index) {
        uint64_t l_resume = 0;
        int64_t l_restored = a_chain->callback_restore_index(a_chain, &l_resume);
        if (l_restored >= 0) {
            log_it(L_NOTICE, "Chain %s: restored %lld atoms from the state index, "
                   "resuming the cell at %" DAP_UINT64_FORMAT_U " (no rescan of covered blocks)",
                   a_chain->name, (long long)l_restored, l_resume);
            l_pos = (off_t)l_resume;
            if (a_chain->is_mapped) {
                if (dap_chain_cell_map_window(a_cell, (size_t)l_resume))
                    l_pos = l_full_size; // nothing more to read; the loop will not run
            } else if (fseeko(a_cell->file_storage, l_pos, SEEK_SET)) {
                l_pos = l_full_size;
            }
            // Fall through: only the blocks above the ledger anchor are read and
            // applied by the normal path below.
        } else {
            log_it(L_WARNING, "Chain %s: state index refused (code %lld), scanning the cell",
                   a_chain->name, (long long)l_restored);
        }
    }

    int l_ret = 0;    
    uint64_t l_el_size = 0, q = 0;
    // Per-load outcome counters: a scan that stops short of the file end is
    // otherwise indistinguishable from one that rejected everything.
    uint64_t l_n_acc = 0, l_n_fork = 0, l_n_rej = 0;
    if (a_chain->is_mapped) {
        dap_hash_fast_t l_atom_hash;
        for ( off_t l_vol_rest = 0; l_pos + sizeof(uint64_t) < (size_t)l_full_size; ++q, l_pos += l_el_size + sizeof(uint64_t) ) {
            l_vol_rest = (off_t)(a_cell->map_end - a_cell->map_pos) - sizeof(uint64_t);
            if ( l_vol_rest <= 0 || (uint64_t)l_vol_rest < *(uint64_t*)a_cell->map_pos )
                if ( s_cell_map_new_volume(a_cell, l_pos, true) ) {
                    log_it(L_ERROR, "CELL LOAD DIAG: map volume switch failed at atom %llu, pos %lld", (unsigned long long)q, (long long)l_pos);
                    l_ret = -2;
                    break;
                }
            l_el_size = *(uint64_t*)a_cell->map_pos;
            if ( !l_el_size || l_el_size > (size_t)(l_full_size - l_pos) ) {
                log_it(L_ERROR, "CELL LOAD DIAG: bad element size %llu at atom %llu, pos %lld of %lld",
                       (unsigned long long)l_el_size, (unsigned long long)q, (long long)l_pos, (long long)l_full_size);
                break;
            }
            if ( q && (q % 50000) == 0 )
                log_it(L_NOTICE, "CELL LOAD DIAG: %llu atoms loaded, pos %lld of %lld", (unsigned long long)q, (long long)l_pos, (long long)l_full_size);
            a_cell->map_pos += sizeof(uint64_t);
            dap_chain_atom_ptr_t l_atom = (dap_chain_atom_ptr_t)(a_cell->map_pos);
            dap_hash_fast(l_atom, l_el_size, &l_atom_hash);
            // Hand the body to the consensus layer: a cache entry it creates for
            // this block stays thin, and the parse it needs for applying datums
            // is served from these bytes instead of faulting them in again.
            s_cell_load_hint_set((uint64_t)l_pos + sizeof(uint64_t), l_atom, l_el_size);
            dap_chain_atom_verify_res_t l_add_res =
                    a_chain->callback_atom_add(a_chain, l_atom, l_el_size, &l_atom_hash, false);
            s_cell_load_hint_clear();
            if (l_add_res == ATOM_ACCEPT)
                ++l_n_acc;
            else if (l_add_res == ATOM_FORK)
                ++l_n_fork;
            else
                ++l_n_rej;
            
            a_cell->map_pos += l_el_size;
            a_chain->load_progress = (int)((float)l_pos/l_full_size * 100 + 0.5);
        }
#ifndef DAP_OS_WINDOWS
        s_cell_reclaim_cur_volume(a_cell);
#endif
    } else { 
        DAP_DELETE(l_hdr);
        size_t l_read = 0;
        while ((l_read = fread(&l_el_size, 1, sizeof(l_el_size), a_cell->file_storage)) && !feof(a_cell->file_storage)) {
            if (l_read != sizeof(l_el_size) || l_el_size == 0) {
                log_it(L_ERROR, "Corrupted element size %" DAP_UINT64_FORMAT_U ", chain %s is damaged", l_el_size, a_cell->file_storage_path);
                l_ret = -4;
                break;
            }
            dap_chain_atom_ptr_t l_element = DAP_NEW_SIZE(dap_chain_atom_ptr_t, l_el_size);
            if (!l_element) {
                log_it(L_CRITICAL, "Memory allocation error");
                l_ret = -5;
                break;
            }
            l_read = fread((void*)l_element, 1, l_el_size, a_cell->file_storage);
            if (l_read != l_el_size) {
                log_it(L_ERROR, "Read only %zu of %" DAP_UINT64_FORMAT_U " bytes, stop cell loading", l_read, l_el_size);
                DAP_DELETE(l_element);
                l_ret = -6;
                break;
            }
            l_pos += sizeof(uint64_t) + l_read;
            a_chain->load_progress = (int)((float)l_pos/l_full_size * 100 + 0.5);
            dap_hash_fast_t l_atom_hash = {};
            dap_hash_fast(l_element, l_el_size, &l_atom_hash);
            // Offset only: this buffer is freed right after the callback, so it
            // must never become a body pointer inside a cache entry.
            s_cell_load_hint_set_offset((uint64_t)(l_pos - l_read));
            dap_chain_atom_verify_res_t l_res = a_chain->callback_atom_add(a_chain, l_element, l_el_size, &l_atom_hash, false);
            s_cell_load_hint_clear();
            if (l_res == ATOM_ACCEPT)
                ++l_n_acc;
            else if (l_res == ATOM_FORK)
                ++l_n_fork;
            else
                ++l_n_rej;
            
            if (l_res != ATOM_ACCEPT && l_res != ATOM_FORK) {
                DAP_DELETE(l_element);
            } else {
                // Non-mapped loader: the block cache takes its OWN copy of the body
                // (dap_chain_block_cache_new with copy_block=true), and the ledger
                // and both notify paths copy anything they keep. The read buffer is
                // therefore dead when the callback returns. It used to be left
                // allocated - one full block buffer leaked per accepted block on a
                // full scan, a second complete copy of the chain in the heap.
                DAP_DELETE(l_element);
            }
            ++q;
        }
    }
    if ( l_pos < l_full_size ) {
        log_it(L_ERROR, "Chain \"%s\" has incomplete tail, truncating %lld bytes",
                        a_cell->file_storage_path, (long long)(l_full_size - l_pos) );
        // Truncation shrinks the file: a lazy-read window may now cover a range
        // that no longer exists, and touching such a page would SIGBUS. Drop the
        // windows before the file shrinks (the block cache is being rebuilt from
        // the truncated tail at this point, so no body pointer outlives them).
        dap_chain_cell_read_windows_drop(a_cell);
#ifdef DAP_OS_WINDOWS
        if (a_cell->chain->is_mapped) {
            LARGE_INTEGER SectionSize = (LARGE_INTEGER) { .QuadPart = l_pos };
            HANDLE hSection = (HANDLE)a_cell->map_range_bounds->data;
            NTSTATUS err = pfnNtExtendSection(hSection, &SectionSize);
            if ( !NT_SUCCESS(err) ) {
                log_it(L_ERROR, "NtExtendSection() failed, status %08X", (unsigned)err);
            }
        } else
#endif
        if (ftruncate(fileno(a_cell->file_storage), l_pos) != 0)
            log_it(L_ERROR, "ftruncate failed for cell %s: %s", a_cell->file_storage_path, dap_strerror(errno));
    }
    fseeko(a_cell->file_storage, l_pos, SEEK_SET);
#ifndef DAP_OS_WINDOWS
    // A scan walked the whole file, so every volume it mapped is resident.
    // Dropping the pages here is what keeps a 20 GB scan from leaving ~9 GB of
    // cell mappings in RSS until the process dies (measured on cf-mm-0: 152
    // volumes / 8.68 GB). This runs AFTER the truncation above on purpose: the
    // loader maps a full 256 MB volume even for a shorter file, so a page of the
    // last volume can lie past EOF - advising it away and then touching it would
    // SIGBUS, while pages below the final file size always re-fault from the file
    // (bodies and datums taken during the scan stay valid; only residency is
    // returned). The bound is the loader's end position, which is exactly the
    // file size after this pass.
    dap_chain_cell_volumes_trim_upto(a_cell, (size_t)l_pos);
#endif
    log_it(L_INFO, "Loaded %" DAP_UINT64_FORMAT_U " atoms in cell %s (accepted %" DAP_UINT64_FORMAT_U
           ", forks %" DAP_UINT64_FORMAT_U ", rejected %" DAP_UINT64_FORMAT_U ")",
           q, a_cell->file_storage_path, l_n_acc, l_n_fork, l_n_rej);
    return l_ret;
}

static int s_cell_file_atom_add(dap_chain_cell_t *a_cell, dap_chain_atom_ptr_t a_atom, uint64_t a_atom_size)
{
    if (!a_atom || !a_atom_size) {
        log_it(L_CRITICAL, "Invalid arguments");
        return -1;
    }
    if (a_cell->chain->is_mapped) {
        off_t l_pos = !fseeko(a_cell->file_storage, 0, SEEK_END) ? ftello(a_cell->file_storage) : -1;
        if (l_pos < 0)
            return log_it(L_ERROR, "Can't get chain size, error %d: \"%s\"", errno, dap_strerror(errno)), -1;
        debug_if (s_debug_more, L_DEBUG, "Before filling volume for atom size %" DAP_UINT64_FORMAT_U ", stream pos of %s is %lld, map pos is %zu, space left in map %zu",
                      a_atom_size, a_cell->file_storage_path, (long long)l_pos, (size_t)(a_cell->map_pos - a_cell->map), (size_t)(a_cell->map_end - a_cell->map_pos));
        if ( a_atom_size + sizeof(uint64_t) > (size_t)(a_cell->map_end - a_cell->map_pos) )
            if ( s_cell_map_new_volume(a_cell, (size_t)l_pos, false) )
                return -2;
    }
    
    debug_if (s_debug_more && a_cell->chain->is_mapped, L_DEBUG, "Before writing an atom of size %" DAP_UINT64_FORMAT_U ", stream pos of %s is %lld and pos is %zu, space left in map %zu", 
                                            a_atom_size, a_cell->file_storage_path, (long long)ftello(a_cell->file_storage),
                                            (size_t)(a_cell->map_pos - a_cell->map), (size_t)(a_cell->map_end - a_cell->map_pos));

    if (fwrite(&a_atom_size, sizeof(a_atom_size), 1, a_cell->file_storage) != 1) {
        log_it (L_ERROR, "Can't write atom data size from cell 0x%016"DAP_UINT64_FORMAT_X" in \"%s\"",
                a_cell->id.uint64,
                a_cell->file_storage_path);
        return -2;
    }
    if (fwrite(a_atom, a_atom_size, 1, a_cell->file_storage) != 1) {
        log_it(L_ERROR, "Can't write atom (%" DAP_UINT64_FORMAT_U " b) to file \"%s\", err %d: \"%s\"",
                        a_atom_size, a_cell->file_storage_path, errno, dap_strerror(errno) );
        return -3;
    }
    debug_if (s_debug_more && a_cell->chain->is_mapped, L_DEBUG, "After writing an atom of size %" DAP_UINT64_FORMAT_U ", stream pos of %s is %lld and map shift is %zu", 
                                            a_atom_size, a_cell->file_storage_path, (long long)ftello(a_cell->file_storage),
                                            (size_t)(a_cell->map_pos - a_cell->map));
#ifdef DAP_OS_DARWIN
    fflush(a_cell->file_storage);
    if (a_cell->chain->is_mapped) {
        if ( MAP_FAILED == (a_cell->map = mmap(a_cell->map, dap_page_roundup(DAP_MAPPED_VOLUME_LIMIT), PROT_READ,
                                            MAP_PRIVATE|MAP_FIXED, fileno(a_cell->file_storage), a_cell->cur_vol_start)) ) {
            log_it(L_ERROR, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X" cannot be remapped, errno %d",
                            a_cell->file_storage_path, a_cell->id.uint64, errno);
            return -1;
        }
    }
#endif
    return 0;
}

/**
 * @brief s_cell_file_append
 * add atoms to selected chain
 * @param a_cell - cell object. Contains file path to cell storage data, for example - "0.dchaincell"
 * a_cell->chain contains 
 *  name - "zerochain"
 *  net_name - "kelvin-testnet"
 *  filepath - "C:\\Users\\Public\\Documents\\cellframe-node\\var\\lib\\network\\kelvin-testnet\\zerochain\\/0.dchaincell"
 * @param a_atom
 * @param a_atom_size
 * @return
 */
ssize_t dap_chain_cell_file_append(dap_chain_cell_t *a_cell, const void *a_atom, size_t a_atom_size)
{
    if(!a_cell)
        return -1;
    if (!a_atom && !a_cell->chain) {
        log_it(L_WARNING,"Chain not found for cell 0x%016"DAP_UINT64_FORMAT_X" ( %s )",
                               a_cell->id.uint64, a_cell->file_storage_path);
        return -1;
    }
    size_t l_total_res = 0, l_count = 0;
    bool l_err = false;
    pthread_rwlock_wrlock(&a_cell->storage_rwlock);
    if (!a_atom || !a_atom_size) {
        // In-place rewrite: everything the lazy-read windows pointed at is gone.
        dap_chain_cell_read_windows_drop(a_cell);
#ifdef DAP_OS_WINDOWS
        strcat(a_cell->file_storage_path, ".new");
#endif
        a_cell->file_storage = freopen(a_cell->file_storage_path, "w+b", a_cell->file_storage);
        debug_if (s_debug_more,L_DEBUG, "Rewinding file %s", a_cell->file_storage_path);
        bool was_mapped = a_cell->chain->is_mapped;
        a_cell->chain->is_mapped = false;
        if ( s_cell_file_write_header(a_cell) < 0 ) {
            log_it(L_ERROR, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X": can't fill header",
                            a_cell->file_storage_path, a_cell->id.uint64);
            a_cell->chain->is_mapped = was_mapped;
            pthread_rwlock_unlock(&a_cell->storage_rwlock);
            return -2;
        }
        l_total_res += sizeof(dap_chain_cell_file_header_t);
        dap_chain_atom_iter_t *l_atom_iter = a_cell->chain->callback_atom_iter_create(a_cell->chain, a_cell->id, NULL);
        dap_chain_atom_ptr_t l_atom;
        size_t l_atom_size = 0;
        for (l_atom = a_cell->chain->callback_atom_iter_get(l_atom_iter, DAP_CHAIN_ITER_OP_FIRST, &l_atom_size);
             l_atom && l_atom_size;
             l_atom = a_cell->chain->callback_atom_iter_get(l_atom_iter, DAP_CHAIN_ITER_OP_NEXT, &l_atom_size))
        {
            if ( s_cell_file_atom_add(a_cell, l_atom, l_atom_size) ) {
                l_err = true;
                break;
            } else {
                l_total_res += sizeof(uint64_t) + l_atom_size;
                ++l_count;
            }
        }
        a_cell->chain->is_mapped = was_mapped;
        a_cell->chain->callback_atom_iter_delete(l_atom_iter);
        debug_if (s_debug_more && a_cell->chain->is_mapped,L_DEBUG, "After rewriting file %s, stream pos is %lld and map pos is %zu",
                      a_cell->file_storage_path, (long long)ftello(a_cell->file_storage),
                      (size_t)(a_cell->map_pos - a_cell->map));
    } else {
        debug_if (s_debug_more && a_cell->chain->is_mapped,L_DEBUG, "Before appending an atom of size %zu, stream pos of %s is %lld, map pos is %zu",
                      a_atom_size, a_cell->file_storage_path, (long long)ftello(a_cell->file_storage),
                      (size_t)(a_cell->map_pos - a_cell->map));
        if ( s_cell_file_atom_add(a_cell, a_atom, a_atom_size) ) {
            log_it(L_ERROR, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X": can't save atom!",
                   a_cell->file_storage_path, a_cell->id.uint64);
            pthread_rwlock_unlock(&a_cell->storage_rwlock);
            return -4;
        }
        debug_if (s_debug_more && a_cell->chain->is_mapped, L_DEBUG,"After appending an atom of size %zu, stream pos of %s is %lld, map pos is %zu",
                                                a_atom_size, a_cell->file_storage_path, (long long)ftello(a_cell->file_storage),
                                                (size_t)(a_cell->map_end - a_cell->map_pos));
        ++l_count;
        l_total_res = a_atom_size + sizeof(uint64_t);
    }
    
    if (l_total_res) {
#ifndef DAP_OS_DARWIN
        fflush(a_cell->file_storage);
#endif
#ifdef DAP_OS_WINDOWS
        if (a_cell->chain->is_mapped) {
            off_t l_off = ftello(a_cell->file_storage);
            if (l_off < 0) {
                log_it(L_ERROR, "Can't get chain size!");
                l_err = true;
            } else {
                LARGE_INTEGER SectionSize = (LARGE_INTEGER) { .QuadPart = l_off };
                HANDLE hSection = (HANDLE)a_cell->map_range_bounds->data;
                NTSTATUS err = pfnNtExtendSection(hSection, &SectionSize);
                if ( !NT_SUCCESS(err) ) {
                    log_it(L_ERROR, "NtExtendSection() failed, status %08X", (unsigned)err);
                    l_err = true;
                }
            }
        }
#endif
        log_it(L_DEBUG, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X": saved %zu atoms (%zu bytes)",
               a_cell->file_storage_path, a_cell->id.uint64, l_count, l_total_res);
        if (l_err) {
            log_it(L_WARNING, "Not all data was saved due to writing error!");
        }
    } else {
        log_it(L_ERROR, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X": nothing saved!",
               a_cell->file_storage_path, a_cell->id.uint64);
    }
    pthread_rwlock_unlock(&a_cell->storage_rwlock);
    return l_total_res;
}

