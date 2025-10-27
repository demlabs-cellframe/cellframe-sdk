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
#include "dap_chain.h"
#include "dap_chain_cell.h"
#include "dap_chain_cache.h"
#include "dap_chain_cache_internal.h"
#include "dap_global_db.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include <stdint.h>
#ifdef DAP_OS_WINDOWS
#include <winternl.h>
#else
#include <sys/mman.h>
#endif
#define LOG_TAG "dap_chain_cell"

#define DAP_CHAIN_CELL_FILE_VERSION 1
#define DAP_CHAIN_CELL_FILE_SIGNATURE 0xfa340bef153eba48
#define DAP_CHAIN_CELL_FILE_TYPE_RAW 0
#define DAP_CHAIN_CELL_FILE_TYPE_COMPRESSED 1
#define DAP_MAPPED_VOLUME_LIMIT ( 1 << 28 ) // 256 MB for now, may be should be configurable?
#define DAP_LOCAL_STAT_GROUP_NAME "local.stat"

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

typedef struct dap_chain_cell_mmap_volume {
#ifdef DAP_OS_DARWIN
    off_t offset;
#endif
    off_t size;
    char *base;
} dap_chain_cell_mmap_volume_t;

typedef struct dap_chain_cell_mmap_data {
#ifdef DAP_OS_WINDOWS
    HANDLE section;
#endif
    dap_chain_cell_mmap_volume_t **volumes;
    uint16_t volumes_current;
    uint16_t volumes_count;
    uint16_t volumes_max;
    char *cursor;
} dap_chain_cell_mmap_data_t;

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
        pfnNtCreateSection      = (pfn_NtCreateSection)     GetProcAddress(ntdll, "NtCreateSection");
        pfnNtMapViewOfSection   = (pfn_NtMapViewOfSection)  GetProcAddress(ntdll, "NtMapViewOfSection");
        pfnNtExtendSection      = (pfn_NtExtendSection)     GetProcAddress(ntdll, "NtExtendSection");
        pfnNtUnmapViewOfSection = (pfn_NtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    }
    
#endif
    return 0;
}

DAP_STATIC_INLINE int s_cell_add_new_volume(dap_chain_cell_t *a_cell,  dap_chain_cell_mmap_volume_t *a_new_vol ) {
    if (a_cell->mapping->volumes_count >= a_cell->mapping->volumes_max) {
        dap_chain_cell_mmap_volume_t **l_new_volumes = DAP_REALLOC(a_cell->mapping->volumes, sizeof(dap_chain_cell_mmap_volume_t*) * (a_cell->mapping->volumes_max + 1));
        if (!l_new_volumes) {
            log_it(L_ERROR, "Memory allocation error");
            return -1;
        }
        a_cell->mapping->volumes = l_new_volumes;
        a_cell->mapping->volumes_max ++;
        log_it(L_DEBUG, "Append new volume, max %d", a_cell->mapping->volumes_max);
    }
    a_cell->mapping->volumes_count++;
    a_cell->mapping->volumes_current = a_cell->mapping->volumes_count - 1;
    a_cell->mapping->volumes[a_cell->mapping->volumes_current] = a_new_vol;
    return 0;
}

#ifndef DAP_OS_WINDOWS
DAP_STATIC_INLINE void s_cell_reclaim_cur_volume(dap_chain_cell_mmap_volume_t *a_vol) {
    if (
#ifdef MADV_PAGEOUT
    //madvise(a_vol->base, a_vol->size, MADV_PAGEOUT) &&
#endif
    madvise(a_vol->base, a_vol->size, MADV_DONTNEED) )
        log_it(L_ERROR, "Unable to reclaim the previous volume, errno %d: \"%s\"", errno, dap_strerror(errno));
}
#endif

DAP_STATIC_INLINE int s_cell_map_new_volume(dap_chain_cell_t *a_cell, off_t a_fpos, bool a_load) {
#ifdef DAP_OS_WINDOWS
    if ( !a_fpos ) {
        LARGE_INTEGER SectionSize = { .QuadPart = !fseeko(a_cell->file_storage, 0, SEEK_END) ? ftello(a_cell->file_storage) : -1 };
        dap_return_val_if_pass_err(SectionSize.QuadPart < 0, -1, "Can't get chain size, error %d: \"%s\"", errno, dap_strerror(errno));
        NTSTATUS err = pfnNtCreateSection( &a_cell->mapping->section, SECTION_MAP_READ | SECTION_EXTEND_SIZE,
                                           NULL, &SectionSize, PAGE_READWRITE, SEC_RESERVE,
                                           (HANDLE)_get_osfhandle(fileno(a_cell->file_storage)) );
        if ( !NT_SUCCESS(err) )
            return log_it(L_ERROR, "NtCreateSection() failed, status %lx: \"%s\"",
                                   err, dap_str_ntstatus(err) ), -1;
    }
#endif
    dap_chain_cell_mmap_volume_t *l_new_vol = DAP_NEW_Z(dap_chain_cell_mmap_volume_t);
    l_new_vol->size = dap_page_roundup(DAP_MAPPED_VOLUME_LIMIT);
    off_t l_volume_offset = a_fpos ?
#ifdef DAP_OS_WINDOWS
            dap_64k_rounddown(a_fpos)
#else               
            dap_page_rounddown(a_fpos)
#endif
            : 0,
        l_offset = a_fpos - l_volume_offset;
#ifdef DAP_OS_WINDOWS
    int err = 0;
    LARGE_INTEGER Offset = { .QuadPart = l_volume_offset };
    err = pfnNtMapViewOfSection(a_cell->mapping->section, GetCurrentProcess(), (HANDLE)&l_new_vol->base, 0, 0, 
                                &Offset, &l_new_vol->size, ViewUnmap, MEM_RESERVE, PAGE_READONLY);
    if ( !NT_SUCCESS(err) ) {
        NtClose(a_cell->mapping->section);
        log_it(L_ERROR, "NtMapViewOfSection() failed, status %lx: \"%s\"", err, dap_str_ntstatus(err) );
        DAP_DELETE(l_new_vol);
        return -1;
    }
#else
    if (a_load)
        s_cell_reclaim_cur_volume(a_cell->mapping->volumes[a_cell->mapping->volumes_current]);
    l_new_vol->base = mmap( NULL, l_new_vol->size, PROT_READ, MAP_PRIVATE,
                            fileno(a_cell->file_storage), l_volume_offset );
    if ( l_new_vol->base == MAP_FAILED ) {
        log_it(L_ERROR, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X" cannot be mapped, errno %d",
                        a_cell->file_storage_path, a_cell->id.uint64, errno);
        DAP_DELETE(l_new_vol);
        return -1;
    }
#ifdef DAP_OS_DARWIN
    l_new_vol->offset = l_volume_offset;
#endif
#endif
    a_cell->mapping->cursor = l_new_vol->base + l_offset;
#ifndef DAP_OS_WINDOWS    
    if (a_load)
        madvise(l_new_vol->base, l_new_vol->size, MADV_SEQUENTIAL);
#endif
    s_cell_add_new_volume(a_cell, l_new_vol);
    return 0;
}

DAP_STATIC_INLINE int s_cell_close(dap_chain_cell_t *a_cell) {
    //pthread_rwlock_wrlock(&a_cell->storage_rwlock);
    if (a_cell->chain->is_mapped) {
        a_cell->mapping->cursor = NULL;
        for (int i = 0; i < a_cell->mapping->volumes_count; i++) {
            dap_chain_cell_mmap_volume_t *l_vol = a_cell->mapping->volumes[i];
            debug_if(s_debug_more, L_DEBUG, "Unmap volume #%d, %lld bytes", i, (long long)l_vol->size);
#ifdef DAP_OS_WINDOWS
            pfnNtUnmapViewOfSection(GetCurrentProcess(), l_vol->base);
#else
            munmap(l_vol->base, l_vol->size);
#endif
            DAP_DELETE(l_vol);
            a_cell->mapping->volumes[i] = NULL;
        }
#ifdef DAP_OS_WINDOWS
        NtClose(a_cell->mapping->section);
#endif
    }
    if(a_cell->file_storage) {
        fclose(a_cell->file_storage);
        a_cell->file_storage = NULL;
    }
    //pthread_rwlock_unlock(&a_cell->storage_rwlock);
    //pthread_rwlock_destroy(&a_cell->storage_rwlock);
    return 0;
}

/**
 * @brief
 * close a_cell->file_storage file object
 * @param a_cell dap_chain_cell_t object
 */
int s_chain_cell_close(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, bool a_remove_file, bool a_make_file_copy)
{
    dap_return_val_if_fail(a_chain, -1);
    dap_chain_cell_t *l_cell = dap_chain_cell_capture_by_id(a_chain, a_cell_id);
    if (!l_cell) {
        dap_chain_cell_remit(a_chain);
        log_it(L_ERROR, "Cell 0x%016"DAP_UINT64_FORMAT_X" not found in chain \"%s : %s\"",
                                            a_cell_id.uint64, a_chain->net_name, a_chain->name);
        return -2;
    }
    s_cell_close(l_cell);
    HASH_DEL(a_chain->cells, l_cell);
    dap_chain_cell_remit(a_chain);
    if (a_make_file_copy) {
        if (!a_remove_file)
            dap_return_val_if_fail_err(l_cell, -3, "Can't arhivate without removing original file");
        char *l_new_name = dap_strdup_printf("%s.gen%hu", l_cell->file_storage_path, a_chain->generation);
        rename(l_cell->file_storage_path, l_new_name);
        log_it(L_NOTICE, "Cell 0x%016" DAP_UINT64_FORMAT_X " in chain \"%s : %s\" is archived with filename %s",
                                            a_cell_id.uint64, a_chain->net_name, a_chain->name, l_new_name);
    } else if (a_remove_file) {
        log_it(L_NOTICE, "Cell 0x%016" DAP_UINT64_FORMAT_X " in chain \"%s : %s\" is dropped",
                                            a_cell_id.uint64, a_chain->net_name, a_chain->name);
        remove(l_cell->file_storage_path);
    }
    DAP_DELETE(l_cell);
    return 0;
}

void dap_chain_cell_close(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id)
{
    s_chain_cell_close(a_chain, a_cell_id, false, false);
}

int dap_chain_cell_remove(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, bool a_archivate)
{
    return s_chain_cell_close(a_chain, a_cell_id, true, a_archivate);
}

int dap_chain_cell_truncate(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, size_t a_delta)
{
    dap_return_val_if_fail(a_chain, -1);
    dap_chain_cell_t *l_cell = dap_chain_cell_capture_by_id(a_chain, a_cell_id);
    if (!l_cell) {
        dap_chain_cell_remit(a_chain);
        log_it(L_ERROR, "Cell 0x%016"DAP_UINT64_FORMAT_X" not found in chain \"%s : %s\"",
                                            a_cell_id.uint64, a_chain->net_name, a_chain->name);
        return -2;
    }
    off_t l_pos = !fseeko(l_cell->file_storage, 0, SEEK_END) ? ftello(l_cell->file_storage) : -1;
    if (l_pos < (off_t)a_delta)
        dap_return_val_if_fail_err(l_cell, -3, "Can't truncate more than file size %" DAP_UINT64_FORMAT_U, l_pos);
    l_pos -= a_delta;
#ifdef DAP_OS_WINDOWS
    if (l_cell->chain->is_mapped) {
        LARGE_INTEGER SectionSize = (LARGE_INTEGER) { .QuadPart = l_pos };
        NTSTATUS err = pfnNtExtendSection(l_cell->mapping->section, &SectionSize);
        if ( !NT_SUCCESS(err) )
            log_it(L_ERROR, "NtExtendSection() failed, status %lx", err);
    } else
#endif
    ftruncate(fileno(l_cell->file_storage), l_pos);
    dap_chain_cell_remit(a_chain);
    return 0;
}

void dap_chain_cell_close_all(dap_chain_t *a_chain) {
    dap_return_if_fail(a_chain);
    pthread_rwlock_wrlock(&a_chain->cell_rwlock);
    dap_chain_cell_t *l_cell, *l_tmp;
    HASH_ITER(hh, a_chain->cells, l_cell, l_tmp) {
        s_cell_close(l_cell);
        HASH_DEL(a_chain->cells, l_cell);
        DAP_DELETE(l_cell);
    }
    pthread_rwlock_unlock(&a_chain->cell_rwlock);
}

static char *s_cell_get_key_count_name(dap_chain_cell_t *a_cell)
{
    return dap_strdup_printf("%s.%s.atom_count", a_cell->chain->net_name, a_cell->chain->name);
}

/**
 * @brief dap_chain_cell_load
 * load cell file, which is pointed in a_cell_file_path variable, for example "0.dchaincell"
 * @param a_chain dap_chain_t object
 * @param a_cell_file_path contains name of chain, for example "0.dchaincell" 
 * @return
 */
DAP_STATIC_INLINE int s_cell_load_from_file(dap_chain_cell_t *a_cell);

// Simple stats for cell loading
typedef struct {
    uint64_t total_blocks;
    uint64_t cache_hits;
    uint64_t cache_misses;
} cell_load_stats_t;

DAP_STATIC_INLINE int s_cell_load_from_file(dap_chain_cell_t *a_cell)
{
    cell_load_stats_t l_stats = {0};
    
    off_t l_pos, l_full_size = !fseeko(a_cell->file_storage, 0, SEEK_END) ? ftello(a_cell->file_storage) : -1;
    dap_return_val_if_fail_err(l_full_size > 0, 1, "Can't get chain size, error %d: \"%s\"", errno, dap_strerror(errno));
    dap_return_val_if_fail_err(l_full_size >= (off_t)sizeof(dap_chain_cell_file_header_t), 2, "Chain cell \"%s\" is corrupt, create new file", a_cell->file_storage_path);

    /* Load header */
    {
        dap_chain_cell_file_header_t *l_hdr = DAP_NEW_STACK(dap_chain_cell_file_header_t);
        if (a_cell->chain->is_mapped) {
            dap_return_val_if_pass_err( s_cell_map_new_volume(a_cell, 0, false), -3, "Error on mapping the first volume" );
            l_hdr = (dap_chain_cell_file_header_t*)a_cell->mapping->volumes[a_cell->mapping->volumes_current]->base;
        } else {
            fseeko(a_cell->file_storage, 0, SEEK_SET);
            dap_return_val_if_fail_err( fread(l_hdr, 1, sizeof(*l_hdr), a_cell->file_storage) == sizeof(*l_hdr), -4,
                                        "Can't read chain header \"%s\"", a_cell->file_storage_path );
        }
        dap_return_val_if_fail_err( l_hdr->cell_id.uint64 == a_cell->id.uint64, 5,
                                    "Wrong cell id, %llu != %llu", (unsigned long long)l_hdr->cell_id.uint64, (unsigned long long)a_cell->id.uint64);
        dap_return_val_if_fail_err( l_hdr->signature == DAP_CHAIN_CELL_FILE_SIGNATURE, 5,
                                    "Wrong signature in chain \"%s\", possible file corrupt", a_cell->file_storage_path );
        dap_return_val_if_fail_err( l_hdr->version >= DAP_CHAIN_CELL_FILE_VERSION, -6,
                                    "Too low chain version %d < %d, create a backup", l_hdr->version, DAP_CHAIN_CELL_FILE_VERSION );
        l_pos = sizeof(*l_hdr);
        if (a_cell->chain->is_mapped)
            a_cell->mapping->cursor = a_cell->mapping->volumes[a_cell->mapping->volumes_current]->base + l_pos;
        if (l_full_size == l_pos)
            return 0;
    }

    char *l_key_name = s_cell_get_key_count_name(a_cell);
    size_t l_value_len = 0;
    uint64_t l_atom_count = 0;
    byte_t *l_atom_count_str = dap_global_db_get_sync(DAP_LOCAL_STAT_GROUP_NAME, l_key_name, &l_value_len, NULL, NULL);
    if (l_atom_count_str) {
        l_atom_count = strtoull((char *)l_atom_count_str, NULL, 10);
        DAP_FREE(l_atom_count_str);
    }
    DAP_DELETE(l_key_name);
    if (!l_atom_count)
        log_it(L_WARNING, "Can't get atom count from global DB, will use file size to calculate progress");
    
    /* Load atoms */
    int l_ret = 0;    
    off_t l_el_size = 0, q = 0;
    dap_chain_atom_ptr_t l_atom;
    dap_hash_fast_t l_atom_hash;
    if (a_cell->chain->is_mapped) {
        for ( off_t l_vol_rest = 0; l_pos + sizeof(uint64_t) < (size_t)l_full_size; ++q, l_pos += sizeof(uint64_t) + l_el_size ) {
            l_vol_rest = (off_t)( a_cell->mapping->volumes[a_cell->mapping->volumes_current]->base + 
                                 a_cell->mapping->volumes[a_cell->mapping->volumes_current]->size - a_cell->mapping->cursor - sizeof(uint64_t) );
            if ( l_vol_rest <= 0 || l_vol_rest < ( l_el_size = *(uint64_t*)a_cell->mapping->cursor ) )
                dap_return_val_if_pass_err( s_cell_map_new_volume(a_cell, l_pos, true), -7, "Error on mapping a new volume" );
            if ( !l_el_size || l_el_size > l_full_size - l_pos )
                break;
            l_atom = (dap_chain_atom_ptr_t)(a_cell->mapping->cursor + sizeof(uint64_t));
            dap_hash_fast(l_atom, l_el_size, &l_atom_hash);
            
            l_stats.total_blocks++;
            
            // Check cache for fast loading (mapped mode)
            bool l_cache_hit = false;
            dap_chain_atom_verify_res_t l_verif = ATOM_REJECT;
            
            if (a_cell->chain->cache && dap_chain_cache_enabled(a_cell->chain->cache)) {
                dap_chain_cache_entry_t l_cache_entry;
                int l_get_result = dap_chain_cache_get_block(a_cell->chain->cache, &l_atom_hash, &l_cache_entry);
                
                // Debug: log first few cache check details
                static uint32_t s_cache_detail_count = 0;
                s_cache_detail_count++;
                if (s_cache_detail_count <= 3) {
                    log_it(L_NOTICE, "Cache detail #%u: get_result=%d, cached_offset=%"PRIu64", file_offset=%"PRIu64", cached_size=%u, file_size=%zu",
                           s_cache_detail_count, l_get_result, 
                           (l_get_result == 0) ? l_cache_entry.file_offset : 0,
                           (uint64_t)l_pos,
                           (l_get_result == 0) ? l_cache_entry.block_size : 0,
                           l_el_size);
                }
                
                if (l_get_result == 0 &&
                    l_cache_entry.file_offset == (uint64_t)l_pos &&
                    l_cache_entry.block_size == (uint32_t)l_el_size) {
                    // CACHE HIT!
                    l_cache_hit = true;
                    l_verif = ATOM_ACCEPT;
                    l_stats.cache_hits++;
                    atomic_fetch_add(&a_cell->chain->cache->cache_hits, 1);
                }
            }
            
            if (!l_cache_hit) {
                // CACHE MISS - full validation
                l_stats.cache_misses++;
                if (a_cell->chain->cache && dap_chain_cache_enabled(a_cell->chain->cache)) {
                    atomic_fetch_add(&a_cell->chain->cache->cache_misses, 1);
                }
                
                l_verif = a_cell->chain->callback_atom_prefetch
                    ? a_cell->chain->callback_atom_prefetch(a_cell->chain, l_atom, l_el_size, &l_atom_hash)
                    : a_cell->chain->callback_atom_add(a_cell->chain, l_atom, l_el_size, &l_atom_hash, false);
                
                // Debug: log why batch_add is not called
                static uint32_t s_batch_check_count = 0;
                s_batch_check_count++;
                if (s_batch_check_count <= 5) {
                    log_it(L_NOTICE, "Cache batch check #%u (chain %s): verif=%d, cache=%p, enabled=%d",
                           s_batch_check_count, a_cell->chain->name, l_verif, 
                           a_cell->chain->cache, 
                           a_cell->chain->cache ? dap_chain_cache_enabled(a_cell->chain->cache) : 0);
                }
                
                // Save to cache using batch buffer (for performance)
                if (l_verif == ATOM_ACCEPT && a_cell->chain->cache && 
                    dap_chain_cache_enabled(a_cell->chain->cache)) {
                    uint32_t l_tx_count = 0;
                    dap_chain_cache_batch_add(a_cell->chain->cache, &l_atom_hash,
                        a_cell->id.uint64, l_pos, l_el_size, l_tx_count);
                }
            }
            
            if ( l_verif == ATOM_CORRUPTED ) {
                log_it(L_ERROR, "Atom #%ld is corrupted, can't proceed with loading chain \"%s : %s\" cell 0x%016"DAP_UINT64_FORMAT_X"",
                                q, a_cell->chain->net_name, a_cell->chain->name, a_cell->id.uint64);
                l_ret = 8;
                break;
            }
            a_cell->mapping->cursor += sizeof(uint64_t) + l_el_size;
            if ( !a_cell->chain->callback_atom_prefetch ) {
                if (l_atom_count) {
                    uint64_t l_cur_count = a_cell->chain->callback_count_atom(a_cell->chain);
                    a_cell->chain->load_progress = (int)((float)l_cur_count/l_atom_count * 100 + 0.5);
                } else
                    a_cell->chain->load_progress = (int)((float)l_pos/l_full_size * 100 + 0.5);
            }
        }
#ifndef DAP_OS_WINDOWS
        /* Reclaim the last volume */
        s_cell_reclaim_cur_volume(a_cell->mapping->volumes[a_cell->mapping->volumes_current]);
#endif
    } else { 
        size_t l_read = 0;
        while (( l_read = fread(&l_el_size, 1, sizeof(l_el_size), a_cell->file_storage) ) && !feof(a_cell->file_storage) ) {
            if ( !l_el_size || l_read != sizeof(l_el_size) ) {
                log_it(L_ERROR, "Corrupted element size %zu, chain %s is damaged", l_el_size, a_cell->file_storage_path);
                l_ret = 8;
                break;
            }
            l_atom = DAP_NEW_SIZE(dap_chain_atom_ptr_t, l_el_size);
            if (!l_atom) {
                log_it(L_CRITICAL, "Memory allocation error");
                l_ret = -9;
                break;
            }
            l_read = fread((void*)l_atom, 1, l_el_size, a_cell->file_storage);
            if (l_read != (size_t)l_el_size) {
                log_it(L_ERROR, "Read only %lu of %zu bytes, stop cell loading", l_read, l_el_size);
                DAP_DELETE(l_atom);
                l_ret = 10;
                break;
            }
            dap_hash_fast(l_atom, l_el_size, &l_atom_hash);
            
            l_stats.total_blocks++;
            
            // Check cache for fast loading
            bool l_cache_hit = false;
            dap_chain_atom_verify_res_t l_verif = ATOM_REJECT; // Default if no callbacks
            
            if (a_cell->chain->cache && dap_chain_cache_enabled(a_cell->chain->cache)) {
                dap_chain_cache_entry_t l_cache_entry;
                // Check if block is in cache and offset matches
                if (dap_chain_cache_get_block(a_cell->chain->cache, &l_atom_hash, &l_cache_entry) == 0 &&
                    l_cache_entry.file_offset == (uint64_t)l_pos &&
                    l_cache_entry.block_size == (uint32_t)l_el_size) {
                    // CACHE HIT! Skip validation, block already verified
                    l_cache_hit = true;
                    l_verif = ATOM_ACCEPT; // Assume accepted (was validated before)
                    l_stats.cache_hits++;
                    atomic_fetch_add(&a_cell->chain->cache->cache_hits, 1);
                    if (a_cell->chain->cache->debug) {
                        char l_hash_str[DAP_HASH_FAST_STR_SIZE];
                        dap_hash_fast_to_str(&l_atom_hash, l_hash_str, sizeof(l_hash_str));
                        log_it(L_DEBUG, "Cache hit for block %s at offset %"DAP_UINT64_FORMAT_U, 
                            l_hash_str, (uint64_t)l_pos);
                    }
                }
            }
            
            if (!l_cache_hit) {
                // CACHE MISS or cache disabled - full validation
                l_stats.cache_misses++;
                if (a_cell->chain->cache && dap_chain_cache_enabled(a_cell->chain->cache)) {
                    atomic_fetch_add(&a_cell->chain->cache->cache_misses, 1);
                }
                
                if (a_cell->chain->callback_atom_prefetch) {
                    l_verif = a_cell->chain->callback_atom_prefetch(a_cell->chain, l_atom, l_el_size, &l_atom_hash);
                } else if (a_cell->chain->callback_atom_add) {
                    l_verif = a_cell->chain->callback_atom_add(a_cell->chain, l_atom, l_el_size, &l_atom_hash, false);
                } else {
                    // No callbacks available - can't process atoms
                    log_it(L_WARNING, "No atom processing callbacks available for chain \"%s : %s\", cell loading incomplete",
                           a_cell->chain->net_name, a_cell->chain->name);
                    DAP_DELETE(l_atom);
                    break; // Stop loading, but not an error
                }
                
                // Save to cache using batch buffer (for performance)
                if (l_verif == ATOM_ACCEPT && a_cell->chain->cache && 
                    dap_chain_cache_enabled(a_cell->chain->cache)) {
                    // TODO: Get actual tx_count from block
                    uint32_t l_tx_count = 0;
                    dap_chain_cache_batch_add(a_cell->chain->cache, &l_atom_hash,
                        a_cell->id.uint64, l_pos, l_el_size, l_tx_count);
                }
            }
            
            DAP_DELETE(l_atom);
            if ( l_verif == ATOM_CORRUPTED ) {
                log_it(L_ERROR, "Atom #%ld is corrupted, can't proceed with loading chain \"%s : %s\" cell 0x%016"DAP_UINT64_FORMAT_X"",
                                q, a_cell->chain->net_name, a_cell->chain->name, a_cell->id.uint64);
                l_ret = 11;
                break;
            }
            ++q;
            l_pos += sizeof(uint64_t) + l_read;
            if ( !a_cell->chain->callback_atom_prefetch ) {
                if (l_atom_count && a_cell->chain->callback_count_atom) {
                    uint64_t l_cur_count = a_cell->chain->callback_count_atom(a_cell->chain);
                    a_cell->chain->load_progress = (int)((float)l_cur_count/l_atom_count * 100 + 0.5);
                } else
                    a_cell->chain->load_progress = (int)((float)l_pos/l_full_size * 100 + 0.5);
            }
        }
    }
    if ( l_pos < l_full_size && l_ret > 0 ) {
        log_it(L_ERROR, "Chain \"%s\" has incomplete tail, truncating %zu bytes",
                        a_cell->file_storage_path, l_full_size - l_pos );
#ifdef DAP_OS_WINDOWS
        if (a_cell->chain->is_mapped) {
            LARGE_INTEGER SectionSize = (LARGE_INTEGER) { .QuadPart = l_pos };
            NTSTATUS err = pfnNtExtendSection(a_cell->mapping->section, &SectionSize);
            if ( !NT_SUCCESS(err) )
                log_it(L_ERROR, "NtExtendSection() failed, status %lx", err);
        } else
#endif
            ftruncate(fileno(a_cell->file_storage), l_pos);
    }
    fseeko(a_cell->file_storage, l_pos, SEEK_SET);
    if ( a_cell->chain->callback_atoms_prefetched_add )
        a_cell->chain->callback_atoms_prefetched_add(a_cell->chain);
    
    // Flush batch buffer after cell loading completes
    if (a_cell->chain->cache && dap_chain_cache_enabled(a_cell->chain->cache)) {
        dap_chain_cache_batch_flush(a_cell->chain->cache);
    }
    
    // Log simple statistics
    if (l_stats.total_blocks > 0) {
        double l_cache_hit_rate = (100.0 * l_stats.cache_hits / l_stats.total_blocks);
        log_it(L_NOTICE, "Cell loaded: chain \"%s : %s\" cell 0x%016"DAP_UINT64_FORMAT_X" - "
               "%"PRIu64" blocks, cache: %"PRIu64" hits (%.1f%%), %"PRIu64" misses",
               a_cell->chain->net_name, a_cell->chain->name, a_cell->id.uint64,
               l_stats.total_blocks, l_stats.cache_hits, l_cache_hit_rate, l_stats.cache_misses);
        
        if (l_stats.cache_misses > 0) {
            log_it(L_INFO, "  -> %"PRIu64" blocks required full validation (cache misses)", 
                   l_stats.cache_misses);
        }
    } else {
        log_it(L_INFO, "Loaded cell \"%s : %s\" cell 0x%016"DAP_UINT64_FORMAT_X" - empty",
               a_cell->chain->net_name, a_cell->chain->name, a_cell->id.uint64);
    }
    return l_ret;
}

DAP_STATIC_INLINE int s_cell_open(dap_chain_t *a_chain, const char *a_filepath, dap_chain_cell_id_t a_cell_id, const char a_mode) {
    char mode[] = { a_mode, '+', 'b', '\0' }, *const a_filename = strrchr(a_filepath, '/') + 1;
    dap_chain_cell_t *l_cell = NULL;

#define m_ret_err(err, ...) return ({ if (l_cell->file_storage) fclose(l_cell->file_storage); \
                                      DAP_DELETE(l_cell); log_it(L_ERROR, ##__VA_ARGS__), err; })

    HASH_FIND(hh, a_chain->cells, &a_cell_id, sizeof(dap_chain_cell_id_t), l_cell);
    if (l_cell) {
        if (a_mode == 'w') {
            /* Attention! File rewriting requires that ledger was already purged */
            s_cell_close(l_cell);
            HASH_DEL(a_chain->cells, l_cell);
            DAP_DELETE(l_cell);
        } else
            m_ret_err(EEXIST, "Cell \"%s\" is already loaded in chain \"%s : %s\"",
                              a_filename, a_chain->net_name, a_chain->name);
    }

    FILE *l_file = fopen(a_filepath, mode);
    if ( !l_file )
        m_ret_err(errno, "Cell \"%s : %s / \"%s\" cannot be opened, error %d",
                         a_chain->net_name, a_chain->name, a_filename, errno);
    if (fseeko(l_file, 0, SEEK_END) != 0)
        m_ret_err(errno, "Cell \"%s : %s / \"%s\" cannot be find end of file, error %d",
                        a_chain->net_name, a_chain->name, a_filename, errno);
                                          
    off_t l_file_size = ftello(l_file);
    // For write mode ('w'), file size 0 is normal for new files
    if (l_file_size <= 0 && a_mode != 'w')
        m_ret_err(errno, "Cell \"%s : %s / \"%s\" cannot get file size or file size 0, error %d",
                        a_chain->net_name, a_chain->name, a_filename, errno);
                        
    fseeko(l_file, 0L, SEEK_SET);
    uint16_t l_mapping_count = l_file_size > 0 ? l_file_size/DAP_MAPPED_VOLUME_LIMIT + 1 : 1;

    l_cell = DAP_NEW_Z(dap_chain_cell_t);
    *l_cell = (dap_chain_cell_t) {
        .id             = a_cell_id,
        .chain          = a_chain,
        .mapping        = a_chain->is_mapped ? DAP_NEW_Z(dap_chain_cell_mmap_data_t) : NULL,
        .file_storage   = l_file,
        //.storage_rwlock = PTHREAD_RWLOCK_INITIALIZER
    };
    if (a_chain->is_mapped) {
        l_cell->mapping->volumes = DAP_NEW_Z_COUNT(dap_chain_cell_mmap_volume_t*, l_mapping_count);
        l_cell->mapping->volumes_count = 0;
        l_cell->mapping->volumes_max = l_mapping_count;
    }

    dap_strncpy(l_cell->file_storage_path, a_filepath, MAX_PATH);

    switch (*mode) {
    case 'a': {
        int l_load_res = s_cell_load_from_file(l_cell);
        if ( !l_load_res )
            break;
        else if (l_load_res < 0)
            m_ret_err(errno, "Cell \"%s : %s / \"%s\" cannot be loaded, code %d",
                             a_chain->net_name, a_chain->name, a_filename, l_load_res);
        // Otherwise, rewrite the file from scratch
        ftruncate(fileno(l_cell->file_storage), 0);
        *mode = 'w';
    }
    case 'w': {
        dap_chain_cell_file_header_t l_hdr = {
            .signature      = DAP_CHAIN_CELL_FILE_SIGNATURE,
            .version        = DAP_CHAIN_CELL_FILE_VERSION,
            .type           = DAP_CHAIN_CELL_FILE_TYPE_RAW,
            .chain_id       = a_chain->id,
            .chain_net_id   = a_chain->net_id,
            .cell_id        = a_cell_id
        };
        if ( !fwrite(&l_hdr, sizeof(l_hdr), 1, l_cell->file_storage) )
            m_ret_err(errno, "fwrite() error %d", errno);
        fflush(l_cell->file_storage);
        l_cell->file_storage = freopen(a_filepath, "a+b", l_cell->file_storage);
        if (a_chain->is_mapped) {
            if (s_cell_map_new_volume(l_cell, 0, false))
                m_ret_err(EINVAL, "Error on mapping the first volume");
            l_cell->mapping->cursor += sizeof(l_hdr);
        }
    }
    default:
        break;
    }
    HASH_ADD(hh, a_chain->cells, id, sizeof(dap_chain_cell_id_t), l_cell);
    log_it(L_INFO, "Cell storage \"%s\" is %s for chain \"%s : %s\"",
                    a_filename, *mode == 'w' ? "created" : "opened", a_chain->net_name, a_chain->name);
    return 0;
#undef m_ret_err
}

int dap_chain_cell_open(dap_chain_t *a_chain, const dap_chain_cell_id_t a_cell_id, const char a_mode) {
    char l_full_path[MAX_PATH];
    snprintf(l_full_path, MAX_PATH, "%s/%"DAP_UINT64_FORMAT_x"."DAP_CHAIN_CELL_FILE_EXT, DAP_CHAIN_PVT(a_chain)->file_storage_dir, a_cell_id.uint64);
    pthread_rwlock_wrlock(&a_chain->cell_rwlock);
    int l_ret = s_cell_open(a_chain, l_full_path, a_cell_id, a_mode);
    pthread_rwlock_unlock(&a_chain->cell_rwlock);
    return l_ret;
}

static int s_cell_file_atom_add(dap_chain_cell_t *a_cell, dap_chain_atom_ptr_t a_atom, uint64_t a_atom_size, char **a_atom_map)
{
    if (a_cell->chain->is_mapped) {
        off_t l_pos = !fseeko(a_cell->file_storage, 0, SEEK_END) ? ftello(a_cell->file_storage) : -1;
        dap_return_val_if_pass_err(l_pos < 0, -1, "Can't get \"%s : %s\" cell 0x%016"DAP_UINT64_FORMAT_X" size, error %d",
                                                     a_cell->chain->net_name, a_cell->chain->name, a_cell->id.uint64, errno);
        if ( a_atom_size + sizeof(uint64_t) > (size_t)(a_cell->mapping->volumes[a_cell->mapping->volumes_current]->base + 
                                                       a_cell->mapping->volumes[a_cell->mapping->volumes_current]->size - a_cell->mapping->cursor) )
            dap_return_val_if_pass_err(
                s_cell_map_new_volume(a_cell, l_pos, false), 
                -2, "Failed to create new map volume for \"%s : %s\" cell 0x%016"DAP_UINT64_FORMAT_X"",
                a_cell->chain->net_name, a_cell->chain->name, a_cell->id.uint64
            );
    }
    dap_return_val_if_fail_err(
        fwrite(&a_atom_size, sizeof(a_atom_size), 1, a_cell->file_storage) == 1 &&
        fwrite(a_atom,       a_atom_size,         1, a_cell->file_storage) == 1,
        -3, "Can't write atom [%zu b] to \"%s : %s\" cell 0x%016"DAP_UINT64_FORMAT_X", error %d: \"%s\"",
            a_atom_size, a_cell->chain->net_name, a_cell->chain->name, a_cell->id.uint64, errno, dap_strerror(errno)
    );
    fflush(a_cell->file_storage);

    if (a_cell->chain->is_mapped) {
#ifdef DAP_OS_DARWIN
        a_cell->mapping->volumes[a_cell->mapping->volumes_current]->base = mmap( a_cell->mapping->volumes[a_cell->mapping->volumes_current]->base, 
                                            a_cell->mapping->volumes[a_cell->mapping->volumes_current]->size,
                                            PROT_READ, MAP_PRIVATE | MAP_FIXED, fileno(a_cell->file_storage),
                                            a_cell->mapping->volumes[a_cell->mapping->volumes_current]->offset );
        dap_return_val_if_pass_err( a_cell->mapping->volumes[a_cell->mapping->volumes_current]->base == MAP_FAILED, -2,
            "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X" cannot be remapped, errno %d",
            a_cell->file_storage_path, a_cell->id.uint64, errno );
#elif defined DAP_OS_WINDOWS
        LARGE_INTEGER SectionSize = (LARGE_INTEGER) { .QuadPart = ftello(a_cell->file_storage) };
        NTSTATUS err = pfnNtExtendSection(a_cell->mapping->section, &SectionSize);
        dap_return_val_if_fail_err( NT_SUCCESS(err), -2, "NtExtendSection() failed, status %lx: \"%s\"", err, dap_str_ntstatus(err) );
#endif
        /* Pass ptr to mapped area */
        if (a_atom_map)
            *a_atom_map = a_cell->mapping->cursor + sizeof(uint64_t);
        a_cell->mapping->cursor += sizeof(uint64_t) + a_atom_size;
    }
    /* Update local stat */
    if (a_cell->chain->callback_count_atom) {
        char *l_key_name = s_cell_get_key_count_name(a_cell);
        char l_value[64];
        snprintf(l_value, sizeof(l_value), "%"DAP_UINT64_FORMAT_U, a_cell->chain->callback_count_atom(a_cell->chain));
        dap_global_db_set(DAP_LOCAL_STAT_GROUP_NAME, l_key_name, l_value, strlen(l_value), false, NULL, NULL);
        DAP_DELETE(l_key_name);
    }
    return 0;
}

/**
 * @brief dap_chain_cell_read_atom_by_offset
 * Read atom from cell file by offset
 * @param a_chain Chain object
 * @param a_cell_id Cell ID where atom is stored
 * @param a_offset File offset where atom is located (points to size field before atom data)
 * @param a_atom_size Pointer to store atom size (output parameter)
 * @return Pointer to atom data (must be freed by caller) or NULL on error
 * @note The offset should point to the uint64_t size field, not the atom data itself
 * @note For mapped chains, data is read from memory-mapped region
 * @note For non-mapped chains, data is read from file using fseeko/fread
 * @author Olzhas Zharasbaev
 */
void *dap_chain_cell_read_atom_by_offset(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, 
                                          off_t a_offset, size_t *a_atom_size)
{
    dap_return_val_if_fail(a_chain && a_atom_size, NULL);
    dap_return_val_if_fail_err(a_offset >= (off_t)sizeof(dap_chain_cell_file_header_t), NULL,
                               "Invalid offset %ld, must be >= header size", (long)a_offset);
    
    dap_chain_cell_t *l_cell = dap_chain_cell_capture_by_id(a_chain, a_cell_id);
    dap_return_val_if_fail_err(l_cell, NULL, "Cell #%"DAP_UINT64_FORMAT_x" not found in chain \"%s : %s\"",
                               a_cell_id.uint64, a_chain->net_name, a_chain->name);
    
    uint64_t l_atom_size = 0;
    void *l_atom_data = NULL;
    
    if (a_chain->is_mapped && l_cell->mapping) {
        // Memory-mapped mode: find the volume containing this offset
        off_t l_volume_offset = 0;
        dap_chain_cell_mmap_volume_t *l_target_volume = NULL;
        
        // Find which volume contains our offset
        for (uint16_t i = 0; i < l_cell->mapping->volumes_count; i++) {
            off_t l_next_volume_offset = l_volume_offset + l_cell->mapping->volumes[i]->size;
            if (a_offset >= l_volume_offset && a_offset < l_next_volume_offset) {
                l_target_volume = l_cell->mapping->volumes[i];
                break;
            }
            l_volume_offset = l_next_volume_offset;
        }
        
        if (!l_target_volume) {
            log_it(L_ERROR, "Offset %ld not found in any mapped volume for cell 0x%016"DAP_UINT64_FORMAT_X,
                   (long)a_offset, a_cell_id.uint64);
            dap_chain_cell_remit(a_chain);
            return NULL;
        }
        
        // Calculate position within the volume
        off_t l_offset_in_volume = a_offset - l_volume_offset;
        char *l_data_ptr = l_target_volume->base + l_offset_in_volume;
        
        // Check if size field fits in current volume
        if (l_offset_in_volume + (off_t)sizeof(uint64_t) > l_target_volume->size) {
            log_it(L_ERROR, "Size field at offset %ld crosses volume boundary in cell 0x%016"DAP_UINT64_FORMAT_X,
                   (long)a_offset, a_cell_id.uint64);
            dap_chain_cell_remit(a_chain);
            return NULL;
        }
        
        // Read atom size
        memcpy(&l_atom_size, l_data_ptr, sizeof(uint64_t));
        l_data_ptr += sizeof(uint64_t);
        
        // Check if atom data fits in current volume
        if (l_offset_in_volume + (off_t)sizeof(uint64_t) + (off_t)l_atom_size > l_target_volume->size) {
            log_it(L_ERROR, "Atom data at offset %ld (size %"DAP_UINT64_FORMAT_U") crosses volume boundary in cell 0x%016"DAP_UINT64_FORMAT_X,
                   (long)a_offset, l_atom_size, a_cell_id.uint64);
            dap_chain_cell_remit(a_chain);
            return NULL;
        }
        
        // Allocate and copy atom data
        l_atom_data = DAP_NEW_SIZE(byte_t, l_atom_size);
        if (!l_atom_data) {
            log_it(L_CRITICAL, "Memory allocation error for atom size %"DAP_UINT64_FORMAT_U, l_atom_size);
            dap_chain_cell_remit(a_chain);
            return NULL;
        }
        memcpy(l_atom_data, l_data_ptr, l_atom_size);
        
    } else {
        // File-based mode: use fseeko/fread
        if (!l_cell->file_storage) {
            log_it(L_ERROR, "file_storage is NULL for cell 0x%016"DAP_UINT64_FORMAT_X, a_cell_id.uint64);
            dap_chain_cell_remit(a_chain);
            return NULL;
        }
        if (fseeko(l_cell->file_storage, a_offset, SEEK_SET) != 0) {
            log_it(L_ERROR, "Cannot seek to offset %ld in cell 0x%016"DAP_UINT64_FORMAT_X", error %d: \"%s\"",
                   (long)a_offset, a_cell_id.uint64, errno, dap_strerror(errno));
            dap_chain_cell_remit(a_chain);
            return NULL;
        }
        
        // Read atom size
        if (fread(&l_atom_size, sizeof(uint64_t), 1, l_cell->file_storage) != 1) {
            log_it(L_ERROR, "Cannot read atom size at offset %ld in cell 0x%016"DAP_UINT64_FORMAT_X", error %d: \"%s\"",
                   (long)a_offset, a_cell_id.uint64, errno, dap_strerror(errno));
            dap_chain_cell_remit(a_chain);
            return NULL;
        }
        
        // Validate atom size
        if (l_atom_size == 0 || l_atom_size > (1ULL << 30)) { // Max 1GB sanity check
            log_it(L_ERROR, "Invalid atom size %"DAP_UINT64_FORMAT_U" at offset %ld in cell 0x%016"DAP_UINT64_FORMAT_X,
                   l_atom_size, (long)a_offset, a_cell_id.uint64);
            dap_chain_cell_remit(a_chain);
            return NULL;
        }
        
        // Allocate memory for atom data
        l_atom_data = DAP_NEW_SIZE(byte_t, l_atom_size);
        if (!l_atom_data) {
            log_it(L_CRITICAL, "Memory allocation error for atom size %"DAP_UINT64_FORMAT_U, l_atom_size);
            dap_chain_cell_remit(a_chain);
            return NULL;
        }
        
        // Read atom data
        if (fread(l_atom_data, l_atom_size, 1, l_cell->file_storage) != 1) {
            log_it(L_ERROR, "Cannot read atom data (%"DAP_UINT64_FORMAT_U" bytes) at offset %ld in cell 0x%016"DAP_UINT64_FORMAT_X", error %d: \"%s\"",
                   l_atom_size, (long)a_offset + (long)sizeof(uint64_t), a_cell_id.uint64, errno, dap_strerror(errno));
            DAP_DELETE(l_atom_data);
            dap_chain_cell_remit(a_chain);
            return NULL;
        }
    }
    
    dap_chain_cell_remit(a_chain);
    
    *a_atom_size = (size_t)l_atom_size;
    log_it(L_DEBUG, "Read atom of size %zu bytes from chain \"%s : %s\", cell 0x%016"DAP_UINT64_FORMAT_X", offset %ld",
           *a_atom_size, a_chain->net_name, a_chain->name, a_cell_id.uint64, (long)a_offset);
    
    return l_atom_data;
}

/**
 * @brief s_cell_file_append
 * add atoms to selected chain
 * @param a_cell - cell object. Contains file path to cell storage data, for example - "0.dchaincell"
 * a_cell->chain contains 
 *  name
 *  net_name
 *  filepath
 * @param a_atom
 * @param a_atom_size
 * @return
 */
int dap_chain_cell_file_append(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, const void *a_atom, size_t a_atom_size, char **a_atom_map)
{
    dap_return_val_if_fail(a_atom && a_atom_size && a_chain, -1);
    dap_chain_cell_t *l_cell = dap_chain_cell_capture_by_id(a_chain, a_cell_id);
    dap_return_val_if_fail_err(l_cell, -2, "Cell #%"DAP_UINT64_FORMAT_x" not found in chain \"%s : %s\"",
                                            a_cell_id.uint64, a_chain->net_name, a_chain->name);
    //pthread_rwlock_wrlock(&l_cell->storage_rwlock);
    int l_err = s_cell_file_atom_add(l_cell, a_atom, a_atom_size, a_atom_map);
    if (!l_err)
        log_it(L_DEBUG, "Saved atom of size %zu bytes to chain \"%s : %s\", cell 0x%016"DAP_UINT64_FORMAT_X"",
                        a_atom_size, a_chain->net_name, a_chain->name, a_cell_id.uint64);
    else
        log_it(L_ERROR, "Noting saved to chain \"%s : %s\", cell 0x%016"DAP_UINT64_FORMAT_X", error %d",
                        a_chain->net_name, a_chain->name, a_cell_id.uint64, l_err);
    //pthread_rwlock_unlock(&l_cell->storage_rwlock);
    dap_chain_cell_remit(a_chain);
    return 0;
}
