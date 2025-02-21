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
#include "dap_chain_cs.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
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

#define CELL_FILE_EXT "dchaincell"

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
    struct dap_chain_cell_mmap_volume *prev, *next;
} dap_chain_cell_mmap_volume_t;

typedef struct dap_chain_cell_mmap_data {
#ifdef DAP_OS_WINDOWS
    HANDLE section;
#endif
    dap_chain_cell_mmap_volume_t *volume;
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
        s_cell_reclaim_cur_volume(a_cell->mapping->volume);
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
    DL_PREPEND(a_cell->mapping->volume, l_new_vol);
    return 0;
}

DAP_STATIC_INLINE int s_cell_close(dap_chain_cell_t *a_cell) {
    //pthread_rwlock_wrlock(&a_cell->storage_rwlock);
    if(a_cell->file_storage) {
        fclose(a_cell->file_storage);
        a_cell->file_storage = NULL;
    }
    if (a_cell->chain->is_mapped) {
        a_cell->mapping->cursor = NULL;
        int i = 0;
        dap_chain_cell_mmap_volume_t *l_vol, *l_tmp;
        DL_FOREACH_SAFE(a_cell->mapping->volume, l_vol, l_tmp) {
            debug_if(s_debug_more, L_DEBUG, "Unmap volume #%d, %lu bytes", i++, l_vol->size);
#ifdef DAP_OS_WINDOWS
            pfnNtUnmapViewOfSection(GetCurrentProcess(), l_vol->base);
#else
            munmap(l_vol->base, l_vol->size);
#endif
            DL_DELETE(a_cell->mapping->volume, l_vol);
            DAP_DELETE(l_vol);
        }
#ifdef DAP_OS_WINDOWS
        NtClose(a_cell->mapping->section);
#endif
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
void dap_chain_cell_close(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id)
{
    dap_return_if_fail(a_chain);
    dap_chain_cell_t *l_cell = dap_chain_cell_capture_by_id(a_chain, a_cell_id);
    dap_return_if_fail_err(l_cell, "Cell 0x%016"DAP_UINT64_FORMAT_X" not found in chain \"%s : %s\"",
                                    a_cell_id.uint64, a_chain->net_name, a_chain->name);
    s_cell_close(l_cell);
    HASH_DEL(a_chain->cells, l_cell);
    dap_chain_cell_remit(l_cell);
    DAP_DELETE(l_cell);
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

/**
 * @brief dap_chain_cell_load
 * load cell file, which is pointed in a_cell_file_path variable, for example "0.dchaincell"
 * @param a_chain dap_chain_t object
 * @param a_cell_file_path contains name of chain, for example "0.dchaincell" 
 * @return
 */
DAP_STATIC_INLINE int s_cell_load_from_file(dap_chain_cell_t *a_cell)
{
    off_t l_pos, l_full_size = !fseeko(a_cell->file_storage, 0, SEEK_END) ? ftello(a_cell->file_storage) : -1;
    dap_return_val_if_fail_err(l_full_size > 0, 1, "Can't get chain size, error %d: \"%s\"", errno, dap_strerror(errno));
    dap_return_val_if_fail_err(l_full_size >= (off_t)sizeof(dap_chain_cell_file_header_t), 2, "Chain cell \"%s\" is corrupt, create new file", a_cell->file_storage_path);

    /* Load header */
    {
        dap_chain_cell_file_header_t *l_hdr = DAP_NEW_STACK(dap_chain_cell_file_header_t);
        if (a_cell->chain->is_mapped) {
            dap_return_val_if_pass_err( s_cell_map_new_volume(a_cell, 0, false), -3, "Error on mapping the first volume" );
            l_hdr = (dap_chain_cell_file_header_t*)a_cell->mapping->volume->base;
        } else {
            fseeko(a_cell->file_storage, 0, SEEK_SET);
            dap_return_val_if_fail_err( fread(l_hdr, 1, sizeof(*l_hdr), a_cell->file_storage) == sizeof(*l_hdr), -4,
                                        "Can't read chain header \"%s\"", a_cell->file_storage_path );
        }
        dap_return_val_if_fail_err( l_hdr->cell_id.uint64 == a_cell->id.uint64, 5,
                                    "Wrong cell id, %lu != %lu", l_hdr->cell_id.uint64, a_cell->id.uint64);
        dap_return_val_if_fail_err( l_hdr->signature == DAP_CHAIN_CELL_FILE_SIGNATURE, 5,
                                    "Wrong signature in chain \"%s\", possible file corrupt", a_cell->file_storage_path );
        dap_return_val_if_fail_err( l_hdr->version >= DAP_CHAIN_CELL_FILE_VERSION, -6,
                                    "Too low chain version %d < %d, create a backup", l_hdr->version, DAP_CHAIN_CELL_FILE_VERSION );
        l_pos = sizeof(*l_hdr);
        if (a_cell->chain->is_mapped)
            a_cell->mapping->cursor = a_cell->mapping->volume->base + l_pos;
        if (l_full_size == l_pos)
            return 0;
    }

    /* Load atoms */
    int l_ret = 0;    
    off_t l_el_size = 0, q = 0;
    dap_chain_atom_ptr_t l_atom;
    dap_hash_fast_t l_atom_hash;
    if (a_cell->chain->is_mapped) {
        for ( off_t l_vol_rest = 0; l_pos + sizeof(uint64_t) < (size_t)l_full_size; ++q, l_pos += sizeof(uint64_t) + l_el_size ) {
            l_vol_rest = (off_t)( a_cell->mapping->volume->base + a_cell->mapping->volume->size - a_cell->mapping->cursor - sizeof(uint64_t) );
            if ( l_vol_rest <= 0 || l_vol_rest < ( l_el_size = *(uint64_t*)a_cell->mapping->cursor ) )
                dap_return_val_if_pass_err( s_cell_map_new_volume(a_cell, l_pos, true), -7, "Error on mapping a new volume" );
            if ( !l_el_size || l_el_size > l_full_size - l_pos )
                break;
            l_atom = (dap_chain_atom_ptr_t)(a_cell->mapping->cursor + sizeof(uint64_t));
            dap_hash_fast(l_atom, l_el_size, &l_atom_hash);
            dap_chain_atom_verify_res_t l_verif = a_cell->chain->callback_atom_prefetch
                ? a_cell->chain->callback_atom_prefetch(a_cell->chain, l_atom, l_el_size, &l_atom_hash)
                : a_cell->chain->callback_atom_add(a_cell->chain, l_atom, l_el_size, &l_atom_hash, false);
            if ( l_verif == ATOM_CORRUPTED ) {
                log_it(L_ERROR, "Atom #%ld is corrupted, can't proceed with loading chain \"%s : %s\" cell 0x%016"DAP_UINT64_FORMAT_X"",
                                q, a_cell->chain->net_name, a_cell->chain->name, a_cell->id.uint64);
                l_ret = 8;
                break;
            }
            a_cell->mapping->cursor += sizeof(uint64_t) + l_el_size;
            if ( !a_cell->chain->callback_atom_prefetch )
                a_cell->chain->load_progress = (int)((float)l_pos/l_full_size * 100 + 0.5);
        }
#ifndef DAP_OS_WINDOWS
        /* Reclaim the last volume */
        s_cell_reclaim_cur_volume(a_cell->mapping->volume);
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
            dap_chain_atom_verify_res_t l_verif = a_cell->chain->callback_atom_prefetch
                ? a_cell->chain->callback_atom_prefetch(a_cell->chain, l_atom, l_el_size, &l_atom_hash)
                : a_cell->chain->callback_atom_add(a_cell->chain, l_atom, l_el_size, &l_atom_hash, false);
            DAP_DELETE(l_atom);
            if ( l_verif == ATOM_CORRUPTED ) {
                log_it(L_ERROR, "Atom #%ld is corrupted, can't proceed with loading chain \"%s : %s\" cell 0x%016"DAP_UINT64_FORMAT_X"",
                                q, a_cell->chain->net_name, a_cell->chain->name, a_cell->id.uint64);
                l_ret = 11;
                break;
            }
            ++q;
            l_pos += sizeof(uint64_t) + l_read;
            if ( !a_cell->chain->callback_atom_prefetch )
                a_cell->chain->load_progress = (int)((float)l_pos/l_full_size * 100 + 0.5);
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
    log_it(L_INFO, "Loaded %lu atoms in chain \"%s : %s\" cell 0x%016"DAP_UINT64_FORMAT_X"",
                    q, a_cell->chain->net_name, a_cell->chain->name, a_cell->id.uint64);
    return l_ret;
}

DAP_STATIC_INLINE int s_cell_open(dap_chain_t *a_chain, const char *a_filename, const char a_mode) {
    dap_chain_cell_id_t l_cell_id = { };
    { /* Check filename */
        char l_fmt[20] = "", l_ext[ sizeof(CELL_FILE_EXT) ] = "", l_ext2 = '\0';
        snprintf(l_fmt, sizeof(l_fmt), "%s%lu%s", "%"DAP_UINT64_FORMAT_x".%", sizeof(CELL_FILE_EXT) - 1, "[^.].%c");

        switch ( sscanf(a_filename, l_fmt, &l_cell_id.uint64, l_ext, &l_ext2) ) {
        case 3:
            // TODO: X.dchaincell.*
        case 2:
            if ( !dap_strncmp(l_ext, CELL_FILE_EXT, sizeof(l_ext)) )
                break;
        default:
            return log_it(L_ERROR, "Invalid cell file name \"%s\"", a_filename), EINVAL;
        }
    }
    char file_storage_path[MAX_PATH], mode[] = { a_mode, '+', 'b', '\0' };
    snprintf(file_storage_path, MAX_PATH, "%s/%s", DAP_CHAIN_PVT(a_chain)->file_storage_dir, a_filename);
    dap_chain_cell_t *l_cell = NULL;

#define m_ret_err(err, ...) return ({ if (l_cell->file_storage) fclose(l_cell->file_storage); \
                                      DAP_DELETE(l_cell); log_it(L_ERROR, ##__VA_ARGS__), err; })

    dap_chain_cell_mmap_data_t l_cell_map_data = { };
    HASH_FIND(hh, a_chain->cells, &l_cell_id, sizeof(dap_chain_cell_id_t), l_cell);
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
    FILE *l_file = fopen(file_storage_path, mode);
    if ( !l_file )
        m_ret_err(errno, "Cell \"%s : %s / \"%s\" cannot be opened, error %d",
                         a_chain->net_name, a_chain->name, a_filename, errno);

    l_cell = DAP_NEW_Z(dap_chain_cell_t);
    *l_cell = (dap_chain_cell_t) {
        .id             = l_cell_id,
        .chain          = a_chain,
        .file_storage   = l_file,
        //.storage_rwlock = PTHREAD_RWLOCK_INITIALIZER
    };
    dap_strncpy(l_cell->file_storage_path, file_storage_path, MAX_PATH);

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
            .cell_id        = l_cell_id
        };
        if ( !fwrite(&l_hdr, sizeof(l_hdr), 1, l_cell->file_storage) )
            m_ret_err(errno, "fwrite() error %d", errno);
        fflush(l_cell->file_storage);
        l_cell->file_storage = freopen(file_storage_path, "a+b", l_cell->file_storage);
        if ( a_chain->is_mapped && s_cell_map_new_volume(l_cell, 0, false) )
            m_ret_err(EINVAL, "Error on mapping the first volume");
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

int dap_chain_cell_open(dap_chain_t *a_chain, const char *a_filename, const char a_mode) {
    pthread_rwlock_wrlock(&a_chain->cell_rwlock);
    int l_ret = s_cell_open(a_chain, a_filename, a_mode);
    pthread_rwlock_unlock(&a_chain->cell_rwlock);
    return l_ret;
}

static int s_cell_file_atom_add(dap_chain_cell_t *a_cell, dap_chain_atom_ptr_t a_atom, uint64_t a_atom_size, char **a_atom_map)
{
    if (a_cell->chain->is_mapped) {
        off_t l_pos = !fseeko(a_cell->file_storage, 0, SEEK_END) ? ftello(a_cell->file_storage) : -1;
        dap_return_val_if_pass_err(l_pos < 0, -1, "Can't get \"%s : %s\" cell 0x%016"DAP_UINT64_FORMAT_X" size, error %d",
                                                     a_cell->chain->net_name, a_cell->chain->name, a_cell->id.uint64, errno);
        if ( a_atom_size + sizeof(uint64_t) > (size_t)(a_cell->mapping->volume->base + a_cell->mapping->volume->size - a_cell->mapping->cursor) )
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
        a_cell->mapping->volume->base = mmap( a_cell->mapping->volume->base, a_cell->mapping->volume->size,
                                              PROT_READ, MAP_PRIVATE | MAP_FIXED, fileno(a_cell->file_storage),
                                              a_cell->mapping->volume->offset );
        dap_return_val_if_pass_err( a_cell->mapping->volume->base == MAP_FAILED, -2,
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
    return 0;
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
    dap_chain_cell_remit(l_cell);
    return 0;
}
