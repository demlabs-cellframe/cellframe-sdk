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
    //s_cells_path = dap_config_get_item_str(g_config,"resources","cells_storage");
    return  0;
}

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
    return (int)fwrite(&l_hdr, sizeof(l_hdr), 1, a_cell->file_storage);
}

DAP_STATIC_INLINE int s_cell_map_new_volume(dap_chain_cell_t *a_cell, size_t a_fpos) {
    int l_fildes = fileno(a_cell->file_storage);
#ifdef DAP_OS_WINDOWS
    HANDLE hSection = NULL;
    if ( !a_fpos ) {
        //if (a_cell->map_range_bounds)
        //    NtClose( (HANDLE)a_cell->map_range_bounds->data );
        LARGE_INTEGER SectionSize = { 
            .QuadPart = ( fseek(a_cell->file_storage, 0, SEEK_END), ftell(a_cell->file_storage) ) 
        };
        
        NTSTATUS err = pfnNtCreateSection(&hSection, SECTION_MAP_READ|SECTION_EXTEND_SIZE|SECTION_MAP_WRITE, 
                                          NULL, &SectionSize, PAGE_READWRITE, SEC_RESERVE,
                                          (HANDLE)_get_osfhandle(l_fildes));
        if ( !NT_SUCCESS(err) ) {
            log_it(L_ERROR, "NtCreateSection() failed, status %lx", err);
            return -1;
        }
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
    if ( !NT_SUCCESS ( err = pfnNtMapViewOfSection(hSection, GetCurrentProcess(), 
                                                   (HANDLE)&a_cell->map, 0, 0, 
                                                   &Offset, &l_map_size,
                                                   ViewUnmap, MEM_RESERVE,
                                                   PAGE_WRITECOPY) ) )
    {
        log_it(L_ERROR, "NtMapViewOfSection() failed, status %lx", err);
        NtClose(hSection);
        return -1;
    }
#else
    if ( MAP_FAILED == (a_cell->map = mmap(NULL, l_map_size, PROT_READ|PROT_WRITE,
                                           MAP_PRIVATE, fileno(a_cell->file_storage), l_volume_start)) ) {
        log_it(L_ERROR, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X" cannot be mapped, errno %d",
                        a_cell->file_storage_path, a_cell->id.uint64, errno);
        return -1;
    }
#endif
    a_cell->map_pos = a_cell->map + l_offset;
    a_cell->map_range_bounds = dap_list_append(a_cell->map_range_bounds, a_cell->map);
    a_cell->map_range_bounds = dap_list_append(a_cell->map_range_bounds, a_cell->map_end = a_cell->map + l_map_size);
    return 0;
}

/**
 * @brief dap_chain_cell_find_by_id
 * get dap_chain_cell_t object by cell (shard) id
 * @param a_chain dap_chain_t object
 * @param a_cell_id dap_chain_cell_id_t cell (shard) id
 * @return dap_chain_cell_t* 
 */
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
        .storage_rwlock = PTHREAD_RWLOCK_INITIALIZER
    };
    size_t l_size = ( fseek(l_file, 0, SEEK_END), ftell(l_file) );
    if ( l_size < sizeof(dap_chain_cell_file_header_t) ) {
        if (l_size) {
            log_it(L_INFO, "Possibly corrupt cell storage 0x%016"DAP_UINT64_FORMAT_X" \"%s\", rewriting it",
                            a_cell_id.uint64, file_storage_path);
            l_file = freopen(file_storage_path, "w+b", l_file);
        }
        if ( !s_cell_file_write_header(l_cell) ) {
            log_it(L_ERROR, "Can't init file storage for cell 0x%016"DAP_UINT64_FORMAT_X" \"%s\", errno %d",
                             a_cell_id.uint64, file_storage_path, errno);
            CLEANUP_AND_RET;
        }
        log_it(L_NOTICE, "Initialized file storage for cell 0x%016"DAP_UINT64_FORMAT_X" \"%s\"",
                          a_cell_id.uint64, file_storage_path);
        fflush(l_file);
    }

    if ( a_chain->is_mapped && s_cell_map_new_volume(l_cell, 0) ) {
        CLEANUP_AND_RET;
    }
#undef CLEANUP_AND_RET
    memcpy(l_cell->file_storage_path, file_storage_path, sizeof(file_storage_path));
    debug_if (s_debug_more && a_chain->is_mapped, L_DEBUG, "Mapped volume size is %lu", (size_t)(l_cell->map_end - l_cell->map));
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
    if(a_cell->file_storage) {
        fclose(a_cell->file_storage);
        a_cell->file_storage = NULL;
    }
    if (a_cell->chain->is_mapped) {
        dap_list_t *l_iter = a_cell->map_range_bounds;
#ifdef DAP_OS_WINDOWS
        l_iter = l_iter->next;
#endif
        for (; l_iter; l_iter = l_iter->next) {
            if (l_iter->next) {
                debug_if(s_debug_more, L_DEBUG, "Unmap volume %p (%lu bytes)", l_iter->data, (size_t)(l_iter->next->data - l_iter->data));
#ifdef DAP_OS_WINDOWS
                pfnNtUnmapViewOfSection(GetCurrentProcess(), l_iter->data);
#else
                munmap(l_iter->data, (size_t)(l_iter->next->data - l_iter->data));
#endif
                l_iter = l_iter->next;
            }
        }
#ifdef DAP_OS_WINDOWS
        NtClose(a_cell->map_range_bounds->data);
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
                .file_storage   = l_file
        };
        if ( !s_cell_file_write_header(l_cell_nh)) {
            log_it(L_ERROR, "Can't init file storage for cell 0x%016"DAP_UINT64_FORMAT_X" \"%s\", errno %d",
                   l_cell_id.uint64, l_fsp, errno);
        } else {
            log_it(L_NOTICE, "Reinitialized file storage for cell 0x%016"DAP_UINT64_FORMAT_X" \"%s\"",
                   l_cell_id.uint64, l_fsp);
        }
        dap_chain_cell_close(l_cell_nh);

        DAP_DELETE(l_fsp);
        HASH_DEL(a_chain->cells, l_cell);
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
    size_t l_size = ( fseek(a_cell->file_storage, 0, SEEK_END), ftell(a_cell->file_storage) ), l_pos = 0;
    if ( l_size < sizeof(dap_chain_cell_file_header_t) ) {
        log_it(L_ERROR, "Chain cell \"%s\" is corrupt, create new file", a_cell->file_storage_path);
        return -1;
    }
    int l_ret = 0;
    dap_chain_cell_file_header_t *l_hdr = NULL;
    if (a_chain->is_mapped) {
        l_hdr = (dap_chain_cell_file_header_t*)a_cell->map;
    } else {
        fseek(a_cell->file_storage, 0, SEEK_SET);
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
    l_pos += sizeof(dap_chain_cell_file_header_t);
    if (a_chain->is_mapped)
        a_cell->map_pos += l_pos;
    if (l_size == l_pos) {
        fseek(a_cell->file_storage, l_pos, SEEK_SET);
        return 0;
    }
        
        
    uint64_t q = 0;
    if (a_chain->is_mapped) {
        a_cell->map_pos = a_cell->map + sizeof(dap_chain_cell_file_header_t);
        for ( uint64_t l_el_size = 0; l_pos < l_size; ++q, l_pos += l_el_size + sizeof(uint64_t), a_chain->load_progress =  (int)((double)l_pos/l_size * 100 + 0.5)) {
            size_t space_left = (size_t)( a_cell->map_end - a_cell->map_pos );
            if ( space_left < sizeof(uint64_t) || (space_left - sizeof(uint64_t)) < *(uint64_t*)a_cell->map_pos )
                if ( s_cell_map_new_volume(a_cell, l_pos) )
                    break;
            l_el_size = *(uint64_t*)a_cell->map_pos;
            dap_hash_fast_t l_atom_hash;
            dap_chain_atom_ptr_t l_atom = (dap_chain_atom_ptr_t)(a_cell->map_pos += sizeof(uint64_t));
            dap_hash_fast(l_atom, l_el_size, &l_atom_hash);
            a_chain->callback_atom_add(a_chain, l_atom, l_el_size, &l_atom_hash);
            a_cell->map_pos += l_el_size;
        }
    } else { 
        DAP_DELETE(l_hdr);
        size_t l_read = 0;
        uint64_t l_el_size = 0;
        while ((l_read = fread(&l_el_size, 1, sizeof(l_el_size), a_cell->file_storage)) && !feof(a_cell->file_storage)) {
            if (l_read != sizeof(l_el_size) || l_el_size == 0) {
                log_it(L_ERROR, "Corrupted element size %zu, chain %s is damaged", l_el_size, a_cell->file_storage_path);
                l_ret = -4;
                break;
            }
            dap_chain_atom_ptr_t l_element = DAP_NEW_SIZE(dap_chain_atom_ptr_t, l_el_size);
            if (!l_element) {
                log_it(L_CRITICAL, "Memory allocation error");
                l_ret = -5;
                break;
            }
            l_pos += sizeof(uint64_t) + ( l_read = fread((void*)l_element, 1, l_el_size, a_cell->file_storage) );
            a_chain->load_progress =  (int)((double)l_pos/l_size * 100 + 0.5);
            if (l_read != l_el_size) {
                log_it(L_ERROR, "Read only %lu of %zu bytes, stop cell loading", l_read, l_el_size);
                DAP_DELETE(l_element);
                l_ret = -6;
                break;
            }
            dap_hash_fast_t l_atom_hash = {};
            dap_hash_fast(l_element, l_el_size, &l_atom_hash);
            dap_chain_atom_verify_res_t l_res = a_chain->callback_atom_add(a_chain, l_element, l_el_size, &l_atom_hash);
            if (l_res != ATOM_ACCEPT && l_res != ATOM_FORK) {
                DAP_DELETE(l_element);
            }
            ++q;
        }
    }
    fseek(a_cell->file_storage, l_pos, SEEK_SET);
    log_it(L_INFO, "Loaded %lu atoms in cell %s", q, a_cell->file_storage_path);
    return l_ret;
}

static int s_cell_file_atom_add(dap_chain_cell_t *a_cell, dap_chain_atom_ptr_t a_atom, uint64_t a_atom_size)
{
    if (!a_atom || !a_atom_size) {
        log_it(L_CRITICAL, "Invalid arguments");
        return -1;
    }
    if (a_cell->chain->is_mapped) {
        size_t l_pos = ( fseek(a_cell->file_storage, 0, SEEK_END), ftell(a_cell->file_storage) );
        debug_if (s_debug_more, L_DEBUG, "Before filling volume for atom size %lu, stream pos of %s is %lu, map pos is %lu, space left in map %lu",
                      a_atom_size, a_cell->file_storage_path, l_pos, (size_t)(a_cell->map_pos - a_cell->map), (size_t)(a_cell->map_end - a_cell->map_pos));
        if ( a_atom_size + sizeof(uint64_t) > (size_t)(a_cell->map_end - a_cell->map_pos) )
            if ( s_cell_map_new_volume(a_cell, l_pos) )
                return -2;
    }
    
    debug_if (s_debug_more && a_cell->chain->is_mapped, L_DEBUG, "Before writing an atom of size %lu, stream pos of %s is %lu and pos is %lu, space left in map %lu", 
                                            a_atom_size, a_cell->file_storage_path, ftell(a_cell->file_storage),
                                            (size_t)(a_cell->map_pos - a_cell->map), (size_t)(a_cell->map_end - a_cell->map_pos));

    if (fwrite(&a_atom_size, sizeof(a_atom_size), 1, a_cell->file_storage) != 1) {
        log_it (L_ERROR, "Can't write atom data size from cell 0x%016"DAP_UINT64_FORMAT_X" in \"%s\"",
                a_cell->id.uint64,
                a_cell->file_storage_path);
        return -2;
    }
    if (fwrite(a_atom, a_atom_size, 1, a_cell->file_storage) != 1) {
        log_it (L_ERROR, "Can't write data from cell 0x%016"DAP_UINT64_FORMAT_X" to the file \"%s\"",
                         a_cell->id.uint64,
                         a_cell->file_storage_path);
        return -3;
    }
    debug_if (s_debug_more && a_cell->chain->is_mapped, L_DEBUG, "After writing an atom of size %lu, stream pos of %s is %lu and map shift is %lu", 
                                            a_atom_size, a_cell->file_storage_path, ftell(a_cell->file_storage),
                                            (size_t)(a_cell->map_pos - a_cell->map));
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
#ifdef DAP_OS_WINDOWS
        strcat(a_cell->file_storage_path, ".new");
#endif
        a_cell->file_storage = freopen(a_cell->file_storage_path, "w+b", a_cell->file_storage);
        debug_if (s_debug_more,L_DEBUG, "Rewinding file %s", a_cell->file_storage_path);
        bool was_mapped = a_cell->chain->is_mapped;
        a_cell->chain->is_mapped = false;
        if ( !s_cell_file_write_header(a_cell) ) {
            log_it(L_ERROR, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X": can't fill header",
                            a_cell->file_storage_path, a_cell->id.uint64);
            a_cell->chain->is_mapped = was_mapped;
            pthread_rwlock_unlock(&a_cell->storage_rwlock);
            return -2;
        }
        l_total_res += sizeof(dap_chain_cell_file_header_t);
        dap_chain_atom_iter_t *l_atom_iter = a_cell->chain->callback_atom_iter_create(a_cell->chain, a_cell->id, NULL);
        dap_chain_atom_ptr_t l_atom;
        uint64_t l_atom_size = 0;
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
        debug_if (s_debug_more && a_cell->chain->is_mapped,L_DEBUG, "After rewriting file %s, stream pos is %lu and map pos is %lu",
                      a_cell->file_storage_path, ftell(a_cell->file_storage),
                      (size_t)(a_cell->map_pos - a_cell->map));
    } else {
        debug_if (s_debug_more && a_cell->chain->is_mapped,L_DEBUG, "Before appending an atom of size %lu, stream pos of %s is %lu, map pos is %lu",
                      a_atom_size, a_cell->file_storage_path, ftell(a_cell->file_storage),
                      (size_t)(a_cell->map_pos - a_cell->map));
        if ( s_cell_file_atom_add(a_cell, a_atom, a_atom_size) ) {
            log_it(L_ERROR, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X": can't save atom!",
                   a_cell->file_storage_path, a_cell->id.uint64);
            pthread_rwlock_unlock(&a_cell->storage_rwlock);
            return -4;
        }
        debug_if (s_debug_more && a_cell->chain->is_mapped, L_DEBUG,"After appending an atom of size %lu, stream pos of %s is %lu, map pos is %lu",
                                                a_atom_size, a_cell->file_storage_path, ftell(a_cell->file_storage),
                                                (size_t)(a_cell->map_end - a_cell->map_pos));
        ++l_count;
        l_total_res = a_atom_size + sizeof(uint64_t);
    }

    if (l_total_res) {
        fflush(a_cell->file_storage);
#ifdef DAP_OS_WINDOWS
        if (a_cell->chain->is_mapped) {
            LARGE_INTEGER SectionSize = (LARGE_INTEGER) { .QuadPart = ftell(a_cell->file_storage) };
            HANDLE hSection = (HANDLE)a_cell->map_range_bounds->data;
            NTSTATUS err = pfnNtExtendSection(hSection, &SectionSize);
            if ( !NT_SUCCESS(err) ) {
                log_it(L_ERROR, "NtExtendSection() failed, status %lx", err);
                return -4;
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

