/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Demlabs Application Protocol) the open source project

    DAP (Demlabs Application Protocol) is free software: you can redistribute it and/or modify
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

#define LOG_TAG "dap_chain_cell"



#define DAP_CHAIN_CELL_FILE_VERSION 1
#define DAP_CHAIN_CELL_FILE_SIGNATURE 0xfa340bef153eba48
#define DAP_CHAIN_CELL_FILE_TYPE_RAW 0
#define DAP_CHAIN_CELL_FILE_TYPE_COMPRESSED 1

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


/**
 * @brief dap_chain_cell_init
 * current version simply returns 0
 * @return
 */
int dap_chain_cell_init(void)
{
    //s_cells_path = dap_config_get_item_str(g_config,"resources","cells_storage");
    return  0;
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
    l_cell = DAP_NEW_Z(dap_chain_cell_t);
    if ( !l_cell ) {
        pthread_rwlock_unlock(&a_chain->cell_rwlock);
        log_it(L_CRITICAL, "%s", g_error_memory_alloc);
        return NULL;
    }
    l_cell->chain = a_chain;
    l_cell->id.uint64 = a_cell_id.uint64;
    snprintf(l_cell->file_storage_path, MAX_PATH, "%s/%0"DAP_UINT64_FORMAT_x".dchaincell",
             DAP_CHAIN_PVT(a_chain)->file_storage_dir, l_cell->id.uint64);
    pthread_rwlock_init(&l_cell->storage_rwlock, NULL);
    HASH_ADD(hh, a_chain->cells, id, sizeof(dap_chain_cell_id_t), l_cell);
    pthread_rwlock_unlock(&a_chain->cell_rwlock);
    return l_cell;
}

/**
 * @brief dap_chain_cell_create_fill2
 * set l_cell->file_storage_path and l_cell->id.uint64 from name of chain. 
 * For example, 0.dchaincell. 0 - chain id, dchaincell - name of file
 * @param a_chain - chain object
 * @param a_filename - chain filename, for example "0.dchaincell"
 * @return dap_chain_cell_t* 
 */
dap_chain_cell_t * dap_chain_cell_create_fill2(dap_chain_t * a_chain, const char *a_filename)
{
    uint64_t l_cell_id_uint64;
    sscanf(a_filename, "%"DAP_UINT64_FORMAT_x".dchaincell", &l_cell_id_uint64);
    return dap_chain_cell_create_fill(a_chain, (dap_chain_cell_id_t){ .uint64 = l_cell_id_uint64});
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
    int l_ret = 0;
    FILE *l_cell_file = fopen(a_cell->file_storage_path, "rb");
    if (!l_cell_file) {
        log_it(L_WARNING,"Can't read chain \"%s\"", a_cell->file_storage_path);
        return -1;
    }
    dap_chain_cell_file_header_t l_hdr = { 0 };
    if (fread(&l_hdr, 1, sizeof(l_hdr), l_cell_file) != sizeof (l_hdr)) {
        log_it(L_ERROR,"Can't read chain header \"%s\"", a_cell->file_storage_path);
        fclose(l_cell_file);
        return -2;
    }
    if (l_hdr.signature != DAP_CHAIN_CELL_FILE_SIGNATURE) {
        log_it(L_ERROR, "Wrong signature in chain \"%s\", possible file corrupt", a_cell->file_storage_path);
        fclose(l_cell_file);
        return -3;
    }
    if (l_hdr.version < DAP_CHAIN_CELL_FILE_VERSION ){
        log_it(L_ERROR, "Too low chain version, backup files");
        fclose(l_cell_file);
        return -3;
    }
    unsigned long q = 0;
    size_t l_read = 0;
    uint64_t l_el_size = 0;
    while ((l_read = fread(&l_el_size, 1, sizeof(l_el_size), l_cell_file)) && !feof(l_cell_file)) {
        if (l_read != sizeof(l_el_size) || l_el_size == 0) {
            log_it(L_ERROR, "Corrupted element size %zu, chain %s is damaged", l_el_size, a_cell->file_storage_path);
            l_ret = -4;
            break;
        }
        dap_chain_atom_ptr_t l_element = DAP_NEW_SIZE(dap_chain_atom_ptr_t, l_el_size);
        if (!l_element) {
            log_it(L_CRITICAL, "%s", g_error_memory_alloc);
            l_ret = -5;
            break;
        }
        l_read = fread((void *)l_element, 1, l_el_size, l_cell_file);
        if (l_read != l_el_size) {
            log_it(L_ERROR, "Read only %lu of %zu bytes, stop cell loading", l_read, l_el_size);
            DAP_DELETE(l_element);
            l_ret = -6;
            break;
        }
        
        dap_hash_fast_t l_atom_hash = {};
        dap_hash_fast(l_element, l_el_size, &l_atom_hash);
        dap_chain_atom_verify_res_t l_res = a_chain->callback_atom_add(a_chain, l_element, l_el_size, &l_atom_hash); // !!! blocking GDB call !!!
        if (l_res == ATOM_PASS || l_res == ATOM_REJECT) {
            DAP_DELETE(l_element);
        }
        ++q;
    }
    if (l_ret < 0) {
        log_it(L_INFO, "Couldn't load all atoms, %lu only", q);
    } else {
        log_it(L_INFO, "Loaded all %lu atoms in cell %s", q, a_cell->file_storage_path);
    }
    fclose(l_cell_file);
    return l_ret;

}

static int s_file_write_header(dap_chain_cell_t *a_cell)
{
    if (!a_cell->file_storage) {
        log_it(L_ERROR, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X" not opened",
               a_cell->file_storage_path, a_cell->id.uint64);
        return -2;
    } else {
        fseek(a_cell->file_storage, 0L, SEEK_END);
        if (ftell(a_cell->file_storage) > (ssize_t)sizeof(dap_chain_cell_file_header_t)) {
            log_it(L_ERROR, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X" is already not empty!",
                   a_cell->file_storage_path, a_cell->id.uint64);
            return -3;
        }
    }
    dap_chain_cell_file_header_t l_hdr = {
        .signature      = DAP_CHAIN_CELL_FILE_SIGNATURE,
        .version        = DAP_CHAIN_CELL_FILE_VERSION,
        .type           = DAP_CHAIN_CELL_FILE_TYPE_RAW,
        .chain_id       = { .uint64 = a_cell->id.uint64 },
        .chain_net_id   = a_cell->chain->net_id
    };
    if(fwrite(&l_hdr, sizeof(l_hdr), 1, a_cell->file_storage) == 1) {
        log_it(L_NOTICE, "Initialized file storage for cell 0x%016"DAP_UINT64_FORMAT_X" ( %s )",
                a_cell->id.uint64, a_cell->file_storage_path);
        fflush(a_cell->file_storage);
        return 0;
    } else {
        log_it(L_ERROR, "Can't init file storage for cell 0x%016"DAP_UINT64_FORMAT_X" ( %s )",
                a_cell->id.uint64, a_cell->file_storage_path);
        return -1;
    }
}

static int s_file_atom_add(dap_chain_cell_t *a_cell, dap_chain_atom_ptr_t a_atom, uint64_t a_atom_size)
{
    if (!a_atom || !a_atom_size) {
        log_it(L_CRITICAL, "Invalid arguments");
        return -1;
    }
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
        a_cell->file_storage = a_cell->file_storage
                ? freopen(a_cell->file_storage_path, "w+b", a_cell->file_storage)
                : fopen(a_cell->file_storage_path, "w+b");
        if (!a_cell->file_storage) {
            log_it(L_ERROR, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X" cannot be opened",
                    a_cell->file_storage_path,
                    a_cell->id.uint64);
            pthread_rwlock_unlock(&a_cell->storage_rwlock);
            return -3;
        }
        if (s_file_write_header(a_cell)) {
            log_it(L_ERROR, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X": can't fill header", a_cell->file_storage_path, a_cell->id.uint64);
            pthread_rwlock_unlock(&a_cell->storage_rwlock);
            return -4;
        }
        dap_chain_atom_iter_t *l_atom_iter = a_cell->chain->callback_atom_iter_create(a_cell->chain, a_cell->id, NULL, false);
        dap_chain_atom_ptr_t l_atom;
        uint64_t l_atom_size = 0;
        for (l_atom = a_cell->chain->callback_atom_iter_get(l_atom_iter, DAP_CHAIN_ITER_OP_FIRST, &l_atom_size);
             l_atom && l_atom_size;
             l_atom = a_cell->chain->callback_atom_iter_get(l_atom_iter, DAP_CHAIN_ITER_OP_NEXT, &l_atom_size))
        {
            if (s_file_atom_add(a_cell, l_atom, l_atom_size)) {
                l_err = true;
                break;
            } else {
                l_total_res += l_atom_size + sizeof(uint64_t);
                ++l_count;
            }
        }
        a_cell->chain->callback_atom_iter_delete(l_atom_iter);
        a_cell->file_storage = freopen(a_cell->file_storage_path, "a+b", a_cell->file_storage);
    } else {
        if (!a_cell->file_storage)
            a_cell->file_storage = fopen(a_cell->file_storage_path, "a+b");
        if (!a_cell->file_storage) {
            log_it(L_ERROR, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X" cannot be opened",
                    a_cell->file_storage_path,
                    a_cell->id.uint64);
            pthread_rwlock_unlock(&a_cell->storage_rwlock);
            return -3;
        } else {
            fseek(a_cell->file_storage, 0L, SEEK_END);
            if (!ftell(a_cell->file_storage)) { // It's not garunteed that header has been yet added or not, regardless the descriptor validity
                if (s_file_write_header(a_cell)) {
                    log_it(L_ERROR, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X": can't fill header", a_cell->file_storage_path, a_cell->id.uint64);
                    pthread_rwlock_unlock(&a_cell->storage_rwlock);
                    return -4;
                }
            }
        }
        if (s_file_atom_add(a_cell, a_atom, a_atom_size)) {
            log_it(L_ERROR, "Chain cell \"%s\" 0x%016"DAP_UINT64_FORMAT_X": can't save atom!",
                   a_cell->file_storage_path, a_cell->id.uint64);
            pthread_rwlock_unlock(&a_cell->storage_rwlock);
            return -4;
        }
        ++l_count;
        l_total_res = a_atom_size + sizeof(uint64_t);
    }

    if (l_total_res) {
        fflush(a_cell->file_storage);
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

/**
 * @brief
 * return dap_chain_cell_file_append(a_cell, NULL, 0);
 * @param a_cell dap_chain_cell_t
 * @return
 */
ssize_t dap_chain_cell_file_update(dap_chain_cell_t *a_cell)
{
    return dap_chain_cell_file_append(a_cell, NULL, 0);
}
