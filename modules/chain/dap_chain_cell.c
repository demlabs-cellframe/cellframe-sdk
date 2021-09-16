/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
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

#include "dap_common.h"
#include "dap_config.h"
#include "dap_strfuncs.h"
#include "dap_chain.h"
#include "dap_chain_cell.h"
#include "dap_chain_cs.h"
#include "dap_chain_pvt.h"

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


//static const char* s_cells_path = NULL;

/**
 * @brief dap_chain_cell_init
 * @return
 */
int dap_chain_cell_init(void)
{
    //s_cells_path = dap_config_get_item_str(g_config,"resources","cells_storage");
    return  0;
}

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
 * @brief dap_chain_cell_create_fill
 * a_cell_id if <0 then not used
 * @return
 */
dap_chain_cell_t * dap_chain_cell_create_fill(dap_chain_t * a_chain, dap_chain_cell_id_t a_cell_id)
{
    dap_chain_cell_t * l_cell = DAP_NEW_Z(dap_chain_cell_t);
    l_cell->chain = a_chain;
    l_cell->id.uint64 = a_cell_id.uint64;
    l_cell->file_storage_path = dap_strdup_printf("%0"DAP_UINT64_FORMAT_x".dchaincell", l_cell->id.uint64);
    pthread_rwlock_wrlock(&a_chain->cell_rwlock);
    HASH_ADD(hh, a_chain->cells, id, sizeof(dap_chain_cell_id_t), l_cell);
    pthread_rwlock_unlock(&a_chain->cell_rwlock);
    return l_cell;
}

dap_chain_cell_t * dap_chain_cell_create_fill2(dap_chain_t * a_chain, const char *a_filename)
{
    dap_chain_cell_t * l_cell = DAP_NEW_Z(dap_chain_cell_t);
    l_cell->chain = a_chain;
    sscanf(a_filename, "%"DAP_UINT64_FORMAT_x".dchaincell", &l_cell->id.uint64);
    l_cell->file_storage_path = dap_strdup_printf(a_filename);
    pthread_rwlock_wrlock(&a_chain->cell_rwlock);
    HASH_ADD(hh, a_chain->cells, id, sizeof(dap_chain_cell_id_t), l_cell);
    pthread_rwlock_unlock(&a_chain->cell_rwlock);
    return l_cell;
}

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
 * @brief dap_chain_cell_delete
 * @return
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
    DAP_DEL_Z(a_cell->file_storage_path)
    DAP_DEL_Z(a_cell);
}

/**
 * @brief dap_chain_cell_load
 * @param a_chain
 * @param a_cell_file_path
 * @return
 */
int dap_chain_cell_load(dap_chain_t * a_chain, const char * a_cell_file_path)
{
    int ret = 0;
    char l_file_path[MAX_PATH] = {'\0'};
    dap_snprintf(l_file_path, MAX_PATH, "%s/%s", DAP_CHAIN_PVT(a_chain)->file_storage_dir, a_cell_file_path);
    FILE *l_f = fopen(l_file_path, "rb");
    if (!l_f) {
        log_it(L_WARNING,"Can't read chain \"%s\"", l_file_path);
        return -1;
    }
    dap_chain_cell_file_header_t l_hdr = { 0 };
    if (fread(&l_hdr, 1, sizeof(l_hdr), l_f) != sizeof (l_hdr)) {
        log_it(L_ERROR,"Can't read chain header \"%s\"", l_file_path);
        fclose(l_f);
        return -2;
    }
    if (l_hdr.signature != DAP_CHAIN_CELL_FILE_SIGNATURE) {
        log_it(L_ERROR, "Wrong signature in chain \"%s\", possible file corrupt", l_file_path);
        fclose(l_f);
        return -3;
    }
    size_t l_el_size = 0;
    unsigned long q = 0;
    volatile dap_chain_cell_t *l_dummy;
    for (fread(&l_el_size, 1, sizeof(l_el_size), l_f); !feof(l_f); l_el_size = 0, fread(&l_el_size, 1, sizeof(l_el_size), l_f))
    {
        if (!l_el_size) {
            log_it(L_ERROR, "Zero element size, chain %s is corrupted", l_file_path);
            ret = -4;
            break;
        }
        dap_chain_atom_ptr_t l_element = DAP_NEW_Z_SIZE(dap_chain_atom_ptr_t, l_el_size);
        if (!l_element) {
            log_it(L_ERROR, "Out of memory");
            ret = -5;
            break;
        }
        unsigned long l_read = fread(l_element, 1, l_el_size, l_f);
        if(l_read == l_el_size) {
            a_chain->callback_atom_add(a_chain, l_element, l_el_size); // !!! blocking GDB call !!!
            ++q;
            DAP_DELETE(l_element);
        } else {
            log_it(L_ERROR, "Read only %zd of %zd bytes, stop cell loading", l_read, l_el_size);
            ret = -6;
            DAP_DELETE(l_element);
            break;
        }
    }
    if (ret < 0) {
        log_it(L_INFO, "Couldn't load all atoms, %d only", q);
    } else {
        log_it(L_INFO, "Loaded all %d atoms in cell %s", q, a_cell_file_path);
        l_dummy = dap_chain_cell_create_fill2(a_chain, a_cell_file_path);
    }
    fclose(l_f);
    return ret;

}

/**
 * @brief s_cell_file_append
 * @param a_cell
 * @param a_atom
 * @param a_atom_size
 * @return
 */
int dap_chain_cell_file_append( dap_chain_cell_t * a_cell, const void* a_atom, size_t a_atom_size)
{
    if(!a_cell)
        return -1;
    if (!a_atom && !a_cell->chain) {
        log_it(L_WARNING,"Chain not found for cell 0x%016X ( %s )",
                               a_cell->id.uint64, a_cell->file_storage_path);
        return -1;
    }
    if(!a_cell->file_storage) {
        char l_file_path[MAX_PATH] = {'\0'};
        dap_snprintf(l_file_path, MAX_PATH, "%s/%s", DAP_CHAIN_PVT(a_cell->chain)->file_storage_dir,
                     a_cell->file_storage_path);
        if(!a_cell->file_storage)
            a_cell->file_storage = fopen(l_file_path, "r+b");
        if (!a_cell->file_storage) {
            log_it(L_INFO, "Create chain cell");
            a_cell->file_storage = fopen(l_file_path, "w+b");
        }
        if (!a_cell->file_storage) {
            log_it(L_ERROR, "Chain cell \"%s\" cannot be opened 0x%016X",
                    a_cell->file_storage_path,
                    a_cell->id.uint64);
            return -3;
        }
    }
    fseek(a_cell->file_storage, 0L, SEEK_END);
    if (ftell(a_cell->file_storage) < (long)sizeof(dap_chain_cell_file_header_t)) { // fill the header
        fseek(a_cell->file_storage, 0L, SEEK_SET);
        dap_chain_cell_file_header_t l_hdr = {
            .signature = DAP_CHAIN_CELL_FILE_SIGNATURE,
            .version = DAP_CHAIN_CELL_FILE_VERSION,
            .type = DAP_CHAIN_CELL_FILE_TYPE_RAW,
            .chain_id = { .uint64 = a_cell->id.uint64 },
            .chain_net_id = a_cell->chain->net_id
        };
        if(fwrite(&l_hdr, 1, sizeof(l_hdr), a_cell->file_storage) == sizeof(l_hdr)) {
            log_it(L_NOTICE, "Initialized file storage for cell 0x%016X ( %s )",
                    a_cell->id.uint64, a_cell->file_storage_path);
        } else {
            log_it(L_ERROR, "Can't init file storage for cell 0x%016X ( %s )",
                    a_cell->id.uint64, a_cell->file_storage_path);
            dap_chain_cell_close(a_cell);
            return -4;
        }
    }
    // if no atom provided in arguments, we flush all the atoms in given chain
    size_t l_atom_size = a_atom_size ? a_atom_size : 0;
    int l_total_wrote_bytes = 0;
    dap_chain_atom_iter_t *l_atom_iter = a_atom ? a_cell->chain->callback_atom_iter_create(a_cell->chain) : NULL;
    for (dap_chain_atom_ptr_t l_atom = a_atom ? (dap_chain_atom_ptr_t)a_atom : a_cell->chain->callback_atom_iter_get_first(l_atom_iter, &l_atom_size);
         l_atom;
         l_atom = a_atom ? NULL : a_cell->chain->callback_atom_iter_get_next(l_atom_iter, &l_atom_size))
    {
        if (fwrite(&l_atom_size, 1, sizeof(l_atom_size), a_cell->file_storage) != sizeof(l_atom_size)) {
            log_it (L_ERROR,"Can't write atom data size from cell 0x%016X in \"%s\"",
                    a_cell->id.uint64,
                    a_cell->file_storage_path);
            dap_chain_cell_close(a_cell);
            l_total_wrote_bytes = -2;
            break;
        }
        l_total_wrote_bytes += sizeof(l_atom_size);
        if (fwrite(l_atom, 1, l_atom_size, a_cell->file_storage) != l_atom_size) {
            log_it (L_ERROR, "Can't write data from cell 0x%016X to the file \"%s\"",
                            a_cell->id.uint64,
                            a_cell->file_storage_path);
            dap_chain_cell_close(a_cell);
            l_total_wrote_bytes = -3;
            break;
        }
        l_total_wrote_bytes += l_atom_size;
        if(a_cell->chain && a_cell->chain->callback_notify)
            a_cell->chain->callback_notify(a_cell->chain->callback_notify_arg,
                                           a_cell->chain,
                                           a_cell->id,
                                           (void *)l_atom,
                                           l_atom_size);
    }
    if (l_atom_iter) {
        a_cell->chain->callback_atom_iter_delete(l_atom_iter);
    }
    return (int)l_total_wrote_bytes;
}

/**
 * @brief dap_chain_cell_file_update
 * @param a_cell
 * @return
 */
int dap_chain_cell_file_update( dap_chain_cell_t * a_cell)
{
    return dap_chain_cell_file_append(a_cell, NULL, 0);
}
