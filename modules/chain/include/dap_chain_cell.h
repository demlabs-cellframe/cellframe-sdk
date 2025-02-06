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
#pragma once
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include "uthash.h"
#include "dap_chain.h"
#include "dap_chain_common.h"

typedef struct dap_chain_cell_mmap_data {
    off_t vol_size;
    char *map, *map_pos, **maps;
} dap_chain_cell_mmap_data_t;

typedef struct dap_chain_cell {
    dap_chain_cell_id_t id;
    dap_chain_t * chain;

    char file_storage_path[MAX_PATH];
    char *map, *map_pos, *map_end;
    FILE *file_storage;
    uint8_t file_storage_type;
    dap_list_t *map_range_bounds;
#ifdef DAP_OS_DARWIN
    size_t cur_vol_start;
#endif
    pthread_rwlock_t storage_rwlock;
    UT_hash_handle hh;
} dap_chain_cell_t;

/**
 *
 */
#define DAP_CHAIN_CELL_DECL_REQ_SIGN_SIZE 32
typedef struct dap_chain_cell_delc_req {
    dap_chain_addr_t wallet_address;  // Need new wallet address where the hold coins should be directed. Must have undefined cell
    uint64_t create_ts;
    union{
        uint8_t raw[DAP_CHAIN_CELL_DECL_REQ_SIGN_SIZE];
        char str[DAP_CHAIN_CELL_DECL_REQ_SIGN_SIZE];
    } info;
} DAP_ALIGN_PACKED dap_chain_cell_decl_req_t;

/**
  * @struct dap_chain_cell_decl
  * @details New cell declaration
  *
  */
#define DAP_CHAIN_CELL_DECL_ACCEPT_INFO_SIZE 32
typedef struct dap_chain_cell_decl{
    dap_chain_cell_decl_req_t request;
    dap_chain_cell_id_t cell_id;
    uint64_t accept_ts;
    union{
        uint8_t raw[DAP_CHAIN_CELL_DECL_ACCEPT_INFO_SIZE];
        char str[DAP_CHAIN_CELL_DECL_ACCEPT_INFO_SIZE];
    } accept_info;
} DAP_ALIGN_PACKED dap_chain_cell_decl_t;


int dap_chain_cell_init(void);
int dap_chain_cell_open(dap_chain_t *a_chain, const char *a_filename, const char a_mode);

DAP_INLINE dap_chain_cell_t *dap_chain_cell_find_by_id(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id) {
    dap_chain_cell_t *l_cell = NULL;
    HASH_FIND(hh, a_chain->cells, &a_cell_id, sizeof(dap_chain_cell_id_t), l_cell);
    return l_cell;
}
DAP_INLINE dap_chain_cell_t *dap_chain_cell_capture_by_id(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id) {
    pthread_rwlock_rdlock(&a_chain->cell_rwlock);
    return dap_chain_cell_find_by_id(a_chain, a_cell_id);
}
DAP_INLINE void dap_chain_cell_remit(const dap_chain_cell_t *a_cell) {
    pthread_rwlock_unlock(&a_cell->chain->cell_rwlock);
}

void dap_chain_cell_close(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id);
void dap_chain_cell_close_all(dap_chain_t *a_chain);
int dap_chain_cell_file_append(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id,
                                   const void *a_atom, size_t a_atom_size, char **a_atom_map);
#define dap_chain_cell_file_update(a_cell) dap_chain_cell_file_append(a_cell, NULL, 0);

