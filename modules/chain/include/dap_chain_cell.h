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
#include <stddef.h>
#include <stdio.h>
#include <pthread.h>
#include "dap_ht.h"
#include "dap_chain.h"
#include "dap_chain_common.h"
#include "dap_serialize.h"

#define DAP_CHAIN_CELL_MAX_COUNT    32
#define DAP_CHAIN_CELL_FILE_EXT     "dchaincell"

/**
 * @brief On-disk / mmap header at the start of a chain cell file.
 */
typedef struct dap_chain_cell_file_header {
    uint64_t signature;
    uint32_t version;
    uint8_t type;
    dap_chain_id_t chain_id;
    dap_chain_net_id_t chain_net_id;
    dap_chain_cell_id_t cell_id;
} DAP_ALIGN_PACKED dap_chain_cell_file_header_t;
_Static_assert(sizeof(dap_chain_cell_file_header_t) == 8u + 4u + 1u + 8u + 8u + 8u,
               "dap_chain_cell_file_header_t wire size");

/** Wire size of @ref dap_chain_cell_file_header_t (packed). */
#define DAP_CHAIN_CELL_FILE_HEADER_WIRE_SIZE sizeof(dap_chain_cell_file_header_t)

/**
 * @brief Naturally aligned in-memory view of @ref dap_chain_cell_file_header_t (matches wire layout).
 */
typedef struct dap_chain_cell_file_header_mem {
    uint64_t signature;
    uint32_t version;
    uint8_t type;
    uint8_t chain_id[DAP_CHAIN_ID_SIZE];
    uint8_t chain_net_id[DAP_CHAIN_NET_ID_SIZE];
    uint8_t cell_id[DAP_CHAIN_SHARD_ID_SIZE];
} dap_chain_cell_file_header_mem_t;

/* _mem_t has trailing padding (40 bytes) vs wire format (37 bytes) — validated by dap_serialize */

extern const dap_serialize_field_t g_dap_chain_cell_file_header_fields[];
extern const dap_serialize_schema_t g_dap_chain_cell_file_header_schema;
#define DAP_CHAIN_CELL_FILE_HEADER_SERIALIZE_MAGIC 0xCF5FF010U

static inline int dap_chain_cell_file_header_pack(const dap_chain_cell_file_header_mem_t *a_mem, uint8_t *a_wire,
                                                  size_t a_wire_size)
{
    if (a_wire_size < DAP_CHAIN_CELL_FILE_HEADER_WIRE_SIZE)
        return -1;
    dap_serialize_result_t l_r =
        dap_serialize_to_buffer_raw(&g_dap_chain_cell_file_header_schema, a_mem, a_wire, a_wire_size, NULL);
    return l_r.error_code;
}

static inline int dap_chain_cell_file_header_unpack(const uint8_t *a_wire, size_t a_wire_size,
                                                    dap_chain_cell_file_header_mem_t *a_mem)
{
    if (a_wire_size < DAP_CHAIN_CELL_FILE_HEADER_WIRE_SIZE)
        return -1;
    dap_deserialize_result_t l_r =
        dap_deserialize_from_buffer_raw(&g_dap_chain_cell_file_header_schema, a_wire, a_wire_size, a_mem, NULL);
    return l_r.error_code;
}

typedef struct dap_chain_cell_mmap_data dap_chain_cell_mmap_data_t;

typedef struct dap_chain_cell {
    dap_chain_cell_id_t id;
    dap_chain_t *chain;
    char file_storage_path[MAX_PATH];
    dap_chain_cell_mmap_data_t *mapping;
    FILE *file_storage;
    uint8_t file_storage_type;
#ifdef DAP_OS_DARWIN
    size_t cur_vol_start;
#endif
    pthread_rwlock_t storage_rwlock;
    dap_ht_handle_t hh;
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
_Static_assert(sizeof(dap_chain_cell_decl_req_t) == (1u + 8u + 4u + 32u + 32u) + 8u + 32u,
               "dap_chain_cell_decl_req_t wire size");

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
_Static_assert(sizeof(dap_chain_cell_decl_t) == sizeof(dap_chain_cell_decl_req_t) + 8u + 8u + 32u,
               "dap_chain_cell_decl_t wire size");


int dap_chain_cell_init(void);
int dap_chain_cell_open(dap_chain_t *a_chain, const dap_chain_cell_id_t a_cell_id, const char a_mode);
DAP_STATIC_INLINE int dap_chain_cell_create(dap_chain_t *a_chain, const dap_chain_cell_id_t a_cell_id) {
    return dap_chain_cell_open(a_chain, a_cell_id, 'w');
}

DAP_STATIC_INLINE dap_chain_cell_t *dap_chain_cell_find_by_id(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id) {
    dap_chain_cell_t *l_cell = NULL;
    dap_ht_find(a_chain->cells, &a_cell_id, sizeof(dap_chain_cell_id_t), l_cell);
    return l_cell;
}
DAP_STATIC_INLINE dap_chain_cell_t *dap_chain_cell_capture_by_id(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id) {
    pthread_rwlock_rdlock(&a_chain->cell_rwlock);
    return dap_chain_cell_find_by_id(a_chain, a_cell_id);
}
DAP_STATIC_INLINE void dap_chain_cell_remit(dap_chain_t *a_chain) {
    pthread_rwlock_unlock(&a_chain->cell_rwlock);
}

void dap_chain_cell_close(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id);
void dap_chain_cell_close_all(dap_chain_t *a_chain);
int dap_chain_cell_file_append(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id,
                                   const void *a_atom, size_t a_atom_size, char **a_atom_map);
int dap_chain_cell_remove(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, bool a_archivate);
int dap_chain_cell_truncate(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, size_t a_delta);
void dap_chain_cell_set_load_skip();