/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net      https://gitlab/demlabs
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
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
#pragma once

#include "dap_chain_net.h"
#include "dap_enc_key.h"
#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_sign.h"
#include "dap_hash.h"

typedef struct dap_chain_cs_dag dap_chain_cs_dag_t;

typedef struct dap_chain_class_dag_event_hdr {
        uint16_t version;
        uint64_t round_id;
        dap_nanotime_t ts_created;
        dap_chain_id_t chain_id;
        dap_chain_cell_id_t cell_id; // Cell id if celled dag
        uint16_t hash_count; // Number of hashes
        uint16_t signs_count; // Number of signs nested with event
} DAP_ALIGN_PACKED dap_chain_class_dag_event_hdr_t;

typedef struct dap_chain_cs_dag_event {
    dap_chain_class_dag_event_hdr_t header;
    uint8_t hashes_n_datum_n_signs[]; // Hashes, signes and datum
} DAP_ALIGN_PACKED dap_chain_cs_dag_event_t;

typedef struct dap_chain_cs_dag_event_round_info {
    uint16_t reject_count;
    dap_nanotime_t ts_update;
    dap_chain_hash_fast_t datum_hash; // for doubles finding
} DAP_ALIGN_PACKED dap_chain_cs_dag_event_round_info_t;

typedef struct dap_chain_cs_dag_event_round_item {
    dap_chain_cs_dag_event_round_info_t round_info;// cfg;
    uint32_t event_size;
    uint32_t data_size;
    uint8_t event_n_signs[]; // event // dap_chain_cs_dag_event_t
} DAP_ALIGN_PACKED dap_chain_cs_dag_event_round_item_t;

dap_chain_cs_dag_event_t *dap_chain_cs_dag_event_new(dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id, uint64_t a_round_id,
                                                     dap_chain_datum_t *a_datum, dap_enc_key_t *a_key,
                                                     dap_chain_hash_fast_t *a_hashes, size_t a_hashes_count, size_t *a_event_size);

/**
 * @brief dap_chain_cs_dag_event_get_datum
 * @param a_event
 * @return
 */
static inline dap_chain_datum_t* dap_chain_cs_dag_event_get_datum(dap_chain_cs_dag_event_t * a_event,size_t a_event_size)
{
    return  a_event->header.hash_count * sizeof(dap_chain_hash_fast_t) <= a_event_size
                ? (dap_chain_datum_t*)(a_event->hashes_n_datum_n_signs + a_event->header.hash_count * sizeof(dap_chain_hash_fast_t))
                : NULL;
}

static inline size_t dap_chain_cs_dag_event_get_datum_size_maximum(dap_chain_cs_dag_event_t * a_event,size_t a_event_size)
{
    return  a_event->header.hash_count * sizeof(dap_chain_hash_fast_t) <= a_event_size
                ? a_event_size - a_event->header.hash_count * sizeof(dap_chain_hash_fast_t)
                : 0;
}

size_t dap_chain_cs_dag_event_sign_add(dap_chain_cs_dag_event_t **a_event_ptr, size_t a_event_size, dap_enc_key_t *a_key);
size_t dap_chain_cs_dag_event_round_sign_add(dap_chain_cs_dag_event_round_item_t **a_round_item_ptr, size_t a_round_item_size,
                                             dap_enc_key_t *a_key);
bool dap_chain_cs_dag_event_sign_exists(dap_chain_cs_dag_event_t *a_event, size_t a_event_size, dap_enc_key_t * a_key);
bool dap_chain_cs_dag_event_round_sign_exists(dap_chain_cs_dag_event_round_item_t *a_round_item, dap_enc_key_t * a_key);
dap_sign_t * dap_chain_cs_dag_event_get_sign( dap_chain_cs_dag_event_t * a_event, size_t a_event_size, uint16_t a_sign_number);

/**
 * @brief dap_chain_cs_dag_event_calc_size_excl_signs
 * @param a_event
 * @return
 */
static inline size_t dap_chain_cs_dag_event_calc_size_excl_signs(dap_chain_cs_dag_event_t *a_event, size_t a_event_size)
{
    if (a_event_size < sizeof(a_event->header))
        return 0;
    size_t l_hashes_size = a_event->header.hash_count*sizeof(dap_chain_hash_fast_t);
    if (a_event_size < l_hashes_size + sizeof(a_event->header))
        return 0;
    dap_chain_datum_t *l_datum = (dap_chain_datum_t*) (a_event->hashes_n_datum_n_signs + l_hashes_size);
    size_t l_ret = dap_chain_datum_size(l_datum) + l_hashes_size + sizeof(a_event->header);
    if (a_event_size < l_ret)
        return 0;
    return l_ret;
}

/**
 * @brief dap_chain_cs_dag_event_calc_size
 * @param a_event
 * @return
 */
static inline size_t dap_chain_cs_dag_event_calc_size(dap_chain_cs_dag_event_t *a_event, size_t a_limit_size)
{
    if (!a_event || !a_limit_size)
        return 0;
    size_t l_signs_offset = dap_chain_cs_dag_event_calc_size_excl_signs(a_event, a_limit_size);
    if (!l_signs_offset)
        return 0;
    byte_t *l_signs = (byte_t *)a_event + l_signs_offset;
    size_t l_signs_size = 0;
    for (uint16_t l_signs_passed = 0; l_signs_passed < a_event->header.signs_count; l_signs_passed++) {
        dap_sign_t *l_sign = (dap_sign_t *)(l_signs + l_signs_size);
        l_signs_size += dap_sign_get_size(l_sign);
        if (a_limit_size < l_signs_offset + l_signs_size)
            return 0;
    }
    return l_signs_offset + l_signs_size;
}

/**
 * @brief dap_chain_cs_dag_event_calc_hash
 * @details Important moment, it calculates hash of everything except signatures
 * @param a_event
 * @param a_event_hash
 */
static inline void dap_chain_cs_dag_event_calc_hash(dap_chain_cs_dag_event_t * a_event,size_t a_event_size, dap_chain_hash_fast_t * a_event_hash)
{
    dap_hash_fast(a_event, a_event_size, a_event_hash);
}

static inline size_t dap_chain_cs_dag_event_round_item_get_size(dap_chain_cs_dag_event_round_item_t * a_event_round_item){
    return sizeof(dap_chain_cs_dag_event_round_item_t)+a_event_round_item->data_size;
}

void dap_chain_cs_dag_event_broadcast(dap_chain_cs_dag_t *a_dag, dap_store_obj_t *a_obj, dap_global_db_instance_t *a_dbi);

bool dap_chain_cs_dag_event_gdb_set(dap_chain_cs_dag_t *a_dag, const char *a_event_hash_str, dap_chain_cs_dag_event_t *a_event,
                                    size_t a_event_size, dap_chain_cs_dag_event_round_item_t *a_round_item);

dap_chain_cs_dag_event_t *dap_chain_cs_dag_event_gdb_get(const char *a_event_hash_str, size_t *a_event_size,
                                                         const char *a_group, dap_chain_cs_dag_event_round_info_t * a_event_round_info);

