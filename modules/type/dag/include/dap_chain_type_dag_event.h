/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net      https://gitlab/demlabs
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
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

#include <stddef.h>
#include <stdint.h>

#include "dap_chain_net.h"
#include "dap_enc_key.h"
#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_sign.h"
#include "dap_hash.h"
#include "dap_serialize.h"

typedef struct dap_chain_type_dag dap_chain_type_dag_t;

typedef struct dap_chain_class_dag_event_hdr {
        uint16_t version;
        uint64_t round_id;
        dap_time_t ts_created;
        dap_chain_id_t chain_id;
        dap_chain_cell_id_t cell_id; // Cell id if celled dag
        uint16_t hash_count; // Number of hashes
        uint16_t signs_count; // Number of signs nested with event
} DAP_ALIGN_PACKED dap_chain_class_dag_event_hdr_t;

/** Wire size of @ref dap_chain_class_dag_event_hdr_t (packed) / fixed part of @ref dap_chain_type_dag_event_t. */
#define DAP_CHAIN_CLASS_DAG_EVENT_HDR_WIRE_SIZE sizeof(dap_chain_class_dag_event_hdr_t)

/**
 * @brief Naturally compact in-memory view of @ref dap_chain_class_dag_event_hdr_t (matches packed wire).
 */
typedef struct dap_chain_class_dag_event_hdr_mem {
    uint16_t version;
    uint8_t round_id_wire[sizeof(uint64_t)];
    uint8_t ts_created_wire[sizeof(dap_time_t)];
    uint8_t chain_id[DAP_CHAIN_ID_SIZE];
    uint8_t cell_id[DAP_CHAIN_SHARD_ID_SIZE];
    uint16_t hash_count;
    uint16_t signs_count;
} dap_chain_class_dag_event_hdr_mem_t;

extern const dap_serialize_field_t g_dap_chain_class_dag_event_hdr_fields[];
extern const dap_serialize_schema_t g_dap_chain_class_dag_event_hdr_schema;
#define DAP_CHAIN_CLASS_DAG_EVENT_HDR_SERIALIZE_MAGIC 0xCF5FF014U

static inline int dap_chain_class_dag_event_hdr_pack(const dap_chain_class_dag_event_hdr_mem_t *a_mem, uint8_t *a_wire,
                                                     size_t a_wire_size)
{
    if (!a_mem || !a_wire || a_wire_size < DAP_CHAIN_CLASS_DAG_EVENT_HDR_WIRE_SIZE)
        return -1;
    dap_serialize_result_t l_r =
        dap_serialize_to_buffer_raw(&g_dap_chain_class_dag_event_hdr_schema, a_mem, a_wire, a_wire_size, NULL);
    return l_r.error_code;
}

static inline int dap_chain_class_dag_event_hdr_unpack(const uint8_t *a_wire, size_t a_wire_size,
                                                       dap_chain_class_dag_event_hdr_mem_t *a_mem)
{
    if (!a_wire || !a_mem || a_wire_size < DAP_CHAIN_CLASS_DAG_EVENT_HDR_WIRE_SIZE)
        return -1;
    dap_deserialize_result_t l_r =
        dap_deserialize_from_buffer_raw(&g_dap_chain_class_dag_event_hdr_schema, a_wire, a_wire_size, a_mem, NULL);
    return l_r.error_code;
}

typedef struct dap_chain_type_dag_event {
    dap_chain_class_dag_event_hdr_t header;
    uint8_t hashes_n_datum_n_signs[]; // Hashes, signes and datum
} DAP_ALIGN_PACKED dap_chain_type_dag_event_t;

typedef struct dap_chain_type_dag_event_round_info {
    uint16_t reject_count;
    dap_nanotime_t ts_update;
    dap_hash_sha3_256_t datum_hash; // for doubles finding
} DAP_ALIGN_PACKED dap_chain_type_dag_event_round_info_t;

typedef struct dap_chain_type_dag_event_round_item {
    dap_chain_type_dag_event_round_info_t round_info;// cfg;
    uint32_t event_size;
    uint32_t data_size;
    uint8_t event_n_signs[]; // event // dap_chain_type_dag_event_t
} DAP_ALIGN_PACKED dap_chain_type_dag_event_round_item_t;

dap_chain_type_dag_event_t *dap_chain_type_dag_event_new(dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id, dap_chain_datum_t *a_datum,
                                                     dap_enc_key_t *a_key, dap_hash_sha3_256_t *a_hashes, size_t a_hashes_count, size_t *a_event_size);

/**
 * @brief dap_chain_type_dag_event_get_datum
 * @param a_event
 * @return
 */
static inline dap_chain_datum_t* dap_chain_type_dag_event_get_datum(dap_chain_type_dag_event_t * a_event,size_t a_event_size)
{
    return  a_event->header.hash_count * sizeof(dap_hash_sha3_256_t) <= a_event_size
                ? (dap_chain_datum_t*)(a_event->hashes_n_datum_n_signs + a_event->header.hash_count * sizeof(dap_hash_sha3_256_t))
                : NULL;
}

static inline size_t dap_chain_type_dag_event_get_datum_size_maximum(dap_chain_type_dag_event_t * a_event,size_t a_event_size)
{
    return  a_event->header.hash_count * sizeof(dap_hash_sha3_256_t) <= a_event_size
                ? a_event_size - a_event->header.hash_count * sizeof(dap_hash_sha3_256_t)
                : 0;
}

size_t dap_chain_type_dag_event_sign_add(dap_chain_type_dag_event_t **a_event_ptr, size_t a_event_size, dap_enc_key_t *a_key);
size_t dap_chain_type_dag_event_round_sign_add(dap_chain_type_dag_event_round_item_t **a_round_item_ptr, size_t a_round_item_size,
                                             dap_enc_key_t *a_key);
bool dap_chain_type_dag_event_sign_exists(dap_chain_type_dag_event_t *a_event, size_t a_event_size, dap_enc_key_t * a_key);
bool dap_chain_type_dag_event_round_sign_exists(dap_chain_type_dag_event_round_item_t *a_round_item, dap_enc_key_t * a_key);
dap_sign_t * dap_chain_type_dag_event_get_sign( dap_chain_type_dag_event_t * a_event, size_t a_event_size, uint16_t a_sign_number);

uint64_t dap_chain_type_dag_event_calc_size_excl_signs(dap_chain_type_dag_event_t *a_event, uint64_t a_limit_size);
uint64_t dap_chain_type_dag_event_calc_size(dap_chain_type_dag_event_t *a_event, uint64_t a_limit_size);


/**
 * @brief dap_chain_type_dag_event_calc_hash
 * @details Important moment, it calculates hash of everything except signatures
 * @param a_event
 * @param a_event_hash
 */
static inline void dap_chain_type_dag_event_calc_hash(dap_chain_type_dag_event_t * a_event,size_t a_event_size, dap_hash_sha3_256_t * a_event_hash)
{
    dap_hash_sha3_256(a_event, a_event_size, a_event_hash);
}

static inline size_t dap_chain_type_dag_event_round_item_get_size(dap_chain_type_dag_event_round_item_t * a_event_round_item){
    return sizeof(dap_chain_type_dag_event_round_item_t)+a_event_round_item->data_size;
}

void dap_chain_type_dag_event_broadcast(dap_chain_type_dag_t *a_dag, dap_global_db_store_obj_t *a_obj, dap_global_db_instance_t *a_dbi);

bool dap_chain_type_dag_event_gdb_set(dap_chain_type_dag_t *a_dag, const char *a_event_hash_str, dap_chain_type_dag_event_t *a_event,
                                    size_t a_event_size, dap_chain_type_dag_event_round_item_t *a_round_item);

dap_chain_type_dag_event_t *dap_chain_type_dag_event_gdb_get(const char *a_event_hash_str, size_t *a_event_size,
                                                         const char *a_group, dap_chain_type_dag_event_round_info_t * a_event_round_info);

