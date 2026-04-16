/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
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
#include "dap_common.h"
#include "dap_serialize.h"
#include "dap_chain_common.h"

/**
  * @struct dap_chain_tx_token
  * @brief Token item
  */
typedef struct dap_chain_tx_in_ems {
    struct {
        dap_chain_tx_item_type_t type ;
        char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
        dap_chain_id_t token_emission_chain_id DAP_ALIGNED(4);
        dap_hash_sha3_256_t token_emission_hash;
    } DAP_PACKED header; /// Only header's hash is used for verification
} DAP_PACKED dap_chain_tx_in_ems_t;

/** Wire size of @ref dap_chain_tx_in_ems_t::header (packed). */
#define DAP_CHAIN_TX_IN_EMS_HDR_WIRE_SIZE sizeof(((dap_chain_tx_in_ems_t *)0)->header)
_Static_assert(sizeof(dap_chain_tx_in_ems_t) == 54u, "dap_chain_tx_in_ems_t wire size");
_Static_assert(DAP_CHAIN_TX_IN_EMS_HDR_WIRE_SIZE == 54, "dap_chain_tx_in_ems_t header wire layout");

#define DAP_CHAIN_TX_IN_EMS_SERIALIZE_MAGIC 0xCF5FEEDFU

/**
 * @brief Naturally aligned layout matching the on-wire @ref dap_chain_tx_in_ems_t::header field sequence.
 */
typedef struct dap_chain_tx_in_ems_mem {
    dap_chain_tx_item_type_t type;
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint8_t wire_pad_before_token_emission_chain_id[3];
    uint64_t token_emission_chain_id_le;
    uint8_t token_emission_hash[sizeof(dap_hash_sha3_256_t)];
} dap_chain_tx_in_ems_mem_t;

_Static_assert(sizeof(dap_chain_tx_in_ems_mem_t) == DAP_CHAIN_TX_IN_EMS_HDR_WIRE_SIZE, "dap_chain_tx_in_ems_mem_t wire size");

extern const dap_serialize_field_t g_dap_chain_tx_in_ems_fields[];
extern const size_t g_dap_chain_tx_in_ems_field_count;
extern const dap_serialize_schema_t g_dap_chain_tx_in_ems_schema;

static inline int dap_chain_tx_in_ems_pack(const dap_chain_tx_in_ems_mem_t *a_mem, uint8_t *a_wire, size_t a_wire_size)
{
    if (!a_mem || !a_wire || a_wire_size < DAP_CHAIN_TX_IN_EMS_HDR_WIRE_SIZE)
        return -1;
    dap_serialize_result_t l_r = dap_serialize_to_buffer_raw(
        &g_dap_chain_tx_in_ems_schema, a_mem, a_wire, a_wire_size, NULL);
    return l_r.error_code;
}

static inline int dap_chain_tx_in_ems_unpack(const uint8_t *a_wire, size_t a_wire_size, dap_chain_tx_in_ems_mem_t *a_mem)
{
    if (!a_wire || !a_mem || a_wire_size < DAP_CHAIN_TX_IN_EMS_HDR_WIRE_SIZE)
        return -1;
    dap_deserialize_result_t l_r = dap_deserialize_from_buffer_raw(
        &g_dap_chain_tx_in_ems_schema, a_wire, a_wire_size, a_mem, NULL);
    return l_r.error_code;
}


/**
  * @struct dap_chain_tx_token_ext
  * @brief External token swap
  */
typedef struct dap_chain_tx_in_ems_ext{
    struct {
        dap_chain_tx_item_type_t type;
        uint8_t version;
        char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
        uint8_t padding1; // Padding
        dap_chain_net_id_t ext_net_id;
        dap_chain_id_t ext_chain_id;
        dap_hash_sha3_256_t ext_tx_hash;
        uint16_t padding2;
        uint16_t ext_tx_out_idx; // Output index
    } header; /// Only header's hash is used for verification
} DAP_ALIGN_PACKED dap_chain_tx_in_ems_ext_t;
