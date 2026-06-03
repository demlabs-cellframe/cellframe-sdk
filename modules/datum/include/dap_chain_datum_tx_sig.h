/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
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

#include <stdint.h>
#include "dap_common.h"
#include "dap_serialize.h"
#include "dap_chain_common.h"

/**
  * @struct dap_chain_tx_sig
  * @brief Section with set of transaction signatures
  */
typedef struct dap_chain_tx_sig{
    struct {
        dap_chain_tx_item_type_t type; /// @param    type            @brief Transaction item type
        uint8_t version DAP_ALIGNED(1);
        uint32_t sig_size DAP_ALIGNED(4); /// Signature size
    } DAP_PACKED header; /// Only header's hash is used for verification
    uint8_t sig[]; /// @param sig @brief raw signature data
} DAP_PACKED dap_chain_tx_sig_t;

#define DAP_CHAIN_TX_SIG_HDR_WIRE_SIZE sizeof(((dap_chain_tx_sig_t *)0)->header)
_Static_assert(DAP_CHAIN_TX_SIG_HDR_WIRE_SIZE == 8, "dap_chain_tx_sig_t header wire layout");

#define DAP_CHAIN_TX_SIG_HDR_SERIALIZE_MAGIC 0xCF5FEED8U

typedef struct dap_chain_tx_sig_hdr_mem {
    dap_chain_tx_item_type_t type;
    uint8_t version;
    uint8_t wire_pad_before_sig_size[2];
    uint32_t sig_size;
} dap_chain_tx_sig_hdr_mem_t;

extern const dap_serialize_field_t g_dap_chain_tx_sig_hdr_fields[];
extern const size_t g_dap_chain_tx_sig_hdr_field_count;
extern const dap_serialize_schema_t g_dap_chain_tx_sig_hdr_schema;

static inline int dap_chain_tx_sig_hdr_pack(const dap_chain_tx_sig_hdr_mem_t *a_mem, uint8_t *a_wire, size_t a_wire_size)
{
    if (!a_mem || !a_wire || a_wire_size < DAP_CHAIN_TX_SIG_HDR_WIRE_SIZE)
        return -1;
    dap_serialize_result_t l_r = dap_serialize_to_buffer_raw(
        &g_dap_chain_tx_sig_hdr_schema, a_mem, a_wire, a_wire_size, NULL);
    return l_r.error_code;
}

static inline int dap_chain_tx_sig_hdr_unpack(const uint8_t *a_wire, size_t a_wire_size, dap_chain_tx_sig_hdr_mem_t *a_mem)
{
    if (!a_wire || !a_mem || a_wire_size < DAP_CHAIN_TX_SIG_HDR_WIRE_SIZE)
        return -1;
    dap_deserialize_result_t l_r = dap_deserialize_from_buffer_raw(
        &g_dap_chain_tx_sig_hdr_schema, a_wire, a_wire_size, a_mem, NULL);
    return l_r.error_code;
}
