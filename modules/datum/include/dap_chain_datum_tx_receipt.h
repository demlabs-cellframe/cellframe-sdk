/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include <stdint.h>
#include <stddef.h>
#include "dap_common.h"
#include "dap_serialize.h"
#include "dap_chain_common.h"


typedef struct dap_chain_receipt_info_old {
    dap_chain_srv_uid_t srv_uid; // Service UID
#if DAP_CHAIN_NET_SRV_UID_SIZE == 8
    uint64_t addition;
#endif
    dap_chain_net_srv_price_unit_uid_t units_type;
    byte_t version;
    byte_t padding[3];
    uint64_t units; // Unit of service (seconds, megabytes, etc.) Only for SERV_CLASS_PERMANENT
    uint256_t value_datoshi; // Receipt value
} DAP_ALIGN_PACKED dap_chain_receipt_info_old_t;

typedef struct dap_chain_receipt_info {
    dap_chain_srv_uid_t srv_uid; // Service UID
    uint64_t addition;
    dap_chain_net_srv_price_unit_uid_t units_type;
    byte_t version;
    byte_t padding[3];
    uint64_t units; // Unit of service (seconds, megabytes, etc.) Only for SERV_CLASS_PERMANENT
    uint256_t value_datoshi; // Receipt value
    dap_hash_sha3_256_t prev_tx_cond_hash;
} DAP_ALIGN_PACKED dap_chain_receipt_info_t;

/**
 * @struct dap_chain_tx_receipt_old
 * @brief Transaction item receipt
 */
typedef struct dap_chain_datum_tx_receipt_old {
    dap_chain_tx_item_type_t type; // Transaction item type
    dap_chain_receipt_info_old_t receipt_info; // Receipt itself
    uint64_t size;
    uint64_t exts_size;
    byte_t exts_n_signs[]; // Signatures, first from provider, second from client
} DAP_ALIGN_PACKED dap_chain_datum_tx_receipt_old_t;


/**
 * @struct dap_chain_tx_out
 * @brief Transaction item out_cond
 */
typedef struct dap_chain_datum_tx_receipt {
    dap_chain_tx_item_type_t type; // Transaction item type
    dap_chain_receipt_info_t receipt_info; // Receipt itself
    uint64_t size;
    uint64_t exts_size;
    byte_t exts_n_signs[]; // Signatures, first from provider, second from client
} DAP_ALIGN_PACKED dap_chain_datum_tx_receipt_t;

/** Wire size of fixed prefix of @ref dap_chain_datum_tx_receipt_t (before FAM @c exts_n_signs). */
#define DAP_CHAIN_DATUM_TX_RECEIPT_HDR_WIRE_SIZE offsetof(dap_chain_datum_tx_receipt_t, exts_n_signs)
_Static_assert(DAP_CHAIN_DATUM_TX_RECEIPT_HDR_WIRE_SIZE == 113, "dap_chain_datum_tx_receipt_t fixed-prefix wire layout");

#define DAP_CHAIN_DATUM_TX_RECEIPT_HDR_SERIALIZE_MAGIC 0xCF5FEEDAU

/**
 * @brief Naturally aligned layout matching the on-wire fixed prefix of @ref dap_chain_datum_tx_receipt_t.
 */
typedef struct dap_chain_datum_tx_receipt_hdr_mem {
    dap_chain_tx_item_type_t type;
    uint64_t srv_uid_le;
    uint64_t addition;
    uint32_t units_type;
    uint8_t version;
    uint8_t receipt_info_padding[3];
    uint64_t units;
    uint8_t value_datoshi[sizeof(uint256_t)];
    uint8_t prev_tx_cond_hash[sizeof(dap_hash_sha3_256_t)];
    uint64_t size;
    uint64_t exts_size;
} dap_chain_datum_tx_receipt_hdr_mem_t;

extern const dap_serialize_field_t g_dap_chain_datum_tx_receipt_hdr_fields[];
extern const size_t g_dap_chain_datum_tx_receipt_hdr_field_count;
extern const dap_serialize_schema_t g_dap_chain_datum_tx_receipt_hdr_schema;

static inline int dap_chain_datum_tx_receipt_hdr_pack(const dap_chain_datum_tx_receipt_hdr_mem_t *a_mem, uint8_t *a_wire,
                                                      size_t a_wire_size)
{
    if (!a_mem || !a_wire || a_wire_size < DAP_CHAIN_DATUM_TX_RECEIPT_HDR_WIRE_SIZE)
        return -1;
    dap_serialize_result_t l_r = dap_serialize_to_buffer_raw(
        &g_dap_chain_datum_tx_receipt_hdr_schema, a_mem, a_wire, a_wire_size, NULL);
    return l_r.error_code;
}

static inline int dap_chain_datum_tx_receipt_hdr_unpack(const uint8_t *a_wire, size_t a_wire_size,
                                                        dap_chain_datum_tx_receipt_hdr_mem_t *a_mem)
{
    if (!a_wire || !a_mem || a_wire_size < DAP_CHAIN_DATUM_TX_RECEIPT_HDR_WIRE_SIZE)
        return -1;
    dap_deserialize_result_t l_r = dap_deserialize_from_buffer_raw(
        &g_dap_chain_datum_tx_receipt_hdr_schema, a_wire, a_wire_size, a_mem, NULL);
    return l_r.error_code;
}


#ifdef __cplusplus
extern "C" {
#endif

dap_chain_datum_tx_receipt_t * dap_chain_datum_tx_receipt_create(dap_chain_srv_uid_t srv_uid,
                                                                  dap_chain_net_srv_price_unit_uid_t units_type,
                                                                    uint64_t units, uint256_t value_datoshi, const void * a_ext, size_t a_ext_size, dap_hash_sha3_256_t *a_prev_tx_hash);

dap_chain_datum_tx_receipt_t *dap_chain_datum_tx_receipt_sign_add(dap_chain_datum_tx_receipt_t *a_receipt, dap_enc_key_t *a_key);
dap_sign_t* dap_chain_datum_tx_receipt_sign_get(dap_chain_datum_tx_receipt_t *a_receipt, size_t a_receipt_size , uint16_t sign_position);
uint32_t    dap_chain_datum_tx_receipt_utype_get(dap_chain_datum_tx_receipt_t *a_receipt);
uint64_t    dap_chain_datum_tx_receipt_srv_uid_get(dap_chain_datum_tx_receipt_t *a_receipt);
uint64_t    dap_chain_datum_tx_receipt_units_get(dap_chain_datum_tx_receipt_t *a_receipt);
uint256_t   dap_chain_datum_tx_receipt_value_get(dap_chain_datum_tx_receipt_t *a_receipt);
uint16_t dap_chain_datum_tx_receipt_signs_count(dap_chain_datum_tx_receipt_t *a_receipt);
int dap_chain_datum_tx_receipt_check_size(dap_chain_datum_tx_receipt_t *a_receipt, size_t a_control_size);

#ifdef __cplusplus
}
#endif
