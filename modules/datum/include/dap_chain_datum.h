/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
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
#include <stdint.h>

#include "dap_common.h"
#include "dap_serialize.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_token.h"

#define DAP_CHAIN_DATUM_VERSION 0x00

/// End section, means all the rest of the block is empty
#define DAP_CHAIN_DATUM_BLOCK_END           0x0000
/// Section with additional roots, for example transaction roots
#define DAP_CHAIN_DATUM_BLOCK_ROOTS         0x0001

/// Transaction header section
#define DAP_CHAIN_DATUM_TX                  0x0100

/// Network decree for governance
#define DAP_CHAIN_DATUM_DECREE              0x0200

/// Transaction request section
#define DAP_CHAIN_DATUM_TX_REQUEST          0x0300

/// Smart contract: DVM code section
#define DAP_CHAIN_DATUM_WASM_CODE           0x0900
/// Smart contract: DVM code section
#define DAP_CHAIN_DATUM_WASM_DATA           0x0901

/// Smart contract: EVM code section
#define DAP_CHAIN_DATUM_EVM_CODE            0x0910

/// Smart contract: EVM data section
#define DAP_CHAIN_DATUM_EVM_DATA            0x0911

/// CA with public key and self signed metadata
#define DAP_CHAIN_DATUM_CA                  0x0c00
#define DAP_CHAIN_DATUM_SIGNER              0x0c01

/// Token
/// Simple token decl
#define DAP_CHAIN_DATUM_TOKEN               0xf000
#define DAP_CHAIN_DATUM_TOKEN_EMISSION      0xf100
#define DAP_CHAIN_DATUM_TOKEN_DISMISSAL     0xf200

#define DAP_CHAIN_DATUM_ANCHOR              0x0a00

#define DAP_CHAIN_DATUM_SERVICE_STATE       0x8000

#define DAP_CHAIN_DATUM_CUSTOM              0xffff

#define DAP_DATUM_TYPE_STR(t, s)        \
    switch (t) {                        \
    case DAP_CHAIN_DATUM_TX:            \
        s = "DATUM_TX"; break;          \
    case DAP_CHAIN_DATUM_TX_REQUEST:    \
        s = "DATUM_WASM_CODE"; break;   \
    case DAP_CHAIN_DATUM_WASM_CODE:     \
        s = "DATUM_WASM_CODE"; break;   \
    case DAP_CHAIN_DATUM_WASM_DATA:     \
        s = "DATUM_WASM_DATA"; break;   \
    case DAP_CHAIN_DATUM_EVM_CODE:      \
        s = "DATUM_EVM_CODE"; break;    \
    case DAP_CHAIN_DATUM_EVM_DATA:      \
        s = "DATUM_EVM_DATA"; break;    \
    case DAP_CHAIN_DATUM_CA:            \
        s = "DATUM_CA"; break;          \
    case DAP_CHAIN_DATUM_SIGNER:        \
        s = "DATUM_SIGNER"; break;      \
    case DAP_CHAIN_DATUM_CUSTOM:        \
        s = "DATUM_CUSTOM"; break;      \
    case DAP_CHAIN_DATUM_TOKEN:    \
        s = "DATUM_TOKEN"; break;  \
    case DAP_CHAIN_DATUM_TOKEN_EMISSION:\
        s = "DATUM_TOKEN_EMISSION"; break;\
    case DAP_CHAIN_DATUM_DECREE:        \
        s = "DATUM_DECREE"; break;      \
    case DAP_CHAIN_DATUM_ANCHOR:        \
        s = "DATUM_ANCHOR"; break;      \
    default:                            \
        s = "DATUM_UNKNOWN"; break;     \
    }

#define DAP_CHAIN_DATUM_ID_SIZE 2

// Datum subchain type id
typedef union dap_chain_datum_typeid{
    uint8_t data[DAP_CHAIN_DATUM_ID_SIZE];
    uint16_t uint16;
} DAP_ALIGN_PACKED dap_chain_datum_typeid_t;
_Static_assert(sizeof(dap_chain_datum_typeid_t) == DAP_CHAIN_DATUM_ID_SIZE, "dap_chain_datum_typeid_t wire size");


/**
  * @struct dap_chain_block_section
  * @brief section inside the block
  */
typedef struct dap_chain_datum{
    struct{
        /// Datum version
        uint8_t version_id;
        /// Datum type id
        uint16_t type_id;
        /// Data section size
        uint32_t data_size;
        /// Create timestamp (GM time)
        uint64_t ts_create;
    } DAP_ALIGN_PACKED header;
    byte_t data[]; /// Stored datum body
} DAP_ALIGN_PACKED dap_chain_datum_t;

/** Wire size of @ref dap_chain_datum_t::header (packed, no tail padding). */
#define DAP_CHAIN_DATUM_HDR_WIRE_SIZE 15u
_Static_assert(DAP_CHAIN_DATUM_HDR_WIRE_SIZE == sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint64_t),
               "dap_chain_datum header wire layout");
_Static_assert(sizeof(((dap_chain_datum_t *)0)->header) == DAP_CHAIN_DATUM_HDR_WIRE_SIZE,
               "dap_chain_datum_t header must match wire layout");

#define DAP_CHAIN_DATUM_HDR_SERIALIZE_MAGIC 0xCF5FEED0U

/**
 * @brief Naturally aligned in-memory view of @ref dap_chain_datum_t::header (wire is packed).
 */
typedef struct dap_chain_datum_hdr_mem {
    uint8_t version_id;
    uint16_t type_id;
    uint32_t data_size;
    uint64_t ts_create;
} dap_chain_datum_hdr_mem_t;

extern const dap_serialize_field_t g_dap_chain_datum_hdr_fields[];
extern const size_t g_dap_chain_datum_hdr_field_count;
extern const dap_serialize_schema_t g_dap_chain_datum_hdr_schema;

static inline int dap_chain_datum_hdr_pack(const dap_chain_datum_hdr_mem_t *a_mem, uint8_t *a_wire, size_t a_wire_size)
{
    if (!a_mem || !a_wire || a_wire_size < DAP_CHAIN_DATUM_HDR_WIRE_SIZE)
        return -1;
    dap_serialize_result_t l_r = dap_serialize_to_buffer_raw(
        &g_dap_chain_datum_hdr_schema, a_mem, a_wire, a_wire_size, NULL);
    return l_r.error_code;
}

static inline int dap_chain_datum_hdr_unpack(const uint8_t *a_wire, size_t a_wire_size, dap_chain_datum_hdr_mem_t *a_mem)
{
    if (!a_wire || !a_mem || a_wire_size < DAP_CHAIN_DATUM_HDR_WIRE_SIZE)
        return -1;
    dap_deserialize_result_t l_r = dap_deserialize_from_buffer_raw(
        &g_dap_chain_datum_hdr_schema, a_wire, a_wire_size, a_mem, NULL);
    return l_r.error_code;
}

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief dap_chain_datum_size
 * @param a_datum
 * @return
 */
DAP_STATIC_INLINE uint64_t dap_chain_datum_size(const dap_chain_datum_t *a_datum)
{
    if (!a_datum)
        return 0;
    return (uint64_t)sizeof(a_datum->header) + a_datum->header.data_size;
}

DAP_STATIC_INLINE void dap_chain_datum_calc_hash(const dap_chain_datum_t *a_datum, dap_hash_sha3_256_t *a_out_hash)
{
    if (!a_datum || !a_out_hash)
        return;
    dap_hash_sha3_256(a_datum->header.data_size ? a_datum->data : (void *)a_datum,
                  a_datum->header.data_size ? a_datum->header.data_size : dap_chain_datum_size(a_datum),
                  a_out_hash);
}


// Forward declarations for dependency inversion
typedef struct dap_ledger dap_ledger_t;

typedef void (*dap_chain_datum_callback_dump_json_t)(dap_json_t *a_json_out, const void *a_data, size_t a_size, const char *a_hash_out_type, int a_version);
void dap_chain_datum_register_dump_decree_callback(dap_chain_datum_callback_dump_json_t a_callback);
void dap_chain_datum_register_dump_anchor_callback(dap_chain_datum_callback_dump_json_t a_callback); // anchor тоже может зависеть от политик

// NO MORE get_ledger callback - datum_dump_json implementation moved to ledger module to avoid circular dependency

dap_chain_datum_t * dap_chain_datum_create(uint16_t a_type_id, const void * a_data, size_t a_data_size);


DAP_STATIC_INLINE const char *dap_chain_datum_type_id_to_str(uint16_t a_type_id)
{
    const char * l_ret;
    DAP_DATUM_TYPE_STR(a_type_id,l_ret);
    return l_ret;
}

void dap_datum_token_dump_tsd_to_json(dap_json_t *json_obj_out, dap_chain_datum_token_t *a_token, size_t a_token_size, const char *a_hash_out_type);
bool dap_chain_datum_dump_tx_json(dap_json_t *a_json_arr_reply,
                             dap_chain_datum_tx_t *a_datum,
                             const char *a_ticker,
                             dap_json_t *json_obj_out,
                             const char *a_hash_out_type,
                             dap_hash_sha3_256_t *a_tx_hash,
                             dap_chain_net_id_t a_net_id,
                             int a_version);
dap_json_t *dap_chain_datum_to_json(dap_chain_datum_t *a_datum);
// NOTE: dap_chain_datum_dump_json перемещена в dap_chain_ledger_json.h (требует ledger для корректного дампа)

#ifdef __cplusplus
}
#endif
