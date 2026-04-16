/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd   https://demlabs.net
 * Copyright  (c) 2017
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "dap_common.h"
#include "dap_time.h"
#include "dap_hash.h"
#include "dap_chain.h"
#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_serialize.h"

#define DAP_CHAIN_BLOCK_SIGNATURE 0xDA05BF8E
#define DAP_CHAIN_BLOCK_ID_SIZE 4

#define DAP_CHAIN_CANDIDATE_SIGNS_MAX_SIZE  (256 * 1024)
#if (DAP_CHAIN_CANDIDATE_SIGNS_MAX_SIZE >= DAP_CHAIN_ATOM_MAX_SIZE)
#error DAP_CHAIN_ATOM_MAX_SIZE should be greater than DAP_CHAIN_CANDIDATE_SIGNS_MAX_SIZE
#endif
#define DAP_CHAIN_CANDIDATE_MAX_SIZE (DAP_CHAIN_ATOM_MAX_SIZE - DAP_CHAIN_CANDIDATE_SIGNS_MAX_SIZE)

typedef union dap_chain_block_typeid{
    uint8_t data[DAP_CHAIN_BLOCK_ID_SIZE];
} DAP_ALIGN_PACKED dap_chain_block_typeid_t;

/**
  * @struct dap_chain_block_hdr
  * @brief Block header
  */
typedef struct dap_chain_block_hdr{
    uint32_t signature; /// @param signature @brief Magic number, always equels to DAP_CHAIN_BLOCK_SIGNATURE
    int32_t version; /// @param version @brief block version (be carefull, signed value, as Bitcoin has)
    dap_chain_cell_id_t cell_id; /// Cell id
    dap_chain_id_t chain_id; /// Chain id
    dap_time_t ts_created; /// @param timestamp @brief Block create time timestamp
    uint16_t meta_count; // Meta values number
    uint16_t datum_count; // Datums's count
    dap_hash_sha3_256_t merkle;
    uint32_t meta_n_datum_n_signs_size; // Meta&Datum&Signs section size
} DAP_ALIGN_PACKED dap_chain_block_hdr_t;

/** Wire size of @ref dap_chain_block_hdr_t (packed). */
#define DAP_CHAIN_BLOCK_HDR_WIRE_SIZE sizeof(dap_chain_block_hdr_t)

/**
 * @brief Naturally aligned in-memory view of @ref dap_chain_block_hdr_t (matches wire layout).
 */
typedef struct dap_chain_block_hdr_mem {
    uint32_t signature;
    int32_t version;
    uint8_t cell_id[DAP_CHAIN_SHARD_ID_SIZE];
    uint8_t chain_id[DAP_CHAIN_ID_SIZE];
    uint8_t ts_created_wire[sizeof(dap_time_t)];
    uint16_t meta_count;
    uint16_t datum_count;
    uint8_t merkle[DAP_CHAIN_HASH_SLOW_SIZE];
    uint32_t meta_n_datum_n_signs_size;
} dap_chain_block_hdr_mem_t;

_Static_assert(sizeof(dap_chain_block_hdr_mem_t) == DAP_CHAIN_BLOCK_HDR_WIRE_SIZE,
               "dap_chain_block_hdr_mem_t matches block header wire layout");
_Static_assert(sizeof(dap_chain_block_hdr_mem_t) == sizeof(dap_chain_block_hdr_t),
               "dap_chain_block_hdr_mem_t matches packed block hdr");

extern const dap_serialize_field_t g_dap_chain_block_hdr_fields[];
extern const dap_serialize_schema_t g_dap_chain_block_hdr_schema;
#define DAP_CHAIN_BLOCK_HDR_SERIALIZE_MAGIC 0xCF5FF015U

static inline int dap_chain_block_hdr_pack(const dap_chain_block_hdr_mem_t *a_mem, uint8_t *a_wire, size_t a_wire_size)
{
    if (!a_mem || !a_wire || a_wire_size < DAP_CHAIN_BLOCK_HDR_WIRE_SIZE)
        return -1;
    dap_serialize_result_t l_r =
        dap_serialize_to_buffer_raw(&g_dap_chain_block_hdr_schema, a_mem, a_wire, a_wire_size, NULL);
    return l_r.error_code;
}

static inline int dap_chain_block_hdr_unpack(const uint8_t *a_wire, size_t a_wire_size, dap_chain_block_hdr_mem_t *a_mem)
{
    if (!a_wire || !a_mem || a_wire_size < DAP_CHAIN_BLOCK_HDR_WIRE_SIZE)
        return -1;
    dap_deserialize_result_t l_r =
        dap_deserialize_from_buffer_raw(&g_dap_chain_block_hdr_schema, a_wire, a_wire_size, a_mem, NULL);
    return l_r.error_code;
}

// Metadata item
typedef struct dap_chain_block_meta{
    struct {
        uint8_t type; /// Meta type
        uint16_t data_size;   /// Data size trailing the section
    } DAP_ALIGN_PACKED hdr;
    byte_t data[]; /// Section's data
} DAP_ALIGN_PACKED dap_chain_block_meta_t;

// Block metadata types

#define DAP_CHAIN_BLOCK_META_GENESIS            0x01
#define DAP_CHAIN_BLOCK_META_GENERATION         0x02
#define DAP_CHAIN_BLOCK_META_PREV               0x10
#define DAP_CHAIN_BLOCK_META_ANCHOR             0x11
#define DAP_CHAIN_BLOCK_META_LINK               0x12
#define DAP_CHAIN_BLOCK_META_NONCE              0x20
#define DAP_CHAIN_BLOCK_META_NONCE2             0x21
#define DAP_CHAIN_BLOCK_META_MERKLE             0x30
#define DAP_CHAIN_BLOCK_META_EMERGENCY          0x80
#define DAP_CHAIN_BLOCK_META_SYNC_ATTEMPT       0x81
#define DAP_CHAIN_BLOCK_META_ROUND_ATTEMPT      0x82
#define DAP_CHAIN_BLOCK_META_EXCLUDED_KEYS      0x83
#define DAP_CHAIN_BLOCK_META_EVM_DATA           0x84
#define DAP_CHAIN_BLOCK_META_BLOCKGEN           0x85

/**
 * @struct dap_chain_block
 * @brief The dap_chain_block struct
 */
typedef struct  dap_chain_block{
    dap_chain_block_hdr_t hdr;
    uint8_t meta_n_datum_n_sign[]; // Here are: metadata, datum sections and verificator signatures
} DAP_ALIGN_PACKED dap_chain_block_t;

DAP_STATIC_INLINE size_t dap_chain_block_get_size(dap_chain_block_t *a_block) { return sizeof(a_block->hdr) + a_block->hdr.meta_n_datum_n_signs_size; }

// Init module
int dap_chain_block_init();
// Deinit module
void dap_chain_block_deinit();

// Create new block
dap_chain_block_t *dap_chain_block_new(dap_hash_sha3_256_t *a_prev_block, size_t *a_block_size);

// Add metadata in block
size_t dap_chain_block_meta_add(dap_chain_block_t ** a_block_ptr, size_t a_block_size, uint8_t a_meta_type, const void * a_data, size_t a_data_size);
uint8_t *dap_chain_block_meta_get(const dap_chain_block_t *a_block, size_t a_block_size, uint8_t a_meta_type);
int dap_chain_block_meta_extract(dap_chain_block_t *a_block, size_t a_block_size,
                                 dap_hash_sha3_256_t *a_block_prev_hash,
                                 dap_hash_sha3_256_t *a_block_anchor_hash,
                                 dap_hash_sha3_256_t *a_merkle,
                                 dap_hash_sha3_256_t **a_block_links,
                                 size_t *a_block_links_count,
                                 bool *a_is_genesis,
                                 uint64_t *a_nonce,
                                 uint64_t *a_nonce2,
                                 uint16_t *a_generation,
                                 bool *a_blockgen);
// Add datum in block
size_t dap_chain_block_datum_add(dap_chain_block_t ** a_block_ptr, size_t a_block_size, dap_chain_datum_t * a_datum, size_t a_datum_size);
size_t dap_chain_block_datum_del_by_hash(dap_chain_block_t ** a_block_ptr, size_t a_block_size, dap_hash_sha3_256_t* a_datum_hash);

// Add sign in block
size_t dap_chain_block_sign_add(dap_chain_block_t ** a_block_ptr, size_t a_block_size, dap_enc_key_t *a_key);
dap_sign_t *dap_chain_block_sign_get (const dap_chain_block_t *a_block_ptr, size_t a_block_size, uint16_t a_sign_num );
bool dap_chain_block_sign_match_pkey(const dap_chain_block_t *a_block, size_t a_block_size, dap_pkey_t *a_sign_pkey);
size_t dap_chain_block_get_signs_count(const dap_chain_block_t *a_block, size_t a_block_size);
size_t dap_chain_block_get_sign_offset(const dap_chain_block_t *a_block, size_t a_block_size);

dap_hash_sha3_256_t *dap_chain_block_get_prev_hash(const dap_chain_block_t *a_block, size_t a_block_size);

// Create and return datums list
dap_chain_datum_t** dap_chain_block_get_datums(const dap_chain_block_t * a_block, size_t a_block_size,size_t * a_datums_count );
