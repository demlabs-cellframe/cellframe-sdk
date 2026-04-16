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

#include "dap_common.h"
#include "dap_chain_common.h"

/**
  * @struct dap_chain_datum_hashtree_roots_v1
  * @brief Hash tree roots for block, version 1
  */
typedef struct dap_chain_datum_hashtree_roots_v1{
    dap_hash_sha3_256_t main;
} DAP_ALIGN_PACKED dap_chain_block_roots_v1_t;
_Static_assert(sizeof(dap_chain_block_roots_v1_t) == 32u, "dap_chain_block_roots_v1_t wire size");

/**
  * @struct dap_chain_datum_hashtree_roots_v2
  * @brief Hash tree roots for block, version 2
  */
typedef struct dap_chain_datum_hashtree_roots_v2{
    dap_hash_sha3_256_t main;
    dap_hash_sha3_256_t txs;
} DAP_ALIGN_PACKED dap_chain_datum_hashtree_roots_v2_t;

typedef dap_chain_datum_hashtree_roots_v2_t dap_chain_datum_hashtree_roots_t;

#include "dap_serialize.h"
#include <stddef.h>

/** Wire image of @ref dap_chain_datum_hashtree_roots_v2_t (two SHA3-256 roots, packed). */
#define DAP_CHAIN_DATUM_HASHTREE_ROOTS_V2_WIRE_SIZE sizeof(dap_chain_datum_hashtree_roots_v2_t)
_Static_assert(DAP_CHAIN_DATUM_HASHTREE_ROOTS_V2_WIRE_SIZE == sizeof(dap_hash_sha3_256_t) * 2,
               "dap_chain_datum_hashtree_roots_v2_t wire size");

#define DAP_CHAIN_DATUM_HASHTREE_ROOTS_V2_SERIALIZE_MAGIC 0xCF5FF003U

typedef struct dap_chain_datum_hashtree_roots_v2_mem {
    uint8_t main[sizeof(dap_hash_sha3_256_t)];
    uint8_t txs[sizeof(dap_hash_sha3_256_t)];
} dap_chain_datum_hashtree_roots_v2_mem_t;

_Static_assert(sizeof(dap_chain_datum_hashtree_roots_v2_mem_t) == DAP_CHAIN_DATUM_HASHTREE_ROOTS_V2_WIRE_SIZE,
               "dap_chain_datum_hashtree_roots_v2_mem_t wire size");

extern const dap_serialize_field_t g_dap_chain_datum_hashtree_roots_v2_fields[];
extern const size_t g_dap_chain_datum_hashtree_roots_v2_field_count;
extern const dap_serialize_schema_t g_dap_chain_datum_hashtree_roots_v2_schema;

static inline int dap_chain_datum_hashtree_roots_v2_pack(const dap_chain_datum_hashtree_roots_v2_mem_t *a_mem,
                                                         uint8_t *a_wire, size_t a_wire_size)
{
    if (!a_mem || !a_wire || a_wire_size < DAP_CHAIN_DATUM_HASHTREE_ROOTS_V2_WIRE_SIZE)
        return -1;
    dap_serialize_result_t l_r =
        dap_serialize_to_buffer_raw(&g_dap_chain_datum_hashtree_roots_v2_schema, a_mem, a_wire, a_wire_size, NULL);
    return l_r.error_code;
}

static inline int dap_chain_datum_hashtree_roots_v2_unpack(const uint8_t *a_wire, size_t a_wire_size,
                                                           dap_chain_datum_hashtree_roots_v2_mem_t *a_mem)
{
    if (!a_wire || !a_mem || a_wire_size < DAP_CHAIN_DATUM_HASHTREE_ROOTS_V2_WIRE_SIZE)
        return -1;
    dap_deserialize_result_t l_r = dap_deserialize_from_buffer_raw(
        &g_dap_chain_datum_hashtree_roots_v2_schema, a_wire, a_wire_size, a_mem, NULL);
    return l_r.error_code;
}

