/*
 * Authors:
 * Frolov Daniil <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2020, All rights reserved.

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

#include "dap_chain_common.h"

#include "dap_common.h"
#include "dap_math_ops.h"
#include "dap_time.h"
#include "dap_list.h"
#include "dap_tsd.h"
#include <stdint.h>

typedef struct dap_chain_datum_anchor{
    uint16_t anchor_version;
    struct {
        dap_time_t ts_created;
        uint32_t data_size;
        uint32_t signs_size;
    } DAP_ALIGN_PACKED header;
    byte_t data_n_sign[];
} DAP_ALIGN_PACKED dap_chain_datum_anchor_t;

#include "dap_serialize.h"
#include <stddef.h>

/** Wire size of @ref dap_chain_datum_anchor_t fixed part before @c data_n_sign (packed). */
#define DAP_CHAIN_DATUM_ANCHOR_FIXED_WIRE_SIZE sizeof(dap_chain_datum_anchor_t)
_Static_assert(DAP_CHAIN_DATUM_ANCHOR_FIXED_WIRE_SIZE == offsetof(dap_chain_datum_anchor_t, data_n_sign),
               "dap_chain_datum_anchor_t fixed wire size");

#define DAP_CHAIN_DATUM_ANCHOR_FIXED_SERIALIZE_MAGIC 0xCF5FF002U

/**
 * @brief Naturally compact in-memory view of @ref dap_chain_datum_anchor_t fixed header (matches packed wire).
 */
typedef struct dap_chain_datum_anchor_fixed_mem {
    uint16_t anchor_version;
    uint8_t ts_created_wire[sizeof(dap_time_t)];
    uint8_t data_size_wire[sizeof(uint32_t)];
    uint8_t signs_size_wire[sizeof(uint32_t)];
} dap_chain_datum_anchor_fixed_mem_t;

_Static_assert(sizeof(dap_chain_datum_anchor_fixed_mem_t) == DAP_CHAIN_DATUM_ANCHOR_FIXED_WIRE_SIZE,
               "dap_chain_datum_anchor_fixed_mem_t wire size");

extern const dap_serialize_field_t g_dap_chain_datum_anchor_fixed_fields[];
extern const size_t g_dap_chain_datum_anchor_fixed_field_count;
extern const dap_serialize_schema_t g_dap_chain_datum_anchor_fixed_schema;

static inline int dap_chain_datum_anchor_fixed_pack(const dap_chain_datum_anchor_fixed_mem_t *a_mem, uint8_t *a_wire,
                                                      size_t a_wire_size)
{
    if (!a_mem || !a_wire || a_wire_size < DAP_CHAIN_DATUM_ANCHOR_FIXED_WIRE_SIZE)
        return -1;
    dap_serialize_result_t l_r =
        dap_serialize_to_buffer_raw(&g_dap_chain_datum_anchor_fixed_schema, a_mem, a_wire, a_wire_size, NULL);
    return l_r.error_code;
}

static inline int dap_chain_datum_anchor_fixed_unpack(const uint8_t *a_wire, size_t a_wire_size,
                                                      dap_chain_datum_anchor_fixed_mem_t *a_mem)
{
    if (!a_wire || !a_mem || a_wire_size < DAP_CHAIN_DATUM_ANCHOR_FIXED_WIRE_SIZE)
        return -1;
    dap_deserialize_result_t l_r =
        dap_deserialize_from_buffer_raw(&g_dap_chain_datum_anchor_fixed_schema, a_wire, a_wire_size, a_mem, NULL);
    return l_r.error_code;
}

// ANCHOR TSD types
#define DAP_CHAIN_DATUM_ANCHOR_TSD_TYPE_DECREE_HASH                0x0001


#ifdef __cplusplus
extern "C" {
#endif

DAP_STATIC_INLINE size_t dap_chain_datum_anchor_get_size(dap_chain_datum_anchor_t *a_datum_anchor)
{
    return sizeof(*a_datum_anchor) + a_datum_anchor->header.data_size + a_datum_anchor->header.signs_size;
}

int dap_chain_datum_anchor_get_hash_from_data(dap_chain_datum_anchor_t* a_anchor, dap_hash_sha3_256_t * a_out_hash);
void dap_chain_datum_anchor_certs_dump(dap_string_t * a_str_out, byte_t * a_signs,
                                       size_t a_certs_size, const char *a_hash_out_type);

void dap_chain_datum_anchor_certs_dump_json(dap_json_t *a_json_out, byte_t * a_signs, size_t a_certs_size, const char *a_hash_out_type, int a_version);

#ifdef __cplusplus
}
#endif
