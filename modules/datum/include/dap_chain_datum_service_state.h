/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
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

#include "dap_chain_datum.h"
#include "dap_serialize.h"
#include <stddef.h>

typedef struct dap_chain_datum_service_state {
    byte_t nonce[DAP_CHAIN_DATUM_NONCE_SIZE];
    dap_chain_srv_uid_t srv_uid;
    uint32_t states_count;
    uint64_t state_size;
    byte_t states[];
} DAP_ALIGN_PACKED dap_chain_datum_service_state_t;

/** Wire size of @ref dap_chain_datum_service_state_t fixed part before @c states (packed). */
#define DAP_CHAIN_DATUM_SERVICE_STATE_HDR_WIRE_SIZE sizeof(dap_chain_datum_service_state_t)
_Static_assert(DAP_CHAIN_DATUM_SERVICE_STATE_HDR_WIRE_SIZE == offsetof(dap_chain_datum_service_state_t, states),
               "dap_chain_datum_service_state_t fixed wire size");

#define DAP_CHAIN_DATUM_SERVICE_STATE_HDR_SERIALIZE_MAGIC 0xCF5FF004U

typedef struct dap_chain_datum_service_state_hdr_mem {
    uint8_t nonce[DAP_CHAIN_DATUM_NONCE_SIZE];
    uint8_t srv_uid_wire[sizeof(dap_chain_srv_uid_t)];
    uint8_t states_count_wire[sizeof(uint32_t)];
    uint8_t state_size_wire[sizeof(uint64_t)];
} dap_chain_datum_service_state_hdr_mem_t;

_Static_assert(sizeof(dap_chain_datum_service_state_hdr_mem_t) == DAP_CHAIN_DATUM_SERVICE_STATE_HDR_WIRE_SIZE,
               "dap_chain_datum_service_state_hdr_mem_t wire size");

extern const dap_serialize_field_t g_dap_chain_datum_service_state_hdr_fields[];
extern const size_t g_dap_chain_datum_service_state_hdr_field_count;
extern const dap_serialize_schema_t g_dap_chain_datum_service_state_hdr_schema;

static inline int dap_chain_datum_service_state_hdr_pack(const dap_chain_datum_service_state_hdr_mem_t *a_mem,
                                                         uint8_t *a_wire, size_t a_wire_size)
{
    if (!a_mem || !a_wire || a_wire_size < DAP_CHAIN_DATUM_SERVICE_STATE_HDR_WIRE_SIZE)
        return -1;
    dap_serialize_result_t l_r =
        dap_serialize_to_buffer_raw(&g_dap_chain_datum_service_state_hdr_schema, a_mem, a_wire, a_wire_size, NULL);
    return l_r.error_code;
}

static inline int dap_chain_datum_service_state_hdr_unpack(const uint8_t *a_wire, size_t a_wire_size,
                                                           dap_chain_datum_service_state_hdr_mem_t *a_mem)
{
    if (!a_wire || !a_mem || a_wire_size < DAP_CHAIN_DATUM_SERVICE_STATE_HDR_WIRE_SIZE)
        return -1;
    dap_deserialize_result_t l_r = dap_deserialize_from_buffer_raw(
        &g_dap_chain_datum_service_state_hdr_schema, a_wire, a_wire_size, a_mem, NULL);
    return l_r.error_code;
}
