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

// ANCHOR TSD types
#define DAP_CHAIN_DATUM_ANCHOR_TSD_TYPE_DECREE_HASH                0x0001

DAP_STATIC_INLINE size_t dap_chain_datum_anchor_get_size(dap_chain_datum_anchor_t *a_datum_anchor)
{
    return sizeof(*a_datum_anchor) + a_datum_anchor->header.data_size + a_datum_anchor->header.signs_size;
}

int dap_chain_datum_anchor_get_hash_from_data(dap_chain_datum_anchor_t* a_anchor, dap_hash_fast_t * l_out_hash);
void dap_chain_datum_anchor_certs_dump(dap_string_t * a_str_out, byte_t * a_signs,
                                       size_t a_certs_size, const char *a_hash_out_type);

json_object *dap_chain_datum_anchor_to_json(dap_chain_datum_anchor_t *a_anchor);
