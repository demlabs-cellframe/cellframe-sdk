/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net      https://gitlab/demlabs
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
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

#include "dap_enc_key.h"
#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_sign.h"
#include "dap_hash.h"

typedef struct dap_chain_cs_dag dap_chain_cs_dag_t;

typedef struct dap_chain_class_dag_event_hdr {
        uint8_t version;
        uint64_t timestamp;
        uint16_t hash_count; // Number of hashes
        uint16_t signs_count; // Number of signs nested with event
} dap_chain_class_dag_event_hdr_t;

typedef struct dap_chain_cs_dag_event {
    dap_chain_class_dag_event_hdr_t header;
    uint8_t hashes_n_signs_n_datum[]; // Hashes, signes and datum
} dap_chain_cs_dag_event_t;


dap_chain_cs_dag_event_t * dap_chain_cs_dag_event_new(dap_chain_cs_dag_t * a_dag, dap_chain_datum_t * a_datum,
                                                dap_enc_key_t * a_key,
                                                dap_chain_hash_fast_t * a_hashes, size_t a_hashes_count);

void dap_chain_cs_dag_event_delete(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_event);

dap_chain_datum_t* dap_chain_cs_dag_event_get_datum(dap_chain_cs_dag_event_t * a_event);
dap_chain_sign_t * dap_chain_cs_dag_event_get_sign( dap_chain_cs_dag_event_t * a_event, uint16_t a_sign_number);

/**
 * @brief dap_chain_cs_dag_event_calc_size
 * @param a_event
 * @return
 */
static inline size_t dap_chain_cs_dag_event_calc_size(dap_chain_cs_dag_event_t * a_event)
{
    size_t l_hashes_size = a_event->header.hash_count*sizeof(dap_chain_hash_fast_t);
    uint8_t * l_signs = a_event->hashes_n_signs_n_datum
            +l_hashes_size;
    uint16_t l_signs_offset = 0;
    uint16_t l_signs_passed;
    for ( l_signs_passed=0;  l_signs_passed < a_event->header.signs_count; l_signs_passed++){
        dap_chain_sign_t * l_sign = (dap_chain_sign_t *) l_signs+l_signs_offset;
        l_signs_offset+=l_sign->header.sign_pkey_size+l_sign->header.sign_size+sizeof(l_sign->header);
    }
    dap_chain_datum_t * l_datum = (dap_chain_datum_t*)  l_signs+l_signs_offset;
    return sizeof( a_event->header ) + l_hashes_size +l_signs_offset +l_datum->header.data_size;
}

/**
 * @brief dap_chain_cs_dag_event_calc_hash
 * @param a_event
 * @param a_event_hash
 */
static inline void dap_chain_cs_dag_event_calc_hash(dap_chain_cs_dag_event_t * a_event,dap_chain_hash_fast_t * a_event_hash)
{
    dap_hash_fast(a_event, dap_chain_cs_dag_event_calc_size (a_event) , a_event_hash);
}
