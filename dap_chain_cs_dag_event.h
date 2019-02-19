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

#include "dap_chain_common.h"
#include "dap_chain_datum.h"


typedef struct dap_chain_cs_dag dap_chain_cs_dag_t;

typedef struct dap_chain_cs_dag_event {
    struct {
        uint8_t version;
        uint64_t timestamp;
        uint16_t hash_count; // Number of hashes
        uint16_t signs_count; // Number of signs nested with event
    } header;
    uint8_t hashes_n_signs_n_datum[]; // Hashes, signes and datum
} dap_chain_cs_dag_event_t;

typedef int (*dap_chain_cs_dag_event_callback_ptr_t)(dap_chain_cs_dag_t *, dap_chain_cs_dag_event_t *);

dap_chain_cs_dag_event_t * dap_chain_cs_dag_event_new(dap_chain_cs_dag_t * a_dag, dap_chain_datum_t * a_datum,
                                                dap_enc_key_t * a_key,
                                                dap_chain_hash_fast_t * a_hashes, size_t a_hashes_count);
void dap_chain_cs_dag_event_delete(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_event);

int dap_chain_cs_dag_event_verify(dap_chain_cs_dag_event_t * a_event);
dap_chain_datum_t* dap_chain_cs_dag_event_get_datum(dap_chain_cs_dag_event_t * a_event);

