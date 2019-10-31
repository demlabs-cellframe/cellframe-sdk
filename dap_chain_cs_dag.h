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
#include "dap_chain.h"
#include "dap_chain_cs_dag_event.h"

typedef struct dap_chain_cs_dag dap_chain_cs_dag_t;

typedef void (*dap_chain_cs_dag_callback_t)(dap_chain_cs_dag_t *);
typedef int (*dap_chain_cs_dag_callback_event_t)(dap_chain_cs_dag_t *, dap_chain_cs_dag_event_t *);



typedef dap_chain_cs_dag_event_t * (*dap_chain_cs_dag_callback_event_create_t)(dap_chain_cs_dag_t *,
                                                                               dap_chain_datum_t *,
                                                                               dap_chain_hash_fast_t *,
                                                                               size_t);

typedef struct dap_chain_cs_dag
{
    dap_chain_t * chain;
    bool is_single_line;
    bool is_celled;
    bool is_add_directy;
    bool is_static_genesis_event;
    dap_chain_hash_fast_t static_genesis_event_hash;

    uint16_t datum_add_hashes_count;
    char * gdb_group_events_round_new;

    dap_chain_cs_dag_callback_t callback_delete;
    dap_chain_cs_dag_callback_event_create_t callback_cs_event_create;
    dap_chain_cs_dag_callback_event_t callback_cs_verify;

    void * _pvt;
    void * _inheritor;
} dap_chain_cs_dag_t;

#define DAP_CHAIN_CS_DAG(a) ( (dap_chain_cs_dag_t *) (a)->_inheritor)

int dap_chain_cs_dag_init(void);
void dap_chain_cs_dag_deinit(void);

int dap_chain_cs_dag_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg);
void dap_chain_cs_dag_delete(dap_chain_t * a_chain);

void dap_chain_cs_dag_proc_treshold(dap_chain_cs_dag_t * a_dag);
void dap_chain_cs_dag_proc_event_round_new(dap_chain_cs_dag_t *a_dag);

dap_chain_cs_dag_event_t* dap_chain_cs_dag_find_event_by_hash(dap_chain_cs_dag_t * a_dag,
                                                              dap_chain_hash_fast_t * a_hash);
