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
#include "uthash.h"
#include "dap_chain.h"
#include "dap_chain_cs_dag_event.h"

typedef struct dap_chain_cs_dag dap_chain_cs_dag_t;

typedef void (*dap_chain_cs_dag_callback_t)(dap_chain_cs_dag_t *);
typedef int (*dap_chain_cs_dag_callback_event_t)(dap_chain_cs_dag_t *, dap_chain_cs_dag_event_t *,size_t);

typedef dap_chain_cs_dag_event_t * (*dap_chain_cs_dag_callback_event_create_t)(dap_chain_cs_dag_t *,
                                                                               dap_chain_datum_t *,
                                                                               dap_chain_hash_fast_t *,
                                                                               size_t, size_t*);

typedef void (*dap_chain_cs_dag_callback_get_round_info_t)(dap_chain_cs_dag_t *, dap_chain_cs_dag_event_round_info_t *);
typedef void (*dap_chain_cs_dag_callback_set_event_round_info_t)(dap_chain_cs_dag_t *, dap_chain_cs_dag_event_round_info_t *);

typedef int (*dap_chain_cs_dag_callback_event_round_sync_t)(dap_chain_cs_dag_t * a_dag, const char a_op_code, const char *a_group,
                                                const char *a_key, const void *a_value, const size_t a_value_size);

typedef struct dap_chain_cs_dag_hal_item {
    dap_chain_hash_fast_t hash;
    UT_hash_handle hh;
} dap_chain_cs_dag_hal_item_t;

typedef struct dap_chain_cs_dag
{
    dap_chain_t * chain;
    bool is_single_line;
    bool is_celled;
    bool is_add_directly;
    bool is_static_genesis_event;
    dap_chain_hash_fast_t static_genesis_event_hash;
    dap_chain_cs_dag_hal_item_t *hal;

    dap_chain_cs_dag_event_round_info_t event_round_info; // for verify function
    bool use_event_round_info;
    bool broadcast_disable;

    uint16_t datum_add_hashes_count;
    char * gdb_group_events_round_new;
    char *gdb_group_datums_queue;

    dap_chain_cs_dag_callback_t callback_delete;
    dap_chain_cs_dag_callback_event_create_t callback_cs_event_create;
    dap_chain_cs_dag_callback_event_t callback_cs_verify;
    dap_chain_cs_dag_callback_get_round_info_t callback_cs_get_round_info;
    dap_chain_cs_dag_callback_set_event_round_info_t callback_cs_set_event_round_info;
    dap_chain_cs_dag_callback_event_round_sync_t callback_cs_event_round_sync;

    void * _pvt;
    void * _inheritor;
} dap_chain_cs_dag_t;

#define DAP_CHAIN_CS_DAG(a) ( (dap_chain_cs_dag_t *) (a)->_inheritor)

int dap_chain_cs_dag_init(void);
void dap_chain_cs_dag_deinit(void);

int dap_chain_cs_dag_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg);
void dap_chain_cs_dag_delete(dap_chain_t * a_chain);

//dap_chain_cs_dag_event_item_t* dap_chain_cs_dag_proc_treshold(dap_chain_cs_dag_t * a_dag, dap_ledger_t * a_ledger);
void dap_chain_cs_dag_proc_event_round_new(dap_chain_cs_dag_t *a_dag);

dap_chain_cs_dag_event_t* dap_chain_cs_dag_find_event_by_hash(dap_chain_cs_dag_t * a_dag,
                                                              dap_chain_hash_fast_t * a_hash);
void dap_chain_cs_new_event_add_datums(dap_chain_t *a_chain, bool a_round_check);
