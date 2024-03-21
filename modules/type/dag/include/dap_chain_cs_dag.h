/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net      https://gitlab/demlabs
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Demlabs Application Protocol) the open source project

    DAP (Demlabs Application Protocol) is free software: you can redistribute it and/or modify
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

#define DAG_ROUND_CURRENT_KEY "round_current"
#define DAP_CHAIN_CLUSTER_ID_DAG 0x10000

typedef struct dap_chain_cs_dag dap_chain_cs_dag_t;

typedef void (*dap_chain_cs_dag_callback_t)(dap_chain_cs_dag_t *);
typedef void (*dap_chain_cs_dag_callback_rc_ptr_t)(dap_chain_cs_dag_t *, int a_rc, void * a_arg);
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

    atomic_uint_fast64_t round_current, round_completed;

    uint16_t datum_add_hashes_count;
    char * gdb_group_events_round_new;

    dap_chain_cs_dag_callback_t callback_delete;
    dap_chain_cs_dag_callback_event_create_t callback_cs_event_create;
    dap_chain_cs_dag_callback_event_t callback_cs_verify;
    dap_chain_cs_dag_callback_event_round_sync_t callback_cs_event_round_sync;

    void * _pvt;
    void * _inheritor;
} dap_chain_cs_dag_t;

#define DAP_CHAIN_CS_DAG(a) ( (dap_chain_cs_dag_t *) (a)->_inheritor)

int dap_chain_cs_dag_init();
void dap_chain_cs_dag_deinit(void);

void dap_chain_cs_dag_proc_event_round_new(dap_chain_cs_dag_t *a_dag);
dap_chain_cs_dag_event_t* dap_chain_cs_dag_find_event_by_hash(dap_chain_cs_dag_t * a_dag, dap_chain_hash_fast_t * a_hash);
