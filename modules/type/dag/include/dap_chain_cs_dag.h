/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net      https://gitlab/demlabs
 * Kelvin Project https://github.com/kelvinblockchain
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
#include "uthash.h"
#include "dap_chain.h"
#include "dap_chain_cs_dag_event.h"

#define DAG_ROUND_CURRENT_KEY "round_current"
#define DAP_CHAIN_CLUSTER_ID_DAG 0x10000

typedef struct dap_chain_cs_dag dap_chain_cs_dag_t;

typedef void (*dap_chain_cs_dag_callback_t)(dap_chain_cs_dag_t *a_dag);
typedef void (*dap_chain_cs_dag_callback_rc_ptr_t)(dap_chain_cs_dag_t *, int a_rc, void * a_arg);
typedef int (*dap_chain_cs_dag_callback_event_t)(dap_chain_cs_dag_t *a_dag, dap_chain_cs_dag_event_t *a_event, dap_hash_fast_t *a_event_hash);

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

    uint16_t datum_add_hashes_count;
    char * gdb_group_events_round_new;

    dap_chain_cs_dag_callback_t callback_delete;
    dap_chain_cs_dag_callback_event_create_t callback_cs_event_create;
    dap_chain_cs_dag_callback_event_t callback_cs_verify;

    void * _pvt;
    void * _inheritor;
} dap_chain_cs_dag_t;

typedef enum s_com_dag_err{
    DAP_CHAIN_NODE_CLI_COM_DAG_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_DAG_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_CHAIN_TYPE_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_DATUM_DEL_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_EVENT_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_SIGN_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_FIND_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_GLOBALDB_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_UNDEF_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_CERT_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_FIND_EVENT_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_UNDEF_SUB_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_CONVERT_ERR,

    /* add custom codes here */

    DAP_CHAIN_NODE_CLI_COM_DAG_UNKNOWN /* MAX */
} s_com_dag_err_t;

#define DAP_CHAIN_CS_DAG(a) ( (dap_chain_cs_dag_t *) (a)->_inheritor)

int dap_chain_cs_dag_init();
void dap_chain_cs_dag_deinit(void);

void dap_chain_cs_dag_proc_event_round_new(dap_chain_cs_dag_t *a_dag);
dap_chain_cs_dag_event_t* dap_chain_cs_dag_find_event_by_hash(dap_chain_cs_dag_t * a_dag, dap_chain_hash_fast_t * a_hash);
