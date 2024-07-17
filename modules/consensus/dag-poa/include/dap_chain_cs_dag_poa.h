/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
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
#include "dap_chain_cs_dag.h"
#include "dap_cert.h"

typedef int (*dap_chain_cs_dag_poa_callback_t)(dap_chain_t *, dap_chain_cs_dag_event_t*, size_t, void *);

typedef struct dap_chain_cs_dag_poa
{
    dap_chain_t * chain;
    dap_chain_cs_dag_t * dag;
    void * _pvt;
    void * _inheritor;
} dap_chain_cs_dag_poa_t;

typedef enum s_com_dag_poa_err{
    DAP_CHAIN_NODE_CLI_COM_DAG_POA_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_DAG_POA_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_POA_CHAIN_TYPE_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_POA_CERT_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_POA_HEX_FORMAT_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_POA_BASE58_FORMAT_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_POA_BASE58_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_POA_EVENT_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_POA_PLACE_EVENT_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_POA_SIGN_EVENT_ERR,
    DAP_CHAIN_NODE_CLI_COM_DAG_POA_SUBCOM_ERR,

    /* add custom codes here */

    DAP_CHAIN_NODE_CLI_COM_DAG_POA_UNKNOWN /* MAX */
} s_com_dag_poa_err_t;

#define DAP_CHAIN_CS_DAG_POA(a) ( (dap_chain_cs_dag_poa_t *) (a)->_inheritor)


int dap_chain_cs_dag_poa_init();
void dap_chain_cs_dag_poa_deinit(void);
dap_list_t *dap_chain_cs_dag_poa_get_auth_certs(dap_chain_t *a_chain, size_t *a_auth_certs_count, uint16_t *a_count_verify);
void dap_chain_cs_dag_poa_presign_callback_set(dap_chain_t *a_chain,
                  dap_chain_cs_dag_poa_callback_t a_callback, void *a_arg);
