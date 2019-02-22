/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
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

#include "dap_common.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"

#define LOG_TAG "dap_chain_cs_dag_poa"

typedef struct dap_chain_cs_dag_poa_pvt
{
    dap_chain_cert_t ** certs;
    size_t certs_count;
    size_t certs_count_verify; // Number of signatures, needed for event verification
} dap_chain_cs_dag_poa_pvt_t;

#define PVT(a) ((dap_chain_cs_dag_poa_pvt_t *) a->_pvt )

static void s_chain_cs_dag_callback_delete(dap_chain_cs_dag_t * a_dag);
static void s_chain_cs_callback_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg);
static int s_chain_cs_dag_callback_event_input(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_dag_event);
static int s_chain_cs_dag_callback_event_verify(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_dag_event);

/**
 * @brief dap_chain_cs_dag_poa_init
 * @return
 */
int dap_chain_cs_dag_poa_init()
{
    dap_chain_cs_add ("dag-poa", s_chain_cs_callback_new );
    return 0;
}

/**
 * @brief dap_chain_cs_dag_poa_deinit
 */
void dap_chain_cs_dag_poa_deinit()
{

}

/**
 * @brief s_cs_callback
 * @param a_chain
 * @param a_chain_cfg
 */
static void s_chain_cs_callback_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg)
{
    dap_chain_cs_dag_new(a_chain,a_chain_cfg);
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG ( a_chain );
    dap_chain_cs_dag_poa_t * l_poa = DAP_NEW_Z ( dap_chain_cs_dag_poa_t);
    l_dag->_inheritor = l_poa;
    l_dag->callback_delete = s_chain_cs_dag_callback_delete;
    l_dag->callback_event_input = s_chain_cs_dag_callback_event_input;
    l_dag->callback_event_verify = s_chain_cs_dag_callback_event_verify;
    l_poa->_pvt = DAP_NEW_Z ( dap_chain_cs_dag_poa_pvt_t );

    dap_chain_cs_dag_poa_pvt_t * l_poa_pvt = PVT ( l_poa );
    l_poa_pvt->certs_count = dap_config_get_item_int32_default(a_chain_cfg,"dag-poa","auth_certs_number",0);

}

/**
 * @brief s_chain_cs_dag_callback_delete
 * @param a_dag
 */
static void s_chain_cs_dag_callback_delete(dap_chain_cs_dag_t * a_dag)
{
    dap_chain_cs_dag_poa_t * l_poa = DAP_CHAIN_CS_DAG_POA ( a_dag );

    if ( l_poa->_pvt ) {
        dap_chain_cs_dag_poa_pvt_t * l_poa_pvt = PVT ( l_poa );
        if ( l_poa_pvt->certs )
            DAP_DELETE ( l_poa_pvt->certs);
        DAP_DELETE ( l_poa->_pvt);
    }

    if ( l_poa->_inheritor ) {
       DAP_DELETE ( l_poa->_inheritor );
    }
}

/**
 * @brief s_chain_cs_dag_callback_event_input
 * @param a_dag
 * @param a_dag_event
 * @return
 */
static int s_chain_cs_dag_callback_event_input(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_dag_event)
{
    return -1; // TODO
}

/**
 * @brief s_chain_cs_dag_callback_event_verify
 * @param a_dag
 * @param a_dag_event
 * @return
 */
static int s_chain_cs_dag_callback_event_verify(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_dag_event)
{
   return -1; // TODO
}
