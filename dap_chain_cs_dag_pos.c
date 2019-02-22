/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
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
#include "dap_chain_cs_dag_pos.h"

#define LOG_TAG "dap_chain_cs_dag_pos"

typedef struct dap_chain_cs_dag_pos_pvt
{
    uint8_t padding;
} dap_chain_cs_dag_pos_pvt_t;

#define PVT(a) ((dap_chain_cs_dag_pos_pvt_t *) a->_pvt )

static void s_chain_cs_dag_callback_delete(dap_chain_cs_dag_t * a_dag);
static void s_chain_cs_callback_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg);

/**
 * @brief dap_chain_cs_dag_pos_init
 * @return
 */
int dap_chain_cs_dag_pos_init()
{
    dap_chain_cs_add ("dag-pos", s_chain_cs_callback_new );
    return 0;
}

/**
 * @brief dap_chain_cs_dag_pos_deinit
 */
void dap_chain_cs_dag_pos_deinit()
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
    dap_chain_cs_dag_pos_t * l_pos = DAP_NEW_Z ( dap_chain_cs_dag_pos_t);
    l_dag->_inheritor = l_pos;
    l_dag->callback_delete = s_chain_cs_dag_callback_delete;
    l_pos->_pvt = DAP_NEW_Z ( dap_chain_cs_dag_pos_pvt_t );

    dap_chain_cs_dag_pos_pvt_t * l_pos_pvt = PVT ( l_pos );
}

/**
 * @brief s_chain_cs_dag_callback_delete
 * @param a_dag
 */
static void s_chain_cs_dag_callback_delete(dap_chain_cs_dag_t * a_dag)
{
    dap_chain_cs_dag_pos_t * l_pos = DAP_CHAIN_CS_DAG_POS ( a_dag );

    if ( l_pos->_pvt ) {
        dap_chain_cs_dag_pos_pvt_t * l_pos_pvt = PVT ( l_pos );
        DAP_DELETE ( l_pos->_pvt);
    }

    if ( l_pos->_inheritor ) {
       DAP_DELETE ( l_pos->_inheritor );
    }
}
