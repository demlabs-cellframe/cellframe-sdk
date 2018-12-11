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
#include <stdint.h>
#include "dap_common.h"
#include "dap_chain_dag.h"

#define LOG_TAG "chain_dag"

typedef struct dap_chain_dag_pvt {
    uint8_t padding;
} dap_chain_dag_pvt_t;

#define PVT(a) ((dap_chain_dag_pvt_t *) a->_pvt )

/**
 * @brief dap_chain_dag_init
 * @return
 */
int dap_chain_dag_init()
{
    return 0;
}

/**
 * @brief dap_chain_dag_deinit
 */
void dap_chain_dag_deinit()
{

}

/**
 * @brief dap_chain_dag_new
 * @param a_chain
 * @return
 */
dap_chain_dag_t *dap_chain_dag_new(dap_chain_t * a_chain)
{
    dap_chain_dag_t * l_ret = DAP_NEW_Z(dap_chain_dag_t);
    l_ret->_pvt = DAP_NEW_Z(dap_chain_dag_pvt_t);
    l_ret->chain = a_chain;
    return l_ret;
}

/**
 * @brief dap_chain_dag_delete
 * @param a_dag
 * @return
 */
void dap_chain_dag_delete(dap_chain_dag_t * a_dag)
{
    if(a_dag->callback_delete )
        a_dag->callback_delete(a_dag->chain);
    if(a_dag->_inheritor)
        DAP_DELETE(a_dag->_inheritor);
    if(a_dag->_pvt)
        DAP_DELETE(a_dag->_pvt);
    DAP_DELETE(a_dag);
}
