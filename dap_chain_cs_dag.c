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
#include "dap_chain_cs_dag.h"

#define LOG_TAG "dap_chain_cs_dag"

typedef struct dap_chain_cs_dag_pvt {
    uint8_t padding;
} dap_chain_cs_dag_pvt_t;

#define PVT(a) ((dap_chain_cs_dag_pvt_t *) a->_pvt )

static int s_chain_callback_element_add(dap_chain_t * a_chain, void * a_data, size_t a_data_size);// Accept new element in chain
static int s_chain_callback_element_get_first(dap_chain_t * a_chain, void ** a_data, size_t * a_data_size ); // Get the fisrt element from chain
static int s_chain_callback_element_get_next( dap_chain_t * a_chain, void ** a_data, size_t * a_data_size ); // Get the next element from chain from the current one

/**
 * @brief dap_chain_cs_dag_init
 * @return
 */
int dap_chain_cs_dag_init()
{
    return 0;
}

/**
 * @brief dap_chain_cs_dag_deinit
 */
void dap_chain_cs_dag_deinit()
{

}

/**
 * @brief dap_chain_cs_dag_new
 * @param a_chain
 * @param a_chain_cfg
 */
void dap_chain_cs_dag_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg)
{
    dap_chain_cs_dag_t * l_chain_cs_dag = DAP_NEW_Z(dap_chain_cs_dag_t);
    l_chain_cs_dag->_pvt = DAP_NEW_Z(dap_chain_cs_dag_pvt_t);
    l_chain_cs_dag->chain = a_chain;

    a_chain->callback_delete = dap_chain_cs_dag_delete;
    a_chain->callback_element_add = s_chain_callback_element_add; // Accept new element in chain
    a_chain->callback_element_get_first = s_chain_callback_element_get_first; // Get the fisrt element from chain
    a_chain->callback_element_get_next = s_chain_callback_element_get_next; // Get the next element from chain from the current one
    a_chain->_inheritor = l_chain_cs_dag;

    log_it (L_NOTICE, "DAG chain initialized");
}

/**
 * @brief dap_chain_cs_dag_delete
 * @param a_dag
 * @return
 */
void dap_chain_cs_dag_delete(dap_chain_t * a_chain)
{
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG ( a_chain );
    if(l_dag->callback_delete )
        l_dag->callback_delete(l_dag);
    if(l_dag->_inheritor)
        DAP_DELETE(l_dag->_inheritor);
    if(l_dag->_pvt)
        DAP_DELETE(l_dag->_pvt);
    DAP_DELETE(l_dag);
}

/**
 * @brief s_chain_callback_element_add Accept new element in chain
 * @param a_chain
 * @param a_data
 * @param a_data_size
 */
static int s_chain_callback_element_add(dap_chain_t * a_chain, void * a_data, size_t a_data_size)
{
    return -1; // TODO
}

/**
 * @brief s_chain_callback_element_get_first Get the fisrt element from chain
 * @param a_chain
 * @param a_data
 * @param a_data_size
 * @return 0 if ok
 */
static int s_chain_callback_element_get_first(dap_chain_t * a_chain, void ** a_data, size_t * a_data_size )
{
    return -1; // TODO
}

/**
 * @brief s_chain_callback_element_get_next Get the next element from chain from the current one
 * @param a_chain
 * @param a_data
 * @param a_data_size
 * @return 0 if ok
 */
static int s_chain_callback_element_get_next( dap_chain_t * a_chain, void ** a_data, size_t * a_data_size )
{
    return -1; // TODO
}
