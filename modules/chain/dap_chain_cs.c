/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
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

#include "dap_common.h"
#include "uthash.h"
#include "utlist.h"
#include "dap_chain_cs.h"

#define LOG_TAG "dap_chain_cs"

typedef struct dap_chain_callback_new_cfg_item
{
    char name[32];
    dap_chain_callback_new_cfg_t callback_init;
    dap_chain_callback_t callback_start;
    UT_hash_handle hh;
} dap_chain_callback_new_cfg_item_t;

static dap_chain_callback_new_cfg_item_t * s_cs_callbacks = NULL;
static dap_chain_callback_new_cfg_item_t * s_class_callbacks = NULL;

/**
 * @brief dap_chain_cs_init
 * @return
 */
int dap_chain_cs_init(void)
{
    return 0;
}

/**
 * @brief dap_chain_cs_deinit
 */
void dap_chain_cs_deinit(void)
{

}

/**
 * @brief dap_chain_class_add
 * @param a_cs_str consensus name
 * @param a_callback_init callback function
 */
void dap_chain_cs_type_add (const char * a_cs_str, dap_chain_callback_new_cfg_t a_callback_init, dap_chain_callback_t a_callback_start)
{
    dap_chain_callback_new_cfg_item_t *l_item = DAP_NEW_Z ( dap_chain_callback_new_cfg_item_t );
    if ( !l_item ) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return;
    }
    strncpy(l_item->name, a_cs_str, sizeof (l_item->name) - 1);
    l_item->name[sizeof (l_item->name) - 1] = '\0';
    l_item->callback_init = a_callback_init;
    l_item->callback_start = a_callback_start;
    HASH_ADD_STR( s_class_callbacks, name, l_item);
}

/**
 * @brief dap_chain_class_create
 * @param a_chain
 * @param a_chain_cfg
 * @return
 */
int dap_chain_cs_type_create(const char *a_type, dap_chain_t * a_chain, dap_config_t * a_chain_cfg)
{
    dap_chain_callback_new_cfg_item_t *l_item = NULL;
    HASH_FIND_STR(s_class_callbacks, a_type, l_item);
    if (l_item && l_item->callback_init)
        return l_item->callback_init(a_chain, a_chain_cfg);
    return -1;
}

/**
 * @brief dap_chain_class_create
 * @param a_chain
 * @return
 */
void dap_chain_cs_type_start(const char *a_type, dap_chain_t *a_chain)
{
    dap_chain_callback_new_cfg_item_t *l_item = NULL;
    HASH_FIND_STR(s_class_callbacks, a_type, l_item);
    if (l_item && l_item->callback_start)
        l_item->callback_start(a_chain);
}


/**
 * @brief dap_chain_cs_add
 * add consensus [dag_pos, dag_poa, block_poa, none] to s_cs_callbacks linked list
 * @param a_cs_str
 * @param a_callback_init
 */
void dap_chain_cs_add (const char * a_cs_str, dap_chain_callback_new_cfg_t a_callback_init, dap_chain_callback_t a_callback_start)
{
    dap_chain_callback_new_cfg_item_t *l_item = DAP_NEW_Z ( dap_chain_callback_new_cfg_item_t );
    if ( !l_item ) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return;
    }
    strncpy(l_item->name, a_cs_str, sizeof (l_item->name) - 1);
    l_item->name[sizeof (l_item->name) - 1] = '\0';
    l_item->callback_init = a_callback_init;
    l_item->callback_start = a_callback_start;
    HASH_ADD_STR( s_cs_callbacks, name, l_item);
}

/**
 * @brief dap_chain_cs_create
 * get consensus from chain cfg file [dag_pos, dag_poa, block_poa, none]
 * dap_config_get_item_str( a_chain_cfg, "chain", "consensus");
 * verify if consensus was created by dap_chain_cs_add function
 * @param a_chain dap_chain_t chain object
 * @param a_chain_cfg dap_config_t 
 * @return
 */
int dap_chain_cs_create(dap_chain_t * a_chain, dap_config_t * a_chain_cfg)
{
    dap_chain_callback_new_cfg_item_t *l_item = NULL;
#if defined(DAP_CHAIN_BLOCKS_TEST) || defined(DAP_LEDGER_TEST)
    const char *l_consensus = NULL;
    if (a_chain->id.uint64 == 0)
        l_consensus = dap_strdup("dag_poa");
    else
        l_consensus = dap_strdup("esbocs");
#else
    const char *l_consensus = dap_config_get_item_str( a_chain_cfg, "chain", "consensus");
#endif
    if(l_consensus)
        HASH_FIND_STR(s_cs_callbacks, l_consensus, l_item );
    if (l_item) {
        log_it(L_NOTICE,"Consensus \"%s\" found, prepare to parse config file",l_item->name );
        int res = 0;
        if (l_item->callback_init)
            res = l_item->callback_init(a_chain, a_chain_cfg);
        DAP_CHAIN_PVT(a_chain)->cs_name = l_item->name;
        return res;
    } else {
        log_it(L_ERROR,"Can't find consensus \"%s\"",dap_config_get_item_str( a_chain_cfg, "chain", "consensus"));
        return -1;
    }
}
