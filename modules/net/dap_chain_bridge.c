/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2020
 * All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <assert.h>
#include "uthash.h"
#include "dap_common.h"
#include "dap_chain_bridge.h"

#define LOG_TAG "dap_chain_bridge"
typedef struct bridge_item{
    char name[64];
    dap_chain_bridge_callback_init_t callback_init;
    UT_hash_handle hh;
} bridge_item_t;

static bridge_item_t * s_items = NULL;

/**
 * @brief dap_chain_bridge_init
 * @return
 */
int dap_chain_bridge_init()
{
    return 0;
}

/**
 * @brief dap_chain_bridge_deinit
 */
void dap_chain_bridge_deinit()
{

}

/**
 * @brief dap_chain_bridge_register
 * @param a_bridge_name
 * @param a_callback_init
 * @return
 */
int dap_chain_bridge_register(const char * a_bridge_name,  dap_chain_bridge_callback_init_t a_callback_init )
{
    bridge_item_t * l_item = NULL;
    HASH_FIND_STR(s_items,a_bridge_name, l_item);
    if (l_item)
        return -1;

    l_item = DAP_NEW_Z(bridge_item_t);
    strncpy( l_item->name,a_bridge_name,sizeof (l_item->name)-1);
    l_item->callback_init = a_callback_init;
    HASH_ADD_STR(s_items,name,l_item);

    return 0;
}

/**
 * @brief dap_chain_bridge_add
 * @param a_bridge_name
 * @param a_net
 * @param a_net_config
 * @return
 */
int dap_chain_bridge_add(const char * a_bridge_name, dap_chain_net_t * a_net, dap_config_t * a_net_config )
{
    bridge_item_t * l_item = NULL;
    HASH_FIND_STR(s_items, a_bridge_name, l_item);
    if (!l_item){
        log_it(L_ERROR,"Can't find \"%s\" bridge", a_bridge_name);
        return -1;
    }
    if (l_item->callback_init){
        log_it(L_ERROR,"Init callback for bridge name \"%s\" is NULL", a_bridge_name);
        return -2;
    }
    l_item->callback_init(a_bridge_name,a_net, a_net_config);
    return 0;
}
