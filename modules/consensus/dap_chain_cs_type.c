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
#include "dap_chain_cs_type.h"

#define DAP_CHAIN_CS_NAME_STRLEN_MAX        32
#define DAP_CHAIN_CS_CLASS_NAME_STRLEN_MAX  DAP_CHAIN_CS_NAME_STRLEN_MAX

// Chain type registration (blocks, dag, none)
typedef struct dap_chain_type_callbacks_item {
    char name[DAP_CHAIN_CS_CLASS_NAME_STRLEN_MAX];
    dap_chain_type_callbacks_t callbacks;
    UT_hash_handle hh;
} dap_chain_type_callbacks_item_t;

#define LOG_TAG "dap_chain_cs"

static dap_chain_type_callbacks_item_t *s_type_callbacks = NULL;

/**
 * @brief dap_chain_type_init - initialize chain type registry
 * @return 0 on success
 */
int dap_chain_type_init(void)
{
    log_it(L_INFO, "Chain type registry initialized");
    return 0;
}

/**
 * @brief dap_chain_type_deinit - cleanup chain type registry
 */
void dap_chain_type_deinit(void)
{
    dap_chain_type_callbacks_item_t *l_item, *l_tmp;
    HASH_ITER(hh, s_type_callbacks, l_item, l_tmp) {
        HASH_DEL(s_type_callbacks, l_item);
        DAP_DELETE(l_item);
    }
    log_it(L_INFO, "Chain type registry cleaned up");
}

/**
 * @brief dap_chain_type_add
 * @param a_cs_str chain type name
 * @param a_callbacks callback function
 */
void dap_chain_type_add(const char *a_cs_str, dap_chain_type_callbacks_t a_callbacks)
{
    dap_chain_type_callbacks_item_t *l_item = DAP_NEW_Z_RET_IF_FAIL(dap_chain_type_callbacks_item_t);
    dap_strncpy(l_item->name, a_cs_str, sizeof (l_item->name));
    l_item->callbacks = a_callbacks;
    HASH_ADD_STR(s_type_callbacks, name, l_item);
}

/**
 * @brief dap_chain_type_create
 * @param a_chain
 * @param a_chain_cfg
 * @return
 */
int dap_chain_type_create(dap_chain_t *a_chain, dap_config_t *a_chain_cfg)
{
    dap_chain_type_callbacks_item_t *l_item = NULL;
    HASH_FIND_STR(s_type_callbacks, DAP_CHAIN_PVT(a_chain)->cs_type, l_item);
    return l_item && l_item->callbacks.callback_init
        ? l_item->callbacks.callback_init(a_chain, a_chain_cfg)
        : -1;
}

int dap_chain_type_delete(dap_chain_t *a_chain)
{
    dap_chain_type_callbacks_item_t *l_item = NULL;
    HASH_FIND_STR(s_type_callbacks, DAP_CHAIN_PVT(a_chain)->cs_type, l_item);
    dap_return_val_if_fail_err(l_item, -1, "Callbacks for cs %s not found!", DAP_CHAIN_PVT(a_chain)->cs_name);
    return l_item->callbacks.callback_delete
        ? l_item->callbacks.callback_delete(a_chain)
        : 0;
}

int dap_chain_type_purge(dap_chain_t *a_chain)
{
    dap_chain_type_callbacks_item_t *l_item = NULL;
    HASH_FIND_STR(s_type_callbacks, DAP_CHAIN_PVT(a_chain)->cs_type, l_item);
    dap_return_val_if_fail_err(l_item, -1, "Callbacks for cs %s not found!", DAP_CHAIN_PVT(a_chain)->cs_name);
    return l_item->callbacks.callback_purge
        ? l_item->callbacks.callback_purge(a_chain)
        : 0;
}
