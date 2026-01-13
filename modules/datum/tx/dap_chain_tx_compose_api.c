/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
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

#include "dap_chain_tx_compose_api.h"
#include "dap_chain_tx_compose_registry.h"
#include "dap_common.h"

#define LOG_TAG "dap_tx_compose_api"

/**
 * @brief Initialize TX Compose API
 */
int dap_chain_tx_compose_init(void)
{
    log_it(L_INFO, "Initializing TX Compose API...");
    
    int l_ret = dap_chain_tx_compose_registry_init();
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to initialize TX Compose Registry");
        return l_ret;
    }
    
    log_it(L_NOTICE, "TX Compose API initialized successfully");
    return 0;
}

/**
 * @brief Deinit TX Compose API
 */
void dap_chain_tx_compose_deinit(void)
{
    log_it(L_INFO, "Deinitializing TX Compose API...");
    dap_chain_tx_compose_registry_deinit();
    log_it(L_NOTICE, "TX Compose API deinitialized");
}

/**
 * @brief Register TX builder for specific type
 */
int dap_chain_tx_compose_register(
    const char *a_tx_type,
    dap_chain_tx_compose_callback_t a_callback,
    void *a_user_data
)
{
    if (!a_tx_type || !a_callback) {
        log_it(L_ERROR, "Invalid parameters for tx_compose_register");
        return -1;
    }
    
    int l_ret = dap_chain_tx_compose_registry_add(a_tx_type, a_callback, a_user_data);
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to register TX builder for type '%s'", a_tx_type);
        return l_ret;
    }
    
    return 0;
}

/**
 * @brief Unregister TX builder
 */
void dap_chain_tx_compose_unregister(const char *a_tx_type)
{
    if (!a_tx_type) {
        return;
    }
    
    dap_chain_tx_compose_registry_remove(a_tx_type);
}

/**
 * @brief Create TX via registered builder (dispatcher)
 */
dap_chain_datum_t* dap_chain_tx_compose_create(
    const char *a_tx_type,
    dap_ledger_t *a_ledger,
    dap_list_t *a_list_used_outs,
    void *a_params
)
{
    if (!a_tx_type || !a_ledger) {
        log_it(L_ERROR, "Invalid parameters for tx_compose_create");
        return NULL;
    }
    
    // Find registered builder
    dap_chain_tx_compose_registry_entry_t *l_entry = 
        dap_chain_tx_compose_registry_find(a_tx_type);
    
    if (!l_entry) {
        log_it(L_ERROR, "No builder registered for TX type '%s'", a_tx_type);
        return NULL;
    }
    
    // Dispatch to builder
    log_it(L_INFO, "Dispatching TX creation to '%s' builder...", a_tx_type);
    
    dap_chain_datum_t *l_datum = l_entry->callback(
        a_ledger,
        a_list_used_outs,
        a_params
    );
    
    if (!l_datum) {
        log_it(L_ERROR, "Builder for TX type '%s' returned NULL", a_tx_type);
        return NULL;
    }
    
    log_it(L_INFO, "TX type '%s' created successfully", a_tx_type);
    return l_datum;
}

/**
 * @brief Check if builder is registered
 */
bool dap_chain_tx_compose_is_registered(const char *a_tx_type)
{
    if (!a_tx_type) {
        return false;
    }
    
    dap_chain_tx_compose_registry_entry_t *l_entry = 
        dap_chain_tx_compose_registry_find(a_tx_type);
    
    return (l_entry != NULL);
}

