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

#include "dap_chain_tx_compose_registry.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include <pthread.h>

#define LOG_TAG "dap_tx_compose_registry"

// Global registry hash table
static dap_chain_tx_compose_registry_entry_t *s_registry = NULL;

// Thread safety
static pthread_rwlock_t s_registry_rwlock = PTHREAD_RWLOCK_INITIALIZER;

/**
 * @brief Initialize registry
 */
int dap_chain_tx_compose_registry_init(void)
{
    s_registry = NULL;
    log_it(L_INFO, "TX Compose Registry initialized");
    return 0;
}

/**
 * @brief Deinit registry - cleanup all entries
 */
void dap_chain_tx_compose_registry_deinit(void)
{
    pthread_rwlock_wrlock(&s_registry_rwlock);
    
    dap_chain_tx_compose_registry_entry_t *l_entry, *l_tmp;
    dap_ht_foreach(s_registry, l_entry, l_tmp) {
        dap_ht_del(s_registry, l_entry);
        DAP_DELETE(l_entry->tx_type);
        DAP_DELETE(l_entry);
    }
    
    s_registry = NULL;
    
    pthread_rwlock_unlock(&s_registry_rwlock);
    
    log_it(L_INFO, "TX Compose Registry deinitialized");
}

/**
 * @brief Add entry to registry
 */
int dap_chain_tx_compose_registry_add(
    const char *a_tx_type,
    dap_chain_tx_compose_callback_t a_callback,
    void *a_user_data
)
{
    if (!a_tx_type || !a_callback) {
        log_it(L_ERROR, "Invalid parameters for registry_add");
        return -1;
    }
    
    pthread_rwlock_wrlock(&s_registry_rwlock);
    
    // Check if already registered
    dap_chain_tx_compose_registry_entry_t *l_existing = NULL;
    dap_ht_find_str(s_registry, a_tx_type, l_existing);
    
    if (l_existing) {
        log_it(L_WARNING, "TX type '%s' already registered, replacing", a_tx_type);
        dap_ht_del(s_registry, l_existing);
        DAP_DELETE(l_existing->tx_type);
        DAP_DELETE(l_existing);
    }
    
    // Create new entry
    dap_chain_tx_compose_registry_entry_t *l_entry = DAP_NEW_Z(dap_chain_tx_compose_registry_entry_t);
    if (!l_entry) {
        log_it(L_ERROR, "Memory allocation failed for registry entry");
        pthread_rwlock_unlock(&s_registry_rwlock);
        return -2;
    }
    
    l_entry->tx_type = dap_strdup(a_tx_type);
    l_entry->callback = a_callback;
    l_entry->user_data = a_user_data;
    
    // Add to hash table
    dap_ht_add_keyptr(s_registry, l_entry->tx_type, strlen(l_entry->tx_type), l_entry);
    
    pthread_rwlock_unlock(&s_registry_rwlock);
    
    log_it(L_INFO, "TX Compose: registered builder for type '%s'", a_tx_type);
    return 0;
}

/**
 * @brief Remove entry from registry
 */
void dap_chain_tx_compose_registry_remove(const char *a_tx_type)
{
    if (!a_tx_type) {
        return;
    }
    
    pthread_rwlock_wrlock(&s_registry_rwlock);
    
    dap_chain_tx_compose_registry_entry_t *l_entry = NULL;
    dap_ht_find_str(s_registry, a_tx_type, l_entry);
    
    if (l_entry) {
        dap_ht_del(s_registry, l_entry);
        DAP_DELETE(l_entry->tx_type);
        DAP_DELETE(l_entry);
        log_it(L_INFO, "TX Compose: unregistered builder for type '%s'", a_tx_type);
    } else {
        log_it(L_WARNING, "TX Compose: type '%s' not found for unregister", a_tx_type);
    }
    
    pthread_rwlock_unlock(&s_registry_rwlock);
}

/**
 * @brief Find entry in registry
 */
dap_chain_tx_compose_registry_entry_t* dap_chain_tx_compose_registry_find(
    const char *a_tx_type
)
{
    if (!a_tx_type) {
        return NULL;
    }
    
    pthread_rwlock_rdlock(&s_registry_rwlock);
    
    dap_chain_tx_compose_registry_entry_t *l_entry = NULL;
    dap_ht_find_str(s_registry, a_tx_type, l_entry);
    
    pthread_rwlock_unlock(&s_registry_rwlock);
    
    return l_entry;
}

