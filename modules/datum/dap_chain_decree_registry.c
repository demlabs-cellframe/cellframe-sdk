/*
 * Authors:
 * Daniil Frolov <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright (c) 2025, All rights reserved.
 *
 * This file is part of CellFrame SDK the open source project
 *
 *    CellFrame SDK is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    CellFrame SDK is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <pthread.h>
#include "dap_chain_decree_registry.h"
#include "dap_chain_datum_decree.h"  // For decree structure access
#include "dap_common.h"
#include "dap_hash.h"
#include "uthash.h"

#define LOG_TAG "dap_decree_registry"

// Registry entry structure
typedef struct dap_chain_decree_handler_entry {
    uint16_t decree_type;
    uint16_t decree_subtype;
    dap_chain_decree_handler_callback_t handler;
    char *handler_name;
    
    // UTHASH key: decree_type (2 bytes) + decree_subtype (2 bytes) = 4 bytes
    uint32_t key;
    UT_hash_handle hh;
} dap_chain_decree_handler_entry_t;

// Global registry state
static dap_chain_decree_handler_entry_t *s_decree_handlers = NULL;
static pthread_rwlock_t s_decree_registry_lock = PTHREAD_RWLOCK_INITIALIZER;
static bool s_registry_initialized = false;

// Helper function to create composite key
static inline uint32_t s_make_key(uint16_t a_decree_type, uint16_t a_decree_subtype) {
    return ((uint32_t)a_decree_type << 16) | (uint32_t)a_decree_subtype;
}

int dap_chain_decree_registry_init(void)
{
    if (s_registry_initialized) {
        log_it(L_WARNING, "Decree registry already initialized");
        return 0;
    }
    
    pthread_rwlock_init(&s_decree_registry_lock, NULL);
    s_decree_handlers = NULL;
    s_registry_initialized = true;
    
    log_it(L_NOTICE, "Decree registry initialized");
    return 0;
}

void dap_chain_decree_registry_deinit(void)
{
    if (!s_registry_initialized)
        return;
    
    pthread_rwlock_wrlock(&s_decree_registry_lock);
    
    dap_chain_decree_handler_entry_t *l_entry, *l_tmp;
    HASH_ITER(hh, s_decree_handlers, l_entry, l_tmp) {
        HASH_DEL(s_decree_handlers, l_entry);
        if (l_entry->handler_name)
            DAP_FREE(l_entry->handler_name);
        DAP_FREE(l_entry);
    }
    
    s_decree_handlers = NULL;
    s_registry_initialized = false;
    
    pthread_rwlock_unlock(&s_decree_registry_lock);
    pthread_rwlock_destroy(&s_decree_registry_lock);
    
    log_it(L_NOTICE, "Decree registry deinitialized");
}

int dap_chain_decree_registry_register_handler(
    uint16_t a_decree_type,
    uint16_t a_decree_subtype,
    dap_chain_decree_handler_callback_t a_handler,
    const char *a_handler_name)
{
    if (!s_registry_initialized) {
        log_it(L_ERROR, "Decree registry not initialized");
        return -1;
    }
    
    if (!a_handler) {
        log_it(L_ERROR, "Handler callback is NULL");
        return -2;
    }
    
    uint32_t l_key = s_make_key(a_decree_type, a_decree_subtype);
    
    pthread_rwlock_wrlock(&s_decree_registry_lock);
    
    // Check if handler already registered
    dap_chain_decree_handler_entry_t *l_existing = NULL;
    HASH_FIND(hh, s_decree_handlers, &l_key, sizeof(uint32_t), l_existing);
    
    if (l_existing) {
        pthread_rwlock_unlock(&s_decree_registry_lock);
        log_it(L_WARNING, "Handler for decree type=0x%04x subtype=0x%04x already registered as '%s'",
               a_decree_type, a_decree_subtype, l_existing->handler_name ?: "unknown");
        return -3;
    }
    
    // Create new entry
    dap_chain_decree_handler_entry_t *l_entry = DAP_NEW_Z(dap_chain_decree_handler_entry_t);
    if (!l_entry) {
        pthread_rwlock_unlock(&s_decree_registry_lock);
        log_it(L_CRITICAL, "Memory allocation failed for decree handler entry");
        return -4;
    }
    
    l_entry->decree_type = a_decree_type;
    l_entry->decree_subtype = a_decree_subtype;
    l_entry->handler = a_handler;
    l_entry->key = l_key;
    
    if (a_handler_name) {
        l_entry->handler_name = dap_strdup(a_handler_name);
    }
    
    HASH_ADD(hh, s_decree_handlers, key, sizeof(uint32_t), l_entry);
    
    pthread_rwlock_unlock(&s_decree_registry_lock);
    
    log_it(L_INFO, "Registered decree handler '%s' for type=0x%04x subtype=0x%04x",
           a_handler_name ?: "unnamed", a_decree_type, a_decree_subtype);
    
    return 0;
}

int dap_chain_decree_registry_unregister_handler(
    uint16_t a_decree_type,
    uint16_t a_decree_subtype)
{
    if (!s_registry_initialized) {
        log_it(L_ERROR, "Decree registry not initialized");
        return -1;
    }
    
    uint32_t l_key = s_make_key(a_decree_type, a_decree_subtype);
    
    pthread_rwlock_wrlock(&s_decree_registry_lock);
    
    dap_chain_decree_handler_entry_t *l_entry = NULL;
    HASH_FIND(hh, s_decree_handlers, &l_key, sizeof(uint32_t), l_entry);
    
    if (!l_entry) {
        pthread_rwlock_unlock(&s_decree_registry_lock);
        log_it(L_WARNING, "Handler for decree type=0x%04x subtype=0x%04x not found",
               a_decree_type, a_decree_subtype);
        return -2;
    }
    
    HASH_DEL(s_decree_handlers, l_entry);
    
    log_it(L_INFO, "Unregistered decree handler '%s' for type=0x%04x subtype=0x%04x",
           l_entry->handler_name ?: "unnamed", a_decree_type, a_decree_subtype);
    
    if (l_entry->handler_name)
        DAP_FREE(l_entry->handler_name);
    DAP_FREE(l_entry);
    
    pthread_rwlock_unlock(&s_decree_registry_lock);
    
    return 0;
}

int dap_chain_decree_registry_process(
    dap_chain_datum_decree_t *a_decree,
    dap_chain_net_t *a_net,
    bool a_apply,
    bool a_anchored)
{
    if (!s_registry_initialized) {
        log_it(L_ERROR, "Decree registry not initialized");
        return -1;
    }
    
    if (!a_decree) {
        log_it(L_ERROR, "Decree is NULL");
        return -2;
    }
    
    // Access decree type/subtype through header
    // Note: We need to include proper header or use accessor functions
    // For now, using direct access assuming structure is available
    uint16_t l_decree_type = a_decree->header.type;
    uint16_t l_decree_subtype = a_decree->header.sub_type;
    
    uint32_t l_key = s_make_key(l_decree_type, l_decree_subtype);
    
    pthread_rwlock_rdlock(&s_decree_registry_lock);
    
    dap_chain_decree_handler_entry_t *l_entry = NULL;
    HASH_FIND(hh, s_decree_handlers, &l_key, sizeof(uint32_t), l_entry);
    
    if (!l_entry) {
        pthread_rwlock_unlock(&s_decree_registry_lock);
        log_it(L_WARNING, "No handler registered for decree type=0x%04x subtype=0x%04x",
               l_decree_type, l_decree_subtype);
        return -404;
    }
    
    dap_chain_decree_handler_callback_t l_handler = l_entry->handler;
    const char *l_handler_name = l_entry->handler_name;
    
    pthread_rwlock_unlock(&s_decree_registry_lock);
    
    // Invoke handler
    log_it(L_DEBUG, "Invoking decree handler '%s' for type=0x%04x subtype=0x%04x (apply=%s, anchored=%s)",
             l_handler_name ?: "unnamed", l_decree_type, l_decree_subtype,
             a_apply ? "true" : "false", a_anchored ? "true" : "false");
    
    int l_ret = l_handler(a_decree, a_net, a_apply, a_anchored);
    
    if (l_ret != 0) {
        log_it(L_WARNING, "Decree handler '%s' returned error code: %d",
               l_handler_name ?: "unnamed", l_ret);
    }
    
    return l_ret;
}

bool dap_chain_decree_registry_has_handler(
    uint16_t a_decree_type,
    uint16_t a_decree_subtype)
{
    if (!s_registry_initialized)
        return false;
    
    uint32_t l_key = s_make_key(a_decree_type, a_decree_subtype);
    
    pthread_rwlock_rdlock(&s_decree_registry_lock);
    
    dap_chain_decree_handler_entry_t *l_entry = NULL;
    HASH_FIND(hh, s_decree_handlers, &l_key, sizeof(uint32_t), l_entry);
    
    pthread_rwlock_unlock(&s_decree_registry_lock);
    
    return (l_entry != NULL);
}
