/*
 * Authors:
 * Dmitriy Gerasimov <naeper@demlabs.net>
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
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
#include <string.h>
#include "dap_common.h"
#include "dap_chain_net_api.h"

#define LOG_TAG "dap_chain_net_api"

/**
 * @brief Global function registry
 * @details Protected by mutex for thread-safe registration
 */
static dap_chain_net_api_registry_t s_api_registry = {0};
static pthread_mutex_t s_api_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool s_api_initialized = false;
static bool s_api_registered = false;

/**
 * @brief Initialize network API registry
 */
int dap_chain_net_api_init(void)
{
    pthread_mutex_lock(&s_api_mutex);
    if (s_api_initialized) {
        pthread_mutex_unlock(&s_api_mutex);
        return 0; // Already initialized
    }
    
    memset(&s_api_registry, 0, sizeof(s_api_registry));
    s_api_initialized = true;
    s_api_registered = false;
    
    log_it(L_INFO, "Network API registry initialized (Phase 5.3)");
    pthread_mutex_unlock(&s_api_mutex);
    return 0;
}

/**
 * @brief Deinitialize network API registry
 */
void dap_chain_net_api_deinit(void)
{
    pthread_mutex_lock(&s_api_mutex);
    memset(&s_api_registry, 0, sizeof(s_api_registry));
    s_api_initialized = false;
    s_api_registered = false;
    log_it(L_INFO, "Network API registry deinitialized");
    pthread_mutex_unlock(&s_api_mutex);
}

/**
 * @brief Register network API functions
 */
int dap_chain_net_api_register(const dap_chain_net_api_registry_t *a_registry)
{
    if (!a_registry) {
        log_it(L_ERROR, "Attempted to register NULL registry");
        return -1;
    }
    
    pthread_mutex_lock(&s_api_mutex);
    
    if (!s_api_initialized) {
        log_it(L_ERROR, "API registry not initialized before registration");
        pthread_mutex_unlock(&s_api_mutex);
        return -2;
    }
    
    if (s_api_registered) {
        log_it(L_WARNING, "API registry already registered - overwriting");
    }
    
    // Copy all function pointers
    memcpy(&s_api_registry, a_registry, sizeof(s_api_registry));
    s_api_registered = true;
    
    log_it(L_INFO, "Network API functions registered successfully");
    pthread_mutex_unlock(&s_api_mutex);
    return 0;
}

/**
 * @brief Core network lookup and accessor functions implementation
 */

dap_chain_net_t *dap_chain_net_api_by_id(dap_chain_net_id_t a_id)
{
    pthread_mutex_lock(&s_api_mutex);
    if (!s_api_registered || !s_api_registry.by_id) {
        log_it(L_ERROR, "Network API function 'by_id' not registered");
        pthread_mutex_unlock(&s_api_mutex);
        return NULL;
    }
    dap_chain_net_t *result = s_api_registry.by_id(a_id);
    pthread_mutex_unlock(&s_api_mutex);
    return result;
}

dap_chain_net_t *dap_chain_net_api_by_name(const char *a_name)
{
    pthread_mutex_lock(&s_api_mutex);
    if (!s_api_registered || !s_api_registry.by_name) {
        log_it(L_ERROR, "Network API function 'by_name' not registered");
        pthread_mutex_unlock(&s_api_mutex);
        return NULL;
    }
    dap_chain_net_t *result = s_api_registry.by_name(a_name);
    pthread_mutex_unlock(&s_api_mutex);
    return result;
}

dap_chain_t *dap_chain_net_api_get_chain_by_name(dap_chain_net_t *a_net, const char *a_name)
{
    pthread_mutex_lock(&s_api_mutex);
    if (!s_api_registered || !s_api_registry.get_chain_by_name) {
        log_it(L_ERROR, "Network API function 'get_chain_by_name' not registered");
        pthread_mutex_unlock(&s_api_mutex);
        return NULL;
    }
    dap_chain_t *result = s_api_registry.get_chain_by_name(a_net, a_name);
    pthread_mutex_unlock(&s_api_mutex);
    return result;
}

dap_chain_t *dap_chain_net_api_get_chain_by_type(dap_chain_net_t *a_net, dap_chain_type_t a_type)
{
    pthread_mutex_lock(&s_api_mutex);
    if (!s_api_registered || !s_api_registry.get_chain_by_type) {
        log_it(L_ERROR, "Network API function 'get_chain_by_type' not registered");
        pthread_mutex_unlock(&s_api_mutex);
        return NULL;
    }
    dap_chain_t *result = s_api_registry.get_chain_by_type(a_net, a_type);
    pthread_mutex_unlock(&s_api_mutex);
    return result;
}

dap_chain_t *dap_chain_net_api_get_default_chain_by_type(dap_chain_net_t *a_net, dap_chain_type_t a_type)
{
    pthread_mutex_lock(&s_api_mutex);
    if (!s_api_registered || !s_api_registry.get_default_chain_by_type) {
        log_it(L_ERROR, "Network API function 'get_default_chain_by_type' not registered");
        pthread_mutex_unlock(&s_api_mutex);
        return NULL;
    }
    dap_chain_t *result = s_api_registry.get_default_chain_by_type(a_net, a_type);
    pthread_mutex_unlock(&s_api_mutex);
    return result;
}

dap_chain_cell_id_t *dap_chain_net_api_get_cur_cell(dap_chain_net_t *a_net)
{
    pthread_mutex_lock(&s_api_mutex);
    if (!s_api_registered || !s_api_registry.get_cur_cell) {
        log_it(L_ERROR, "Network API function 'get_cur_cell' not registered");
        pthread_mutex_unlock(&s_api_mutex);
        return NULL;
    }
    dap_chain_cell_id_t *result = s_api_registry.get_cur_cell(a_net);
    pthread_mutex_unlock(&s_api_mutex);
    return result;
}

bool dap_chain_net_api_get_load_mode(dap_chain_net_t *a_net)
{
    pthread_mutex_lock(&s_api_mutex);
    if (!s_api_registered || !s_api_registry.get_load_mode) {
        log_it(L_ERROR, "Network API function 'get_load_mode' not registered");
        pthread_mutex_unlock(&s_api_mutex);
        return false;
    }
    bool result = s_api_registry.get_load_mode(a_net);
    pthread_mutex_unlock(&s_api_mutex);
    return result;
}

uint256_t dap_chain_net_api_get_reward(dap_chain_net_t *a_net, uint64_t a_block_num)
{
    pthread_mutex_lock(&s_api_mutex);
    if (!s_api_registered || !s_api_registry.get_reward) {
        log_it(L_ERROR, "Network API function 'get_reward' not registered");
        pthread_mutex_unlock(&s_api_mutex);
        return uint256_0;
    }
    uint256_t result = s_api_registry.get_reward(a_net, a_block_num);
    pthread_mutex_unlock(&s_api_mutex);
    return result;
}

int dap_chain_net_api_add_reward(dap_chain_net_t *a_net, uint256_t a_reward, uint64_t a_block_num)
{
    pthread_mutex_lock(&s_api_mutex);
    if (!s_api_registered || !s_api_registry.add_reward) {
        log_it(L_ERROR, "Network API function 'add_reward' not registered");
        pthread_mutex_unlock(&s_api_mutex);
        return -1;
    }
    int result = s_api_registry.add_reward(a_net, a_reward, a_block_num);
    pthread_mutex_unlock(&s_api_mutex);
    return result;
}

char *dap_chain_net_api_datum_add_to_mempool(const dap_chain_datum_t *a_datum, dap_chain_t *a_chain, const char *a_hash_out_type)
{
    pthread_mutex_lock(&s_api_mutex);
    if (!s_api_registered || !s_api_registry.datum_add_to_mempool) {
        log_it(L_ERROR, "Network API function 'datum_add_to_mempool' not registered");
        pthread_mutex_unlock(&s_api_mutex);
        return NULL;
    }
    char *result = s_api_registry.datum_add_to_mempool(a_datum, a_chain, a_hash_out_type);
    pthread_mutex_unlock(&s_api_mutex);
    return result;
}





