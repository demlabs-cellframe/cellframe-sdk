/*
 * Authors:
 * Cellframe Development Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 *
 * Validator API implementation
 * Phase 5.4.2: Dependency Inversion - breaks esbocs → stake cycle
 */

#include <pthread.h>
#include "dap_chain_validator_api.h"
#include "dap_common.h"

#define LOG_TAG "dap_chain_validator_api"

// Global API registry (protected by mutex)
static dap_chain_validator_api_registry_t s_validator_api = {0};
static pthread_mutex_t s_api_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool s_api_registered = false;

/**
 * @brief Initialize validator API
 */
int dap_chain_validator_api_init(void)
{
    log_it(L_NOTICE, "Validator API initialized");
    return 0;
}

/**
 * @brief Deinitialize validator API
 */
void dap_chain_validator_api_deinit(void)
{
    pthread_mutex_lock(&s_api_mutex);
    memset(&s_validator_api, 0, sizeof(s_validator_api));
    s_api_registered = false;
    pthread_mutex_unlock(&s_api_mutex);
    log_it(L_NOTICE, "Validator API deinitialized");
}

/**
 * @brief Register validator implementation (called by stake service at init)
 */
void dap_chain_validator_api_register(const dap_chain_validator_api_registry_t *a_registry)
{
    if (!a_registry) {
        log_it(L_ERROR, "Cannot register NULL validator API");
        return;
    }
    
    pthread_mutex_lock(&s_api_mutex);
    s_validator_api = *a_registry;
    s_api_registered = true;
    pthread_mutex_unlock(&s_api_mutex);
    
    log_it(L_INFO, "Validator API implementation registered");
}

// Macro for thread-safe API calls
#define VALIDATOR_API_CALL(func_name, default_ret, ...) \
    pthread_mutex_lock(&s_api_mutex); \
    if (!s_api_registered || !s_validator_api.func_name) { \
        pthread_mutex_unlock(&s_api_mutex); \
        log_it(L_WARNING, "Validator API not registered or function %s is NULL", #func_name); \
        return default_ret; \
    } \
    typeof(s_validator_api.func_name) func_ptr = s_validator_api.func_name; \
    pthread_mutex_unlock(&s_api_mutex); \
    return func_ptr(__VA_ARGS__)

/**
 * @brief Get validators list
 */
dap_list_t* dap_chain_validator_api_get_validators(dap_chain_net_id_t a_net_id, bool a_only_active, uint16_t **a_excluded_list)
{
    VALIDATOR_API_CALL(get_validators, NULL, a_net_id, a_only_active, a_excluded_list);
}

/**
 * @brief Check if key is delegated
 */
int dap_chain_validator_api_check_key_delegated(dap_chain_addr_t *a_signing_addr)
{
    VALIDATOR_API_CALL(check_key_delegated, -1, a_signing_addr);
}

/**
 * @brief Mark validator active/inactive
 */
int dap_chain_validator_api_mark_validator_active(dap_chain_addr_t *a_signing_addr, bool a_active)
{
    VALIDATOR_API_CALL(mark_validator_active, -1, a_signing_addr, a_active);
}

/**
 * @brief Get public key by hash
 */
dap_pkey_t* dap_chain_validator_api_get_pkey_by_hash(dap_chain_net_id_t a_net_id, dap_hash_fast_t *a_hash)
{
    VALIDATOR_API_CALL(get_pkey_by_hash, NULL, a_net_id, a_hash);
}

/**
 * @brief Delegate key
 */
void dap_chain_validator_api_key_delegate(dap_chain_net_t *a_net, dap_chain_addr_t *a_signing_addr,
    dap_hash_fast_t *a_decree_hash, dap_hash_fast_t *a_tx_hash, uint256_t a_value,
    dap_chain_node_addr_t *a_node_addr, dap_pkey_t *a_pkey)
{
    pthread_mutex_lock(&s_api_mutex);
    if (!s_api_registered || !s_validator_api.key_delegate) {
        pthread_mutex_unlock(&s_api_mutex);
        log_it(L_WARNING, "Validator API not registered or key_delegate is NULL");
        return;
    }
    typeof(s_validator_api.key_delegate) func_ptr = s_validator_api.key_delegate;
    pthread_mutex_unlock(&s_api_mutex);
    func_ptr(a_net, a_signing_addr, a_decree_hash, a_tx_hash, a_value, a_node_addr, a_pkey);
}

/**
 * @brief Get minimum allowed value
 */
uint256_t dap_chain_validator_api_get_allowed_min_value(dap_chain_net_id_t a_net_id)
{
    VALIDATOR_API_CALL(get_allowed_min_value, uint256_0, a_net_id);
}

/**
 * @brief Update hardfork TX
 */
void dap_chain_validator_api_hardfork_tx_update(dap_chain_net_t *a_net)
{
    pthread_mutex_lock(&s_api_mutex);
    if (!s_api_registered || !s_validator_api.hardfork_tx_update) {
        pthread_mutex_unlock(&s_api_mutex);
        return;
    }
    typeof(s_validator_api.hardfork_tx_update) func_ptr = s_validator_api.hardfork_tx_update;
    pthread_mutex_unlock(&s_api_mutex);
    func_ptr(a_net);
}

/**
 * @brief Get node address from validator item
 */
dap_stream_node_addr_t* dap_chain_validator_api_get_node_addr(dap_chain_validator_item_t a_item)
{
    VALIDATOR_API_CALL(get_node_addr_from_item, NULL, a_item);
}

/**
 * @brief Get value from validator item
 */
uint256_t dap_chain_validator_api_get_value(dap_chain_validator_item_t a_item)
{
    VALIDATOR_API_CALL(get_value_from_item, uint256_0, a_item);
}


