/**
 * @file dap_chain_rpc_callbacks.c
 * @brief RPC Callback Registry implementation
 * @details Thread-safe implementation of callback registry
 *          
 * @author Cellframe Team
 * @date 2025-12-15
 * 
 * @note Phase 5.3 - Архитектурный рефакторинг для устранения циклических зависимостей
 */

#include <string.h>
#include "dap_chain_rpc_callbacks.h"
#include "dap_common.h"

#define LOG_TAG "dap_chain_rpc_callbacks"

// Global callback registry
static dap_chain_rpc_callbacks_t s_callbacks = {0};
static bool s_initialized = false;

/**
 * @brief Инициализация callback registry
 */
int dap_chain_rpc_callbacks_init(void)
{
    if (s_initialized) {
        log_it(L_WARNING, "RPC callbacks already initialized");
        return 0;
    }
    
    memset(&s_callbacks, 0, sizeof(s_callbacks));
    
    // Initialize rwlock for thread safety
    if (pthread_rwlock_init(&s_callbacks.rwlock, NULL) != 0) {
        log_it(L_ERROR, "Failed to initialize rwlock for RPC callbacks");
        return -1;
    }
    
    s_initialized = true;
    log_it(L_NOTICE, "RPC callbacks initialized successfully");
    return 0;
}

/**
 * @brief Деинициализация callback registry
 */
void dap_chain_rpc_callbacks_deinit(void)
{
    if (!s_initialized) {
        return;
    }
    
    pthread_rwlock_destroy(&s_callbacks.rwlock);
    memset(&s_callbacks, 0, sizeof(s_callbacks));
    s_initialized = false;
    
    log_it(L_NOTICE, "RPC callbacks deinitialized");
}

/**
 * @brief Регистрация consensus callback
 */
int dap_chain_rpc_callbacks_register_consensus(
    dap_chain_rpc_consensus_callback_t callback,
    void *user_data)
{
    if (!s_initialized) {
        log_it(L_ERROR, "RPC callbacks not initialized");
        return -1;
    }
    
    if (!callback) {
        log_it(L_ERROR, "NULL consensus callback");
        return -2;
    }
    
    pthread_rwlock_wrlock(&s_callbacks.rwlock);
    
    if (s_callbacks.consensus_callback) {
        log_it(L_WARNING, "Consensus callback already registered, replacing");
    }
    
    s_callbacks.consensus_callback = callback;
    s_callbacks.consensus_user_data = user_data;
    
    pthread_rwlock_unlock(&s_callbacks.rwlock);
    
    log_it(L_NOTICE, "Consensus callback registered");
    return 0;
}

/**
 * @brief Вызов consensus callback
 */
int dap_chain_rpc_callbacks_notify_consensus(dap_chain_rpc_consensus_params_t *params)
{
    if (!s_initialized) {
        log_it(L_ERROR, "RPC callbacks not initialized");
        return -1;
    }
    
    if (!params) {
        log_it(L_ERROR, "NULL params for consensus callback");
        return -2;
    }
    
    pthread_rwlock_rdlock(&s_callbacks.rwlock);
    
    if (!s_callbacks.consensus_callback) {
        pthread_rwlock_unlock(&s_callbacks.rwlock);
        log_it(L_WARNING, "Consensus callback not registered");
        return -3;
    }
    
    int result = s_callbacks.consensus_callback(params, s_callbacks.consensus_user_data);
    
    pthread_rwlock_unlock(&s_callbacks.rwlock);
    
    return result;
}

/**
 * @brief Регистрация storage type callback
 */
int dap_chain_rpc_callbacks_register_storage(
    dap_chain_rpc_storage_callback_t callback,
    void *user_data)
{
    if (!s_initialized) {
        log_it(L_ERROR, "RPC callbacks not initialized");
        return -1;
    }
    
    if (!callback) {
        log_it(L_ERROR, "NULL storage callback");
        return -2;
    }
    
    pthread_rwlock_wrlock(&s_callbacks.rwlock);
    
    if (s_callbacks.storage_callback) {
        log_it(L_WARNING, "Storage callback already registered, replacing");
    }
    
    s_callbacks.storage_callback = callback;
    s_callbacks.storage_user_data = user_data;
    
    pthread_rwlock_unlock(&s_callbacks.rwlock);
    
    log_it(L_NOTICE, "Storage callback registered");
    return 0;
}

/**
 * @brief Вызов storage type callback
 */
int dap_chain_rpc_callbacks_notify_storage(dap_chain_rpc_storage_params_t *params)
{
    if (!s_initialized) {
        log_it(L_ERROR, "RPC callbacks not initialized");
        return -1;
    }
    
    if (!params) {
        log_it(L_ERROR, "NULL params for storage callback");
        return -2;
    }
    
    pthread_rwlock_rdlock(&s_callbacks.rwlock);
    
    if (!s_callbacks.storage_callback) {
        pthread_rwlock_unlock(&s_callbacks.rwlock);
        log_it(L_WARNING, "Storage callback not registered");
        return -3;
    }
    
    int result = s_callbacks.storage_callback(params, s_callbacks.storage_user_data);
    
    pthread_rwlock_unlock(&s_callbacks.rwlock);
    
    return result;
}

/**
 * @brief Регистрация service callback
 */
int dap_chain_rpc_callbacks_register_service(
    dap_chain_rpc_service_callback_t callback,
    void *user_data)
{
    if (!s_initialized) {
        log_it(L_ERROR, "RPC callbacks not initialized");
        return -1;
    }
    
    if (!callback) {
        log_it(L_ERROR, "NULL service callback");
        return -2;
    }
    
    pthread_rwlock_wrlock(&s_callbacks.rwlock);
    
    if (s_callbacks.service_callback) {
        log_it(L_WARNING, "Service callback already registered, replacing");
    }
    
    s_callbacks.service_callback = callback;
    s_callbacks.service_user_data = user_data;
    
    pthread_rwlock_unlock(&s_callbacks.rwlock);
    
    log_it(L_NOTICE, "Service callback registered");
    return 0;
}

/**
 * @brief Вызов service callback
 */
int dap_chain_rpc_callbacks_notify_service(dap_chain_rpc_service_params_t *params)
{
    if (!s_initialized) {
        log_it(L_ERROR, "RPC callbacks not initialized");
        return -1;
    }
    
    if (!params) {
        log_it(L_ERROR, "NULL params for service callback");
        return -2;
    }
    
    pthread_rwlock_rdlock(&s_callbacks.rwlock);
    
    if (!s_callbacks.service_callback) {
        pthread_rwlock_unlock(&s_callbacks.rwlock);
        log_it(L_WARNING, "Service callback not registered");
        return -3;
    }
    
    int result = s_callbacks.service_callback(params, s_callbacks.service_user_data);
    
    pthread_rwlock_unlock(&s_callbacks.rwlock);
    
    return result;
}

/**
 * @brief Регистрация wallet callback
 */
int dap_chain_rpc_callbacks_register_wallet(
    dap_chain_rpc_wallet_callback_t callback,
    void *user_data)
{
    if (!s_initialized) {
        log_it(L_ERROR, "RPC callbacks not initialized");
        return -1;
    }
    
    if (!callback) {
        log_it(L_ERROR, "NULL wallet callback");
        return -2;
    }
    
    pthread_rwlock_wrlock(&s_callbacks.rwlock);
    
    if (s_callbacks.wallet_callback) {
        log_it(L_WARNING, "Wallet callback already registered, replacing");
    }
    
    s_callbacks.wallet_callback = callback;
    s_callbacks.wallet_user_data = user_data;
    
    pthread_rwlock_unlock(&s_callbacks.rwlock);
    
    log_it(L_NOTICE, "Wallet callback registered");
    return 0;
}

/**
 * @brief Вызов wallet callback
 */
int dap_chain_rpc_callbacks_notify_wallet(dap_chain_rpc_wallet_params_t *params)
{
    if (!s_initialized) {
        log_it(L_ERROR, "RPC callbacks not initialized");
        return -1;
    }
    
    if (!params) {
        log_it(L_ERROR, "NULL params for wallet callback");
        return -2;
    }
    
    pthread_rwlock_rdlock(&s_callbacks.rwlock);
    
    if (!s_callbacks.wallet_callback) {
        pthread_rwlock_unlock(&s_callbacks.rwlock);
        log_it(L_WARNING, "Wallet callback not registered");
        return -3;
    }
    
    int result = s_callbacks.wallet_callback(params, s_callbacks.wallet_user_data);
    
    pthread_rwlock_unlock(&s_callbacks.rwlock);
    
    return result;
}

/**
 * @brief Регистрация TX notification callback
 */
int dap_chain_rpc_callbacks_register_tx_notify(
    dap_chain_rpc_tx_notify_callback_t callback,
    void *user_data)
{
    if (!s_initialized) {
        log_it(L_ERROR, "RPC callbacks not initialized");
        return -1;
    }
    
    if (!callback) {
        log_it(L_ERROR, "NULL TX notify callback");
        return -2;
    }
    
    pthread_rwlock_wrlock(&s_callbacks.rwlock);
    
    if (s_callbacks.tx_notify_callback) {
        log_it(L_WARNING, "TX notify callback already registered, replacing");
    }
    
    s_callbacks.tx_notify_callback = callback;
    s_callbacks.tx_notify_user_data = user_data;
    
    pthread_rwlock_unlock(&s_callbacks.rwlock);
    
    log_it(L_NOTICE, "TX notify callback registered");
    return 0;
}

/**
 * @brief Вызов TX notification callback
 */
void dap_chain_rpc_callbacks_notify_tx(dap_chain_rpc_tx_notify_params_t *params)
{
    if (!s_initialized) {
        log_it(L_ERROR, "RPC callbacks not initialized");
        return;
    }
    
    if (!params) {
        log_it(L_ERROR, "NULL params for TX notify callback");
        return;
    }
    
    pthread_rwlock_rdlock(&s_callbacks.rwlock);
    
    if (!s_callbacks.tx_notify_callback) {
        pthread_rwlock_unlock(&s_callbacks.rwlock);
        // TX notifications are optional, don't log warning
        return;
    }
    
    s_callbacks.tx_notify_callback(params, s_callbacks.tx_notify_user_data);
    
    pthread_rwlock_unlock(&s_callbacks.rwlock);
}
