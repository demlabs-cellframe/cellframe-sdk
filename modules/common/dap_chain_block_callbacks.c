/*
 * Authors:
 * Cellframe Development Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 */

#include <pthread.h>
#include "dap_chain_block_callbacks.h"
#include "dap_common.h"

#define LOG_TAG "dap_chain_block_callbacks"

// Global callback registry (protected by mutex)
static dap_chain_sovereign_tax_callback_t s_sovereign_tax_callback = NULL;
static pthread_mutex_t s_callback_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief Initialize block callbacks registry
 */
int dap_chain_block_callbacks_init(void)
{
    log_it(L_NOTICE, "Block callbacks registry initialized");
    return 0;
}

/**
 * @brief Deinitialize block callbacks registry
 */
void dap_chain_block_callbacks_deinit(void)
{
    pthread_mutex_lock(&s_callback_mutex);
    s_sovereign_tax_callback = NULL;
    pthread_mutex_unlock(&s_callback_mutex);
    log_it(L_NOTICE, "Block callbacks registry deinitialized");
}

/**
 * @brief Register sovereign tax callback (called by stake service)
 */
void dap_chain_block_callbacks_register_sovereign_tax(dap_chain_sovereign_tax_callback_t a_callback)
{
    pthread_mutex_lock(&s_callback_mutex);
    s_sovereign_tax_callback = a_callback;
    pthread_mutex_unlock(&s_callback_mutex);
    log_it(L_INFO, "Sovereign tax callback registered: %p", a_callback);
}

/**
 * @brief Get sovereign tax info (calls registered callback)
 */
dap_chain_sovereign_tax_info_t* dap_chain_block_callbacks_get_sovereign_tax(
    dap_chain_net_id_t a_net_id,
    dap_hash_fast_t *a_pkey_hash
)
{
    if (!a_pkey_hash)
        return NULL;
    
    dap_chain_sovereign_tax_callback_t l_callback = NULL;
    pthread_mutex_lock(&s_callback_mutex);
    l_callback = s_sovereign_tax_callback;
    pthread_mutex_unlock(&s_callback_mutex);
    
    if (!l_callback) {
        // No callback registered - no tax applies (normal for non-stake networks)
        return NULL;
    }
    
    return l_callback(a_net_id, a_pkey_hash);
}


