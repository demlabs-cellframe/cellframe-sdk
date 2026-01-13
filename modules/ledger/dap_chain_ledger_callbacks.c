/*
 * Authors:
 * Cellframe Team  
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.
 */

#include "dap_chain_ledger_callbacks.h"
#include "dap_common.h"

#define LOG_TAG "dap_ledger_callbacks"

// Global callbacks (all optional, initialized to NULL)
static dap_ledger_callbacks_t s_ledger_callbacks = {
    .addr_to_wallet_name = NULL,
    .wallet_info_to_json = NULL,
    .tx_added = NULL
};

/**
 * @brief Register ledger callbacks
 */
void dap_ledger_callbacks_register(const dap_ledger_callbacks_t *a_callbacks)
{
    if (!a_callbacks) {
        log_it(L_WARNING, "Attempted to register NULL callbacks");
        return;
    }
    
    s_ledger_callbacks = *a_callbacks;
    
    log_it(L_NOTICE, "Ledger callbacks registered: addr_to_wallet=%s, wallet_info=%s, tx_added=%s",
           s_ledger_callbacks.addr_to_wallet_name ? "YES" : "NO",
           s_ledger_callbacks.wallet_info_to_json ? "YES" : "NO",
           s_ledger_callbacks.tx_added ? "YES" : "NO");
}

/**
 * @brief Get current ledger callbacks
 */
const dap_ledger_callbacks_t* dap_ledger_callbacks_get(void)
{
    return &s_ledger_callbacks;
}

