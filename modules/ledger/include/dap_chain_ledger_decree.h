/*
 * Authors:
 * Daniil Frolov <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright (c) 2025, All rights reserved.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Register ledger decree handlers
 * 
 * Registers: owners, owners_min, event_pkey_add, event_pkey_remove
 * Called by dap_ledger_init()
 */
void dap_chain_ledger_decree_init(void);

/**
 * @brief Unregister ledger decree handlers
 */
void dap_chain_ledger_decree_deinit(void);

#ifdef __cplusplus
}
#endif
