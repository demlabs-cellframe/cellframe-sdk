/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
* DeM Labs Inc.   https://demlabs.net
 * Copyright (c) 2025, All rights reserved.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Register net-tx decree handlers
 * 
 * Registers: fee
 * Called by dap_chain_net_tx_init()
 */
void dap_chain_net_tx_decree_init(void);

/**
 * @brief Unregister net-tx decree handlers
 */
void dap_chain_net_tx_decree_deinit(void);

#ifdef __cplusplus
}
#endif

