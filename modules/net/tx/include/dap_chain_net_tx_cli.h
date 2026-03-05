/*
 * Authors:
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2019-2026
 * All rights reserved.
 *
 * TX-related CLI commands that require net/wallet/mempool access.
 * These live in net/tx module to respect the dependency hierarchy:
 *   dap-sdk → chain → datum → ledger → net → net/tx (this module)
 *
 * Commands registered here:
 *   tx_create, tx_create_json, tx_history, tx_verify,
 *   tx_cond_create, tx_cond_remove, tx_cond_unspent_find, mempool_add
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

int dap_chain_net_tx_cli_init(void);
void dap_chain_net_tx_cli_deinit(void);

#ifdef __cplusplus
}
#endif
