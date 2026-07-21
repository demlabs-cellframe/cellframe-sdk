/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.
 */

#pragma once

#include "dap_json.h"
#include "dap_chain_ledger.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Token info CLI command
 *
 * Queries token info (decimals, type, supply, etc.) from the ledger.
 * Usage: ledger token info -net <network> -token <ticker>
 *
 * Response JSON includes:
 *   - token_name, subtype, decimals, supply_current, supply_total, etc.
 */
int ledger_cli_token_info(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version);

/**
 * @brief Initialize Token commands module
 */
int dap_chain_ledger_cli_token_init(void);

/**
 * @brief Deinitialize Token commands module
 */
void dap_chain_ledger_cli_token_deinit(void);

#ifdef __cplusplus
}
#endif
