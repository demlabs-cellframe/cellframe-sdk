/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.
 *
 * This file is part of CellFrame SDK the open source project
 */

#pragma once

#include "dap_json.h"
#include "dap_chain_ledger.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Token commands module
 * 
 * Handles token-related CLI commands:
 * - token list: List all tokens in network
 * - token info: Show detailed token information
 */

/**
 * @brief Main token command handler
 * @details Dispatches to list/info/tx subcommands
 * @param a_argc Argument count
 * @param a_argv Argument values
 * @param a_json_arr_reply JSON array for reply
 * @param a_version API version
 * @return 0 on success, negative error code on failure
 */
int com_token(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version);

/**
 * @brief Initialize token commands module
 * @details Registers token subcommands with CLI registry
 * @return 0 on success, negative error code on failure
 */
int dap_chain_ledger_cli_token_init(void);

/**
 * @brief Deinitialize token commands module
 */
void dap_chain_ledger_cli_token_deinit(void);

#ifdef __cplusplus
}
#endif
