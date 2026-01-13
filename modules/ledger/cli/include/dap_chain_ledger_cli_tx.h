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
 * @brief TX commands module
 * 
 * Handles all transaction-related CLI commands using the new TX Compose API
 */

/**
 * @brief tx create - Create transaction using TX Compose API
 */
int ledger_cli_tx_create(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version);

/**
 * @brief tx create_json - Create transaction from JSON using TX Compose API
 */
int ledger_cli_tx_create_json(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version);

/**
 * @brief tx verify - Verify transaction
 */
int ledger_cli_tx_verify(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version);

/**
 * @brief tx history - Show transaction history
 */
int ledger_cli_tx_history(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version);

/**
 * @brief Initialize TX commands module
 */
int dap_chain_ledger_cli_tx_init(void);

/**
 * @brief Deinitialize TX commands module
 */
void dap_chain_ledger_cli_tx_deinit(void);

#ifdef __cplusplus
}
#endif

