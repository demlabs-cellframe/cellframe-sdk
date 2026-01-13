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
 * @brief Internal shared helpers for CLI commands
 * 
 * These are utility functions used across multiple CLI command modules
 */

/**
 * @brief Parse hash output type parameter
 * @param a_argv Command arguments
 * @param a_arg_index Argument index
 * @param a_argc Total argument count
 * @param a_hash_out_type OUT: Parsed hash type ("hex" or "base58")
 * @return 0 on success, error code on failure
 */
int cli_parse_hash_out_type(char **a_argv, int a_arg_index, int a_argc, const char **a_hash_out_type);

/**
 * @brief Get ledger by network name
 * @param a_net_name Network name
 * @param a_json_arr_reply JSON reply array for errors
 * @return Ledger pointer or NULL
 */
dap_ledger_t* cli_get_ledger_by_net_name(const char *a_net_name, dap_json_t *a_json_arr_reply);

/**
 * @brief Validate and parse pagination parameters
 * @param a_argv Command arguments
 * @param a_argc Total argument count
 * @param a_limit OUT: Limit value
 * @param a_offset OUT: Offset value
 * @return 0 on success, error code on failure
 */
int cli_parse_pagination(char **a_argv, int a_argc, size_t *a_limit, size_t *a_offset);

#ifdef __cplusplus
}
#endif

