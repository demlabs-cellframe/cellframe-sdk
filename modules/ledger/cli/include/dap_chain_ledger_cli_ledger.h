/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2019-2025
 * All rights reserved.
 *
 * This file is part of DAP (Distributed Applications Platform) the open source project
 *
 * DAP is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DAP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "dap_json.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Ledger CLI command handler
 * @details Implements 'ledger' CLI command with subcommands:
 *          - list coins|threshold|balance - list ledger entries
 *          - info - get transaction info by hash
 *          - trace - trace transaction chain
 *          - event - manage ledger events
 * 
 * @param a_argc Argument count
 * @param a_argv Argument values
 * @param a_json_arr_reply JSON array for reply
 * @param a_version API version
 * @return 0 on success, error code on failure
 */
int com_ledger(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version);

/**
 * @brief Initialize ledger CLI module
 * @details Registers 'ledger' command with CLI server
 * @return 0 on success, negative error code on failure
 */
int dap_chain_ledger_cli_ledger_init(void);

/**
 * @brief Deinitialize ledger CLI module
 */
void dap_chain_ledger_cli_ledger_deinit(void);

#ifdef __cplusplus
}
#endif
