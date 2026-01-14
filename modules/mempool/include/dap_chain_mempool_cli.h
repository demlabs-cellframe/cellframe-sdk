/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network  https://github.com/demlabs-cellframe
 * Copyright  (c) 2019-2025
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

 DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 DAP is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "dap_json.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Mempool CLI commands
 * @details Implements mempool-related CLI commands: list, proc, delete, etc.
 */

/**
 * @brief Initialize mempool CLI commands
 * @return 0 on success, negative error code on failure
 */
int dap_chain_mempool_cli_init(void);

/**
 * @brief Main mempool CLI command handler
 * @details Main entry point for mempool commands. Can be called from other modules.
 * This function is also exposed as `dap_chain_mempool_cli_command` for API consistency.
 * @param a_argc Argument count
 * @param a_argv Argument vector
 * @param a_json_arr_reply JSON response array
 * @param a_version RPC version
 * @return 0 on success, negative error code on failure
 */
int com_mempool(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version);

// Alias for API consistency
#define dap_chain_mempool_cli_command com_mempool

/**
 * @brief Cleanup mempool CLI
 */
void dap_chain_mempool_cli_deinit(void);

#ifdef __cplusplus
}
#endif

