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
 * @brief Chain CLI commands
 * @details Implements chain-related CLI commands: token operations, CA operations
 */

/**
 * @brief Initialize token CLI commands
 * @return 0 on success, negative error code on failure
 */
int dap_chain_token_cli_init(void);

/**
 * @brief Cleanup token CLI
 */
void dap_chain_token_cli_deinit(void);

#ifdef __cplusplus
}
#endif

