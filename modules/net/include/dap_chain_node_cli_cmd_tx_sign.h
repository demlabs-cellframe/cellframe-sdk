/*
 * Authors:
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network  https://github.com/demlabs-cellframe
 * Copyright  (c) 2024
 * All rights reserved.
 *
 * This file is part of DAP (Distributed Applications Platform) the open source project
 *
 * DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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

#include "dap_chain_node_cli_cmd.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Add signatures to existing arbitrage transaction in mempool
 * com_tx_sign command
 * @param argc
 * @param argv
 * @param str_reply
 * @param version
 * @return int
 */
int com_tx_sign(int a_argc, char **a_argv, void **a_str_reply, int a_version);

#ifdef __cplusplus
}
#endif

