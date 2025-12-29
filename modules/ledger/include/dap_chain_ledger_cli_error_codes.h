/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024
 * All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

/**
 * @brief Register ledger CLI error codes
 * 
 * Should be called during ledger CLI initialization to register
 * all error codes used by ledger commands.
 */
void dap_chain_ledger_cli_error_codes_init(void);

// Error code helpers - use these macros to get registered codes
#define DAP_LEDGER_CLI_ERROR(name) dap_cli_error_code_get("LEDGER_" #name)

