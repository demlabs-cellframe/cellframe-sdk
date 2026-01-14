/*
 * Authors:
 * Dmitriy Gerasimov <naeper@demlabs.net>
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 *
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

#include "dap_chain_common.h"
#include "dap_chain_datum_decree.h"

// Forward declarations
typedef struct dap_chain dap_chain_t;
typedef struct dap_ledger dap_ledger_t;

/**
 * @brief Universal decree handler callback
 * @details Each module (net, stake, esbocs, etc.) registers handlers for decree types it processes.
 *          Handler has access to all context it needs via a_decree, a_ledger, a_chain.
 * 
 * @param a_decree The decree to process
 * @param a_ledger Ledger where decree is being applied
 * @param a_chain Chain where decree is applied (may be NULL for network-wide decrees)
 * @param a_apply If true - apply changes, if false - verify only
 * @return 0 on success, negative error code otherwise
 */
typedef int (*dap_chain_decree_handler_t)(dap_chain_datum_decree_t *a_decree, 
                                          dap_ledger_t *a_ledger,
                                          dap_chain_t *a_chain,
                                          bool a_apply);

/**
 * @brief Register decree handler for specific type/subtype
 * @details Each module (stake, esbocs, etc.) registers handlers for decree types it processes.
 *          Multiple modules can register for different types/subtypes.
 * 
 * @param a_decree_type Main decree type (COMMON or SERVICE)
 * @param a_decree_subtype Specific subtype within that type
 * @param a_handler Callback to handle this decree type/subtype
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_decree_handler_register(uint16_t a_decree_type, 
                                      uint16_t a_decree_subtype,
                                      dap_chain_decree_handler_t a_handler);

/**
 * @brief Find and call registered handler for given decree type/subtype
 * @return 0 on success, -1 if no handler found, or handler's error code
 */
int dap_chain_decree_handler_call(uint16_t a_decree_type,
                                  uint16_t a_decree_subtype,
                                  dap_chain_datum_decree_t *a_decree,
                                  dap_ledger_t *a_ledger,
                                  dap_chain_t *a_chain,
                                  bool a_apply);
