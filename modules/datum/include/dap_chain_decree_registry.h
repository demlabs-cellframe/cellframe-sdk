/*
 * Authors:
 * Daniil Frolov <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright (c) 2025, All rights reserved.
 *
 * This file is part of CellFrame SDK the open source project
 *
 *    CellFrame SDK is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    CellFrame SDK is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "dap_common.h"
#include "dap_chain_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations to avoid circular dependencies
typedef struct dap_chain_datum_decree dap_chain_datum_decree_t;
typedef struct dap_chain_net dap_chain_net_t;

/**
 * @brief Decree handler callback function type
 * 
 * @param a_decree Decree datum to process
 * @param a_net Network context
 * @param a_apply Whether to apply changes (true) or just validate (false)
 * @param a_anchored Whether decree is already anchored in ledger
 * @return 0 on success, negative error code on failure
 */
typedef int (*dap_chain_decree_handler_callback_t)(
    dap_chain_datum_decree_t *a_decree,
    dap_chain_net_t *a_net,
    bool a_apply,
    bool a_anchored
);

/**
 * @brief Initialize the decree registry system
 * 
 * Must be called before any decree processing.
 * @return 0 on success, negative on error
 */
int dap_chain_decree_registry_init(void);

/**
 * @brief Deinitialize and cleanup decree registry
 */
void dap_chain_decree_registry_deinit(void);

/**
 * @brief Register a handler for a specific decree subtype
 * 
 * @param a_decree_type Decree type (COMMON or SERVICE)
 * @param a_decree_subtype Decree subtype identifier
 * @param a_handler Handler callback function
 * @param a_handler_name Human-readable handler name for logging
 * @return 0 on success, negative on error
 */
int dap_chain_decree_registry_register_handler(
    uint16_t a_decree_type,
    uint16_t a_decree_subtype,
    dap_chain_decree_handler_callback_t a_handler,
    const char *a_handler_name
);

/**
 * @brief Unregister a handler for a specific decree subtype
 * 
 * @param a_decree_type Decree type (COMMON or SERVICE)
 * @param a_decree_subtype Decree subtype identifier
 * @return 0 on success, negative on error
 */
int dap_chain_decree_registry_unregister_handler(
    uint16_t a_decree_type,
    uint16_t a_decree_subtype
);

/**
 * @brief Process a decree through the registered handler
 * 
 * Finds appropriate handler and invokes it with given parameters.
 * 
 * @param a_decree Decree datum to process
 * @param a_net Network context
 * @param a_apply Whether to apply changes (true) or just validate (false)
 * @param a_anchored Whether decree is already anchored in ledger
 * @return Handler return code (0 on success, negative on error)
 *         -404 if no handler registered for this decree type/subtype
 */
int dap_chain_decree_registry_process(
    dap_chain_datum_decree_t *a_decree,
    dap_chain_net_t *a_net,
    bool a_apply,
    bool a_anchored
);

/**
 * @brief Check if a handler is registered for given decree type/subtype
 * 
 * @param a_decree_type Decree type (COMMON or SERVICE)
 * @param a_decree_subtype Decree subtype identifier
 * @return true if handler exists, false otherwise
 */
bool dap_chain_decree_registry_has_handler(
    uint16_t a_decree_type,
    uint16_t a_decree_subtype
);

#ifdef __cplusplus
}
#endif
