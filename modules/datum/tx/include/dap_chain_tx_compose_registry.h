/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
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

#include "dap_chain_tx_compose_api.h"
#include "dap_ht.h"

/**
 * @file dap_chain_tx_compose_registry.h
 * @brief Internal registry for TX Compose callbacks
 * 
 * ARCHITECTURE: Hash table registry for O(1) lookup
 * 
 * НЕ ИСПОЛЬЗУЙТЕ ЭТОТ HEADER В EXTERNAL МОДУЛЯХ!
 * Только для внутреннего использования в datum/tx модуле.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Registry entry for TX builder callback
 */
typedef struct dap_chain_tx_compose_registry_entry {
    char *tx_type;                              // Key for hash table
    dap_chain_tx_compose_callback_t callback;   // Builder function
    void *user_data;                             // Optional user data
    dap_ht_handle_t hh;
} dap_chain_tx_compose_registry_entry_t;

/**
 * @brief Internal registry functions
 */

/**
 * @brief Initialize registry (called by dap_chain_tx_compose_init)
 */
int dap_chain_tx_compose_registry_init(void);

/**
 * @brief Deinit registry (called by dap_chain_tx_compose_deinit)
 */
void dap_chain_tx_compose_registry_deinit(void);

/**
 * @brief Add entry to registry
 */
int dap_chain_tx_compose_registry_add(
    const char *a_tx_type,
    dap_chain_tx_compose_callback_t a_callback,
    void *a_user_data
);

/**
 * @brief Remove entry from registry
 */
void dap_chain_tx_compose_registry_remove(const char *a_tx_type);

/**
 * @brief Find entry in registry
 * @return Entry or NULL if not found
 */
dap_chain_tx_compose_registry_entry_t* dap_chain_tx_compose_registry_find(
    const char *a_tx_type
);

#ifdef __cplusplus
}
#endif

