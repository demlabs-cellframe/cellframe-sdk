/*
 * Authors:
 * Dmitriy Gerasimov <naeper@demlabs.net>
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
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

/**
 * @file dap_chain_net_api.h
 * @brief Core Network API - Phase 5.3 Architectural Refactoring
 * @details This module provides core network lookup and accessor functions
 *          that are needed by mid-level modules (blocks, esbocs, stake) to break
 *          cyclic dependencies with the high-level net module.
 *
 * ARCHITECTURAL NOTE (Phase 5.3):
 * - This API layer breaks cycles by providing essential net functions without
 *   requiring full net module dependencies
 * - Follows SLC methodology: Type Extraction + API Layering pattern
 * - Implementation delegates to actual net module (inversion of control)
 * - Lower-level modules include THIS header instead of full dap_chain_net.h
 *
 * DESIGN PRINCIPLES:
 * - Thin wrapper API only (no business logic here)
 * - Functions registered at runtime by net module (dependency injection)
 * - Thread-safe function pointer registry
 * - Zero overhead when functions are registered
 */

#include <stdint.h>
#include <stdbool.h>
#include "dap_chain_net_types.h"
#include "dap_chain_common.h"
#include "dap_math_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Core network lookup function types
 * @details These function pointers will be set by net module at initialization
 */
typedef dap_chain_net_t *(*dap_chain_net_by_id_func_t)(dap_chain_net_id_t a_id);
typedef dap_chain_net_t *(*dap_chain_net_by_name_func_t)(const char *a_name);
typedef dap_chain_t *(*dap_chain_net_get_chain_by_name_func_t)(dap_chain_net_t *a_net, const char *a_name);
typedef dap_chain_t *(*dap_chain_net_get_chain_by_chain_type_func_t)(dap_chain_net_t *a_net, dap_chain_type_t a_type);
typedef dap_chain_t *(*dap_chain_net_get_default_chain_by_chain_type_func_t)(dap_chain_net_t *a_net, dap_chain_type_t a_type);
typedef dap_chain_cell_id_t *(*dap_chain_net_get_cur_cell_func_t)(dap_chain_net_t *a_net);
typedef bool (*dap_chain_net_get_load_mode_func_t)(dap_chain_net_t *a_net);
typedef uint256_t (*dap_chain_net_get_reward_func_t)(dap_chain_net_t *a_net, uint64_t a_block_num);
typedef int (*dap_chain_net_add_reward_func_t)(dap_chain_net_t *a_net, uint256_t a_reward, uint64_t a_block_num);

/**
 * @brief Network API function registry
 * @details Net module registers its implementations here at init time
 */
typedef struct dap_chain_net_api_registry {
    dap_chain_net_by_id_func_t by_id;
    dap_chain_net_by_name_func_t by_name;
    dap_chain_net_get_chain_by_name_func_t get_chain_by_name;
    dap_chain_net_get_chain_by_chain_type_func_t get_chain_by_type;
    dap_chain_net_get_default_chain_by_chain_type_func_t get_default_chain_by_type;
    dap_chain_net_get_cur_cell_func_t get_cur_cell;
    dap_chain_net_get_load_mode_func_t get_load_mode;
    dap_chain_net_get_reward_func_t get_reward;
    dap_chain_net_add_reward_func_t add_reward;
} dap_chain_net_api_registry_t;

/**
 * @brief Initialize network API registry
 * @details Called once at common module initialization
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_api_init(void);

/**
 * @brief Deinitialize network API registry
 */
void dap_chain_net_api_deinit(void);

/**
 * @brief Register network API functions (called by net module)
 * @param a_registry Pointer to filled registry structure
 * @return 0 on success, negative error code otherwise
 *
 * USAGE (in net module init):
 *   dap_chain_net_api_registry_t l_registry = {
 *       .by_id = dap_chain_net_by_id_impl,
 *       .by_name = dap_chain_net_by_name_impl,
 *       // ... other functions
 *   };
 *   dap_chain_net_api_register(&l_registry);
 */
int dap_chain_net_api_register(const dap_chain_net_api_registry_t *a_registry);

/**
 * @brief Core network lookup and accessor functions (PUBLIC API)
 * @details These are the functions that mid-level modules should use
 *          instead of including full dap_chain_net.h
 */

/**
 * @brief Get network by ID
 * @param a_id Network ID
 * @return Network structure or NULL if not found
 */
dap_chain_net_t *dap_chain_net_api_by_id(dap_chain_net_id_t a_id);

/**
 * @brief Get network by name
 * @param a_name Network name
 * @return Network structure or NULL if not found
 */
dap_chain_net_t *dap_chain_net_api_by_name(const char *a_name);

/**
 * @brief Get chain by name from network
 * @param a_net Network structure
 * @param a_name Chain name
 * @return Chain structure or NULL if not found
 */
dap_chain_t *dap_chain_net_api_get_chain_by_name(dap_chain_net_t *a_net, const char *a_name);

/**
 * @brief Get chain by type from network
 * @param a_net Network structure
 * @param a_type Chain type
 * @return Chain structure or NULL if not found
 */
dap_chain_t *dap_chain_net_api_get_chain_by_type(dap_chain_net_t *a_net, dap_chain_type_t a_type);

/**
 * @brief Get default chain by type from network
 * @param a_net Network structure
 * @param a_type Chain type
 * @return Default chain structure or NULL if not found
 */
dap_chain_t *dap_chain_net_api_get_default_chain_by_type(dap_chain_net_t *a_net, dap_chain_type_t a_type);

/**
 * @brief Get current cell ID from network
 * @param a_net Network structure
 * @return Current cell ID pointer or NULL
 */
dap_chain_cell_id_t *dap_chain_net_api_get_cur_cell(dap_chain_net_t *a_net);

/**
 * @brief Get load mode status of network
 * @param a_net Network structure
 * @return true if in load mode, false otherwise
 */
bool dap_chain_net_api_get_load_mode(dap_chain_net_t *a_net);

/**
 * @brief Get reward for block number
 * @param a_net Network structure
 * @param a_block_num Block number
 * @return Reward value (uint256_t)
 */
uint256_t dap_chain_net_api_get_reward(dap_chain_net_t *a_net, uint64_t a_block_num);

/**
 * @brief Add reward to network
 * @param a_net Network structure
 * @param a_reward Reward value
 * @param a_block_num Block number
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_api_add_reward(dap_chain_net_t *a_net, uint256_t a_reward, uint64_t a_block_num);

/**
 * @brief Direct accessors for public network fields
 * @details These accessors work directly on public structure fields
 *          without needing function registration (zero overhead)
 */
#define DAP_CHAIN_NET_API_GET_ID(net)           ((net)->pub.id)
#define DAP_CHAIN_NET_API_GET_NAME(net)         ((net)->pub.name)
#define DAP_CHAIN_NET_API_GET_LEDGER(net)       ((net)->pub.ledger)
#define DAP_CHAIN_NET_API_GET_CHAINS(net)       ((net)->pub.chains)
#define DAP_CHAIN_NET_API_GET_FEE_VALUE(net)    ((net)->pub.fee_value)
#define DAP_CHAIN_NET_API_GET_FEE_ADDR(net)     ((net)->pub.fee_addr)
#define DAP_CHAIN_NET_API_GET_NODE_ROLE(net)    ((net)->pub.node_role)

#ifdef __cplusplus
}
#endif

