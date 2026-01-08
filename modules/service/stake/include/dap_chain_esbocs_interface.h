/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 */

#pragma once

#include "dap_chain_common.h"
#include "dap_chain_node_addr.h"

/**
 * @file dap_chain_esbocs_interface.h
 * @brief ESBOCS Module Interface for Stake Module
 * 
 * ARCHITECTURE: Dependency Inversion
 * 
 * Stake module needs some information from ESBOCS consensus, but should NOT
 * depend directly on ESBOCS module (circular dependency).
 * 
 * SOLUTION: Interface with stub implementation + callback registration
 * 
 * When ESBOCS module initializes, it registers real implementations via
 * dap_chain_esbocs_interface_register().
 * 
 * Until then, stub implementations return safe defaults.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Check if ESBOCS consensus is started for given network
 * @param a_net_id Network ID
 * @return true if ESBOCS is running, false otherwise
 */
bool dap_chain_esbocs_started(dap_chain_net_id_t a_net_id);

/**
 * @brief Get minimum validators count for network
 * @param a_net_id Network ID
 * @return Minimum validators count (default: 1 if ESBOCS not initialized)
 */
uint16_t dap_chain_esbocs_get_min_validators_count(dap_chain_net_id_t a_net_id);

/**
 * @brief Set minimum validators count for chain
 * @param a_chain Chain instance
 * @param a_count New minimum count
 * @return 0 on success, negative on error
 */
int dap_chain_esbocs_set_min_validators_count(struct dap_chain *a_chain, uint16_t a_count);

/**
 * @brief Add validator to ESBOCS clusters
 * @param a_net_id Network ID
 * @param a_node_addr Node address
 * @return 0 on success, negative on error
 */
int dap_chain_esbocs_add_validator_to_clusters(dap_chain_net_id_t a_net_id, const dap_chain_node_addr_t *a_node_addr);

/**
 * @brief Remove validator from ESBOCS clusters
 * @param a_net_id Network ID
 * @param a_node_addr Node address
 * @return 0 on success, negative on error
 */
int dap_chain_esbocs_remove_validator_from_clusters(dap_chain_net_id_t a_net_id, const dap_chain_node_addr_t *a_node_addr);

/**
 * @brief Callback types for ESBOCS operations
 */
typedef bool (*dap_chain_esbocs_started_callback_t)(dap_chain_net_id_t a_net_id);
typedef uint16_t (*dap_chain_esbocs_get_min_validators_callback_t)(dap_chain_net_id_t a_net_id);
typedef int (*dap_chain_esbocs_set_min_validators_callback_t)(struct dap_chain *a_chain, uint16_t a_count);
typedef int (*dap_chain_esbocs_add_validator_callback_t)(dap_chain_net_id_t a_net_id, const dap_chain_node_addr_t *a_node_addr);
typedef int (*dap_chain_esbocs_remove_validator_callback_t)(dap_chain_net_id_t a_net_id, const dap_chain_node_addr_t *a_node_addr);

/**
 * @brief ESBOCS interface callbacks structure
 */
typedef struct {
    dap_chain_esbocs_started_callback_t started;
    dap_chain_esbocs_get_min_validators_callback_t get_min_validators_count;
    dap_chain_esbocs_set_min_validators_callback_t set_min_validators_count;
    dap_chain_esbocs_add_validator_callback_t add_validator;
    dap_chain_esbocs_remove_validator_callback_t remove_validator;
} dap_chain_esbocs_interface_t;

/**
 * @brief Register ESBOCS interface callbacks
 * 
 * Called by ESBOCS module during initialization to provide real implementations.
 * 
 * @param a_interface Pointer to interface structure with callbacks
 * @return 0 on success, -1 if already registered
 */
int dap_chain_esbocs_interface_register(const dap_chain_esbocs_interface_t *a_interface);

/**
 * @brief Unregister ESBOCS interface callbacks
 * 
 * Called by ESBOCS module during deinitialization.
 */
void dap_chain_esbocs_interface_unregister(void);

#ifdef __cplusplus
}
#endif


