/*
 * Authors:
 * Cellframe Development Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 *
 * Validator API - abstraction for PoS validator operations
 * Breaks circular dependency: consensus → stake
 *
 * Phase 5.4.2: Dependency Inversion Pattern
 * - Consensus modules (esbocs, etc) call validator functions through this API
 * - Stake service registers implementation at init()
 * - NO direct dependency consensus → stake
 */

#pragma once

#include "dap_chain_common.h"  // includes all common types (chain_addr_t, etc)
#include "dap_list.h"
#include "dap_hash.h"
#include "dap_pkey.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration for dap_chain_net_t only (avoid including net.h)
typedef struct dap_chain_net dap_chain_net_t;

/**
 * @brief Validator item opaque pointer
 * Actual structure is in stake module, consensus only sees pointer
 */
typedef void* dap_chain_validator_item_t;

/**
 * @brief Get list of validators for network
 * @param a_net_id Network ID
 * @param a_only_active Only active validators
 * @param a_excluded_list Optional excluded keys list
 * @return List of validator items or NULL
 */
typedef dap_list_t* (*dap_chain_validator_get_list_func_t)(
    dap_chain_net_id_t a_net_id,
    bool a_only_active,
    uint16_t **a_excluded_list
);

/**
 * @brief Check if key is delegated
 * @param a_signing_addr Signing address
 * @return 0 if delegated, -1 if inactive, >0 if not delegated
 */
typedef int (*dap_chain_validator_check_delegated_func_t)(
    dap_chain_addr_t *a_signing_addr
);

/**
 * @brief Mark validator as active/inactive
 * @param a_signing_addr Signing address
 * @param a_active true=active, false=inactive
 * @return 0 on success
 */
typedef int (*dap_chain_validator_mark_active_func_t)(
    dap_chain_addr_t *a_signing_addr,
    bool a_active
);

/**
 * @brief Get public key by hash
 * @param a_net_id Network ID
 * @param a_hash Public key hash
 * @return Public key or NULL
 */
typedef dap_pkey_t* (*dap_chain_validator_get_pkey_func_t)(
    dap_chain_net_id_t a_net_id,
    dap_hash_sha3_256_t *a_hash
);

/**
 * @brief Delegate key
 * @param a_net Network
 * @param a_signing_addr Signing address
 * @param a_decree_hash Decree hash (optional)
 * @param a_tx_hash Transaction hash (optional)
 * @param a_value Stake value
 * @param a_node_addr Node address
 * @param a_pkey Public key
 */
typedef void (*dap_chain_validator_delegate_func_t)(
    dap_chain_net_t *a_net,
    dap_chain_addr_t *a_signing_addr,
    dap_hash_sha3_256_t *a_decree_hash,
    dap_hash_sha3_256_t *a_tx_hash,
    uint256_t a_value,
    dap_chain_node_addr_t *a_node_addr,
    dap_pkey_t *a_pkey
);

/**
 * @brief Get minimum allowed stake value
 * @param a_net_id Network ID
 * @return Minimum value
 */
typedef uint256_t (*dap_chain_validator_get_min_value_func_t)(
    dap_chain_net_id_t a_net_id
);

/**
 * @brief Update hardfork transaction
 * @param a_net Network
 */
typedef void (*dap_chain_validator_hardfork_update_func_t)(
    dap_chain_net_t *a_net
);

/**
 * @brief Get node address from validator item
 * @param a_item Validator item
 * @return Node address pointer
 */
typedef dap_stream_node_addr_t* (*dap_chain_validator_get_node_addr_func_t)(
    dap_chain_validator_item_t a_item
);

/**
 * @brief Get value from validator item
 * @param a_item Validator item
 * @return Stake value
 */
typedef uint256_t (*dap_chain_validator_get_value_func_t)(
    dap_chain_validator_item_t a_item
);

/**
 * @brief Validator API registry
 */
typedef struct dap_chain_validator_api_registry {
    dap_chain_validator_get_list_func_t get_validators;
    dap_chain_validator_check_delegated_func_t check_key_delegated;
    dap_chain_validator_mark_active_func_t mark_validator_active;
    dap_chain_validator_get_pkey_func_t get_pkey_by_hash;
    dap_chain_validator_delegate_func_t key_delegate;
    dap_chain_validator_get_min_value_func_t get_allowed_min_value;
    dap_chain_validator_hardfork_update_func_t hardfork_tx_update;
    dap_chain_validator_get_node_addr_func_t get_node_addr_from_item;
    dap_chain_validator_get_value_func_t get_value_from_item;
} dap_chain_validator_api_registry_t;

/**
 * @brief Initialize validator API
 */
int dap_chain_validator_api_init(void);

/**
 * @brief Deinitialize validator API
 */
void dap_chain_validator_api_deinit(void);

/**
 * @brief Register validator implementation (called by stake service)
 * @param a_registry Registry with function pointers
 */
void dap_chain_validator_api_register(const dap_chain_validator_api_registry_t *a_registry);

/**
 * @brief API functions (wrappers that call registered implementation)
 */
dap_list_t* dap_chain_validator_api_get_validators(dap_chain_net_id_t a_net_id, bool a_only_active, uint16_t **a_excluded_list);
int dap_chain_validator_api_check_key_delegated(dap_chain_addr_t *a_signing_addr);
int dap_chain_validator_api_mark_validator_active(dap_chain_addr_t *a_signing_addr, bool a_active);
dap_pkey_t* dap_chain_validator_api_get_pkey_by_hash(dap_chain_net_id_t a_net_id, dap_hash_sha3_256_t *a_hash);
void dap_chain_validator_api_key_delegate(dap_chain_net_t *a_net, dap_chain_addr_t *a_signing_addr,
    dap_hash_sha3_256_t *a_decree_hash, dap_hash_sha3_256_t *a_tx_hash, uint256_t a_value,
    dap_chain_node_addr_t *a_node_addr, dap_pkey_t *a_pkey);
uint256_t dap_chain_validator_api_get_allowed_min_value(dap_chain_net_id_t a_net_id);
void dap_chain_validator_api_hardfork_tx_update(dap_chain_net_t *a_net);
dap_stream_node_addr_t* dap_chain_validator_api_get_node_addr(dap_chain_validator_item_t a_item);
uint256_t dap_chain_validator_api_get_value(dap_chain_validator_item_t a_item);

#ifdef __cplusplus
}
#endif



