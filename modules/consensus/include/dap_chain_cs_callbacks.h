/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 */

#pragma once

#include "dap_chain_common.h"
#include "dap_hash.h"
#include "dap_pkey.h"
#include "dap_enc_key.h"

// dap_chain_node_addr_t and dap_list_t already defined in dap_chain_common.h and dap_list.h
// Forward declaration for dap_json_t
typedef struct dap_json dap_json_t;

/**
 * @file dap_chain_cs_callbacks.h
 * @brief Consensus-Agnostic Callbacks Structure
 * 
 * ARCHITECTURE: Dependency Inversion for Consensus Layer
 * 
 * This structure provides a unified interface for consensus-specific operations
 * without forcing hard dependencies on particular consensus implementations (ESBOCS, DAG-PoA, etc).
 * 
 * PRINCIPLES:
 * 1. Consensus-agnostic: Same API for block-based (ESBOCS) and event-based (DAG) consensus
 * 2. Zero coupling: Modules using consensus don't know which consensus is running
 * 3. Plugin system: Each consensus registers its own implementations
 * 4. Optional callbacks: NULL callbacks mean "not supported by this consensus"
 * 
 * USAGE:
 * - Consensus module (esbocs/dag_poa) fills this structure during init
 * - Registers it via dap_chain_cs_set_callbacks()
 * - Other modules use dap_chain_cs_* wrappers which safely call registered callbacks
 */

// Forward declarations
typedef struct dap_chain dap_chain_t;
typedef struct dap_chain_datum dap_chain_datum_t;
typedef struct dap_chain_addr dap_chain_addr_t;

// ============================================================================
// CONSENSUS LIFECYCLE CALLBACKS
// ============================================================================

/**
 * @brief Check if consensus is started/running for this chain
 * @param a_chain Chain instance
 * @return true if consensus is active, false otherwise
 */
typedef bool (*dap_chain_cs_callback_is_started_t)(dap_chain_t *a_chain);

/**
 * @brief Get minimum validators/nodes count required by consensus
 * @param a_chain Chain instance
 * @return Minimum count (0 if not applicable to this consensus)
 */
typedef uint16_t (*dap_chain_cs_callback_get_min_validators_count_t)(dap_chain_t *a_chain);

/**
 * @brief Set minimum validators/nodes count for consensus
 * @param a_chain Chain instance
 * @param a_count New minimum count
 * @return 0 on success, negative on error
 */
typedef int (*dap_chain_cs_callback_set_min_validators_count_t)(dap_chain_t *a_chain, uint16_t a_count);

// ============================================================================
// VALIDATOR MANAGEMENT CALLBACKS
// ============================================================================

/**
 * @brief Add validator/node to consensus clusters/pools
 * @param a_chain Chain instance
 * @param a_node_addr Node address to add
 * @return 0 on success, negative on error
 */
typedef int (*dap_chain_cs_callback_add_validator_t)(dap_chain_t *a_chain, const dap_chain_node_addr_t *a_node_addr);

/**
 * @brief Remove validator/node from consensus clusters/pools
 * @param a_chain Chain instance  
 * @param a_node_addr Node address to remove
 * @return 0 on success, negative on error
 */
typedef int (*dap_chain_cs_callback_remove_validator_t)(dap_chain_t *a_chain, const dap_chain_node_addr_t *a_node_addr);

// ============================================================================
// FEE AND REWARD CALLBACKS
// ============================================================================

/**
 * @brief Get fee group name for this consensus
 * @param a_chain Chain instance
 * @param a_net_name Network name
 * @return Fee group string or NULL
 */
typedef char* (*dap_chain_cs_callback_get_fee_group_t)(dap_chain_t *a_chain, const char *a_net_name);

/**
 * @brief Get reward group name for this consensus
 * @param a_chain Chain instance
 * @param a_net_name Network name
 * @return Reward group string or NULL
 */
typedef char* (*dap_chain_cs_callback_get_reward_group_t)(dap_chain_t *a_chain, const char *a_net_name);

/**
 * @brief Get consensus fee amount
 * @param a_chain Chain instance
 * @return Fee amount
 */
typedef uint256_t (*dap_chain_cs_callback_get_fee_t)(dap_chain_t *a_chain);

// ============================================================================
// SIGNING CALLBACKS
// ============================================================================

/**
 * @brief Get signing public key for consensus
 * @param a_chain Chain instance
 * @return Public key or NULL
 */
typedef dap_pkey_t* (*dap_chain_cs_callback_get_sign_pkey_t)(dap_chain_t *a_chain);

/**
 * @brief Get signing encryption key for consensus
 * @param a_chain Chain instance
 * @return Encryption key or NULL
 */
typedef dap_enc_key_t* (*dap_chain_cs_callback_get_sign_key_t)(dap_chain_t *a_chain);

// ============================================================================
// BLOCK/EVENT COLLECTION CALLBACKS
// ============================================================================

/**
 * @brief Get collecting level/threshold for consensus
 * @param a_chain Chain instance
 * @return Collecting level
 */
typedef uint256_t (*dap_chain_cs_callback_get_collecting_level_t)(dap_chain_t *a_chain);

/**
 * @brief Add block/event to collection queue
 * @param a_chain Chain instance
 * @param a_block_cache Block cache object
 * @param a_params Additional parameters
 * @param a_type Collection type
 */
typedef void (*dap_chain_cs_callback_add_block_collect_t)(dap_chain_t *a_chain, void *a_block_cache, void *a_params, int a_type);

/**
 * @brief Get autocollect status for consensus
 * @param a_chain Chain instance
 * @return true if autocollect is enabled
 */
typedef bool (*dap_chain_cs_callback_get_autocollect_status_t)(dap_chain_t *a_chain);

// ============================================================================
// HARDFORK CALLBACKS
// ============================================================================

/**
 * @brief Set hardfork state for consensus
 * @param a_chain Chain instance
 * @param a_state New hardfork state
 * @return 0 on success, negative on error
 */
typedef int (*dap_chain_cs_callback_set_hardfork_state_t)(dap_chain_t *a_chain, bool a_state);

/**
 * @brief Check if hardfork is engaged/active
 * @param a_chain Chain instance
 * @return true if hardfork is active
 */
typedef bool (*dap_chain_cs_callback_hardfork_engaged_t)(dap_chain_t *a_chain);

/**
 * @brief Prepare hardfork with parameters
 * @param a_chain Chain instance
 * @param a_generation New generation number
 * @param a_start_atom Starting atom number
 * @param a_addrs List of addresses
 * @param a_params JSON parameters
 * @return 0 on success, negative on error
 */
typedef int (*dap_chain_cs_callback_set_hardfork_prepare_t)(dap_chain_t *a_chain, uint16_t a_generation, uint64_t a_start_atom, dap_list_t *a_addrs, dap_json_t *a_params);

/**
 * @brief Complete hardfork process
 * @param a_chain Chain instance
 * @return 0 on success, negative on error
 */
typedef int (*dap_chain_cs_callback_set_hardfork_complete_t)(dap_chain_t *a_chain);

// ============================================================================
// STAKE SERVICE CALLBACKS
// ============================================================================

/**
 * @brief Check public key hash for staking
 * @param a_chain Chain instance
 * @param a_pkey_hash Public key hash to check
 * @param a_sovereign_tax Output: sovereign tax if found
 * @param a_sovereign_addr Output: sovereign address if found
 * @return 0 if valid, negative on error
 */
typedef int (*dap_chain_cs_callback_stake_check_pkey_hash_t)(dap_chain_t *a_chain, dap_hash_sha3_256_t *a_pkey_hash, 
                                                              uint256_t *a_sovereign_tax, dap_chain_addr_t *a_sovereign_addr);

/**
 * @brief Import hardfork data for stake service
 * @param a_chain Chain instance
 * @param a_decree_hash Decree hash containing hardfork data
 * @return 0 on success, negative on error
 */
typedef int (*dap_chain_cs_callback_stake_hardfork_data_import_t)(dap_chain_t *a_chain, dap_hash_sha3_256_t *a_decree_hash);

/**
 * @brief Switch stake table between main and sandbox
 * @param a_chain Chain instance
 * @param a_to_sandbox true to switch to sandbox, false to main
 * @return 0 on success, negative on error
 */
typedef int (*dap_chain_cs_callback_stake_switch_table_t)(dap_chain_t *a_chain, bool a_to_sandbox);

// ============================================================================
// MEMPOOL CALLBACKS
// ============================================================================

/**
 * @brief Add datum to mempool for consensus processing
 * @param a_chain Chain instance
 * @param a_datum Datum to add
 * @param a_hash_out_type Output hash type
 * @return Result string or NULL on error
 */
typedef char* (*dap_chain_cs_callback_mempool_datum_add_t)(dap_chain_t *a_chain, dap_chain_datum_t *a_datum, const char *a_hash_out_type);

// ============================================================================
// MAIN CALLBACKS STRUCTURE
// ============================================================================

/**
 * @brief Consensus-agnostic callbacks structure
 * 
 * Each consensus implementation (ESBOCS, DAG-PoA) fills this structure
 * with pointers to its specific implementations.
 * 
 * NULL callbacks mean "not supported by this consensus".
 */
typedef struct dap_chain_cs_callbacks {
    // Lifecycle
    dap_chain_cs_callback_is_started_t is_started;
    dap_chain_cs_callback_get_min_validators_count_t get_min_validators_count;
    dap_chain_cs_callback_set_min_validators_count_t set_min_validators_count;
    
    // Validator management
    dap_chain_cs_callback_add_validator_t add_validator;
    dap_chain_cs_callback_remove_validator_t remove_validator;
    
    // Fee and reward
    dap_chain_cs_callback_get_fee_group_t get_fee_group;
    dap_chain_cs_callback_get_reward_group_t get_reward_group;
    dap_chain_cs_callback_get_fee_t get_fee;
    
    // Signing
    dap_chain_cs_callback_get_sign_pkey_t get_sign_pkey;
    dap_chain_cs_callback_get_sign_key_t get_sign_key;
    
    // Block/Event collection
    dap_chain_cs_callback_get_collecting_level_t get_collecting_level;
    dap_chain_cs_callback_add_block_collect_t add_block_collect;
    dap_chain_cs_callback_get_autocollect_status_t get_autocollect_status;
    
    // Hardfork
    dap_chain_cs_callback_set_hardfork_state_t set_hardfork_state;
    dap_chain_cs_callback_hardfork_engaged_t hardfork_engaged;
    dap_chain_cs_callback_set_hardfork_prepare_t set_hardfork_prepare;
    dap_chain_cs_callback_set_hardfork_complete_t set_hardfork_complete;
    
    // Stake service
    dap_chain_cs_callback_stake_check_pkey_hash_t stake_check_pkey_hash;
    dap_chain_cs_callback_stake_hardfork_data_import_t stake_hardfork_data_import;
    dap_chain_cs_callback_stake_switch_table_t stake_switch_table;
    
    // Mempool
    dap_chain_cs_callback_mempool_datum_add_t mempool_datum_add;
    
} dap_chain_cs_callbacks_t;

