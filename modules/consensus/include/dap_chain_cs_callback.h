/**
 * @file dap_chain_cs_callback.h
 * @brief Chain callback structures - breaks circular dependencies between modules
 * 
 * All callbacks are stored per-chain to support different consensus and services per chain
 */

#pragma once

#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_hash.h"
#include "dap_pkey.h"

// Forward declarations
typedef struct dap_chain dap_chain_t;
typedef struct dap_chain_datum dap_chain_datum_t;

/**
 * @brief Chain consensus callbacks structure 
 * All callbacks are stored per-chain to support different consensus and services per chain
 */
typedef struct dap_chain_cs_callbacks {
    // ===== Consensus callbacks (chain ↔ consensus communication) =====
    
    // Get fee collection group name
    char* (*get_fee_group)(const char *a_net_name);
    // Get reward collection group name
    char* (*get_reward_group)(const char *a_net_name);
    // Get minimum fee for consensus
    uint256_t (*get_fee)(dap_chain_net_id_t a_net_id);
    // Get signing public key
    dap_pkey_t* (*get_sign_pkey)(dap_chain_net_id_t a_net_id);
    // Get collecting level (returns uint256_t!)
    uint256_t (*get_collecting_level)(dap_chain_t *a_chain);
    // Add block collect operation
    void (*add_block_collect)(void *a_block_cache, void *a_params, int a_type);
    // Get autocollect status
    bool (*get_autocollect_status)(dap_chain_net_id_t a_net_id);
    // Set hardfork state (int return for error codes)
    int (*set_hardfork_state)(dap_chain_t *a_chain, bool a_state);
    // Check if hardfork is engaged
    bool (*hardfork_engaged)(dap_chain_t *a_chain);
    // Prepare hardfork
    int (*set_hardfork_prepare)(dap_chain_t *a_chain, uint16_t a_generation, uint64_t a_start_atom, dap_list_t *a_addrs, dap_json_t *a_params);
    // Complete hardfork
    void (*set_hardfork_complete)(dap_chain_t *a_chain);
    
    // ===== Stake service callbacks (blocks → stake communication) =====
    
    // Check public key hash and get sovereign tax info
    // Returns: 0 if not found, 1 if found
    int (*stake_check_pkey_hash)(dap_chain_net_id_t a_net_id, dap_hash_fast_t *a_pkey_hash, 
                                 uint256_t *a_sovereign_tax, dap_chain_addr_t *a_sovereign_addr);
    // Import hardfork data
    int (*stake_hardfork_data_import)(dap_chain_net_id_t a_net_id, dap_hash_fast_t *a_decree_hash);
    // Switch stake table (main/sandbox)
    int (*stake_switch_table)(dap_chain_net_id_t a_net_id, bool a_to_sandbox);
    
    // ===== Mempool callbacks (net → mempool communication) =====
    
    // Add datum to mempool
    char* (*mempool_datum_add)(dap_chain_datum_t *a_datum, dap_chain_t *a_chain, const char *a_datum_hash_out_type);
} dap_chain_cs_callbacks_t;

