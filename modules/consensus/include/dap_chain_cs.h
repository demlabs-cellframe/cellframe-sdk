/**
 * @file dap_chain_cs.h
 * @brief Chain callbacks helper functions
 * 
 * Callback structure dap_chain_cs_callbacks_t defined in dap_chain_cs_callbacks.h
 * This file provides registration and retrieval functions
 */

#pragma once

#include "dap_chain.h"
#include "dap_config.h"
#include "dap_chain_cs_callbacks.h"

// Consensus lifecycle callbacks
typedef int (*dap_chain_callback_new_cfg_t)(dap_chain_t *, dap_config_t *);
typedef int (*dap_chain_callback_t)(dap_chain_t *);

typedef struct dap_chain_cs_lifecycle {
    dap_chain_callback_new_cfg_t callback_init;
    dap_chain_callback_new_cfg_t callback_load;
    dap_chain_callback_t callback_delete;
    dap_chain_callback_t callback_created;
    dap_chain_callback_t callback_start;
    dap_chain_callback_t callback_stop;
    dap_chain_callback_t callback_purge;
} dap_chain_cs_lifecycle_t;

// Consensus system initialization
int dap_chain_cs_init(void);
void dap_chain_cs_deinit(void);

/**
 * @brief Register callbacks for specific chain
 * @param a_chain Chain instance
 * @param a_callbacks Pointer to callbacks structure (must remain valid during chain lifetime)
 */
void dap_chain_cs_set_callbacks(dap_chain_t *a_chain, dap_chain_cs_callbacks_t *a_callbacks);

/**
 * @brief Get registered callbacks for specific chain
 * @param a_chain Chain instance
 * @return Pointer to callbacks structure or NULL if not registered
 */
dap_chain_cs_callbacks_t* dap_chain_cs_get_callbacks(dap_chain_t *a_chain);

// ===== Wrapper functions for safe callback invocation =====

// Consensus wrappers
char* dap_chain_cs_get_fee_group(dap_chain_t *a_chain, const char *a_net_name);
char* dap_chain_cs_get_reward_group(dap_chain_t *a_chain, const char *a_net_name);
uint256_t dap_chain_cs_get_fee(dap_chain_t *a_chain);
dap_pkey_t* dap_chain_cs_get_sign_pkey(dap_chain_t *a_chain);
dap_enc_key_t* dap_chain_cs_get_sign_key(dap_chain_t *a_chain);
uint256_t dap_chain_cs_get_collecting_level(dap_chain_t *a_chain);
void dap_chain_cs_add_block_collect(dap_chain_t *a_chain, void *a_block_cache, void *a_params, int a_type);
bool dap_chain_cs_get_autocollect_status(dap_chain_t *a_chain);
int dap_chain_cs_set_hardfork_state(dap_chain_t *a_chain, bool a_state);
bool dap_chain_cs_hardfork_engaged(dap_chain_t *a_chain);

// Stake service wrappers
int dap_chain_cs_stake_check_pkey_hash(dap_chain_t *a_chain, dap_hash_sha3_256_t *a_pkey_hash, 
                                       uint256_t *a_sovereign_tax, dap_chain_addr_t *a_sovereign_addr);
int dap_chain_cs_stake_hardfork_data_import(dap_chain_t *a_chain, dap_hash_sha3_256_t *a_decree_hash);
int dap_chain_cs_stake_switch_table(dap_chain_t *a_chain, bool a_to_sandbox);

// Mempool wrappers
char* dap_chain_cs_mempool_datum_add(dap_chain_t *a_chain, dap_chain_datum_t *a_datum, const char *a_hash_out_type);

// ===== NEW: Consensus-agnostic validator management wrappers =====

/**
 * @brief Check if consensus is started/running
 * @param a_chain Chain instance
 * @return true if consensus is active, false if not or callback not registered
 */
bool dap_chain_cs_is_started(dap_chain_t *a_chain);

/**
 * @brief Get minimum validators count required by consensus
 * @param a_chain Chain instance
 * @return Minimum count (0 if not applicable or callback not registered)
 */
uint16_t dap_chain_cs_get_min_validators_count(dap_chain_t *a_chain);

/**
 * @brief Set minimum validators count for consensus
 * @param a_chain Chain instance
 * @param a_count New minimum count
 * @return 0 on success, negative on error or if callback not registered
 */
int dap_chain_cs_set_min_validators_count(dap_chain_t *a_chain, uint16_t a_count);

/**
 * @brief Add validator to consensus clusters/pools
 * @param a_chain Chain instance
 * @param a_node_addr Node address to add
 * @return 0 on success, negative on error or if callback not registered
 */
int dap_chain_cs_add_validator(dap_chain_t *a_chain, const dap_chain_node_addr_t *a_node_addr);

/**
 * @brief Remove validator from consensus clusters/pools
 * @param a_chain Chain instance
 * @param a_node_addr Node address to remove
 * @return 0 on success, negative on error or if callback not registered
 */
int dap_chain_cs_remove_validator(dap_chain_t *a_chain, const dap_chain_node_addr_t *a_node_addr);

// ===== Consensus registration and lifecycle =====

/**
 * @brief Register consensus implementation (esbocs, dag_poa, etc)
 * @param a_cs_str Consensus name
 * @param a_callbacks Lifecycle callbacks for this consensus
 */
void dap_chain_cs_add(const char *a_cs_str, dap_chain_cs_lifecycle_t a_callbacks);

/**
 * @brief Create consensus from config
 */
int dap_chain_cs_create(dap_chain_t *a_chain, dap_config_t *a_chain_cfg);
int dap_chain_cs_load(dap_chain_t *a_chain, dap_config_t *a_chain_cfg);
int dap_chain_cs_start(dap_chain_t *a_chain);
int dap_chain_cs_stop(dap_chain_t *a_chain);
int dap_chain_cs_purge(dap_chain_t *a_chain);

