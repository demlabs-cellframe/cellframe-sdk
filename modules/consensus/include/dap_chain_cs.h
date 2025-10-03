/**
 * @file dap_chain_cs.h
 * @brief Chain callbacks helper functions
 * 
 * Callback structure dap_chain_cs_callbacks_t defined in dap_chain.h
 * This file provides registration and retrieval functions
 */

#pragma once

#include "dap_chain.h"

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
uint256_t dap_chain_cs_get_collecting_level(dap_chain_t *a_chain);
void dap_chain_cs_add_block_collect(dap_chain_t *a_chain, void *a_block_cache, void *a_params, int a_type);
bool dap_chain_cs_get_autocollect_status(dap_chain_t *a_chain);
int dap_chain_cs_set_hardfork_state(dap_chain_t *a_chain, bool a_state);
bool dap_chain_cs_hardfork_engaged(dap_chain_t *a_chain);

// Stake service wrappers
int dap_chain_cs_stake_check_pkey_hash(dap_chain_t *a_chain, dap_hash_fast_t *a_pkey_hash, 
                                       uint256_t *a_sovereign_tax, dap_chain_addr_t *a_sovereign_addr);
int dap_chain_cs_stake_hardfork_data_import(dap_chain_t *a_chain, dap_hash_fast_t *a_decree_hash);
int dap_chain_cs_stake_switch_table(dap_chain_t *a_chain, bool a_to_sandbox);

// Mempool wrappers
char* dap_chain_cs_mempool_group_new(dap_chain_t *a_chain);
char* dap_chain_cs_mempool_datum_add(dap_chain_t *a_chain, dap_chain_datum_t *a_datum, const char *a_hash_out_type);

