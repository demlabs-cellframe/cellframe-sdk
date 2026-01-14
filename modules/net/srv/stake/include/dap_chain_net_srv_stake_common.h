/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2017-2025
 * All rights reserved.
 *
 * Common stake service types
 * Extracted to break circular dependencies
 * Phase 5.4: Type Extraction pattern
 */

#pragma once

#include "dap_chain_common.h"
#include "dap_hash.h"
#include "dap_math_ops.h"
#include "uthash.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
typedef struct dap_chain_net dap_chain_net_t;
typedef struct dap_pkey dap_pkey_t;

/**
 * @brief Stake validator item structure
 * 
 * Common structure used by multiple modules (net-tx, esbocs, xchange, voting)
 * Extracted from stake module to break dependencies
 */
typedef struct dap_chain_net_srv_stake_item {
    bool is_active;
    dap_chain_net_t *net;
    uint256_t locked_value;
    uint256_t value;
    dap_chain_addr_t signing_addr;
    union {
        dap_chain_hash_fast_t hash;     // Transaction hash (packed)
        uint8_t hash_key[DAP_CHAIN_HASH_FAST_SIZE];  // Aligned key for uthash
    } tx_hash;
    union {
        dap_chain_hash_fast_t hash;     // Decree hash (packed)
        uint8_t hash_key[DAP_CHAIN_HASH_FAST_SIZE];  // Aligned key for uthash
    } decree_hash;
    dap_chain_node_addr_t node_addr;
    dap_chain_addr_t sovereign_addr;
    uint256_t sovereign_tax;
    dap_pkey_t *pkey;
    UT_hash_handle hh, ht;  // hh for signing_addr hash, ht for tx_hash
} dap_chain_net_srv_stake_item_t;

/**
 * @brief Stake service UID
 */
#define DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID 0x13

#ifdef __cplusplus
}
#endif









