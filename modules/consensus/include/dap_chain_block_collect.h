/*
 * Authors:
 * Cellframe Development Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 *
 * Common block collection types for consensus modules
 * Extracted to break circular dependency blocks ↔ esbocs
 */

#pragma once

#include "dap_chain_common.h"
#include "dap_enc_key.h"
#include "dap_pkey.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
typedef struct dap_chain dap_chain_t;

/**
 * @brief Block autocollect type enum
 */
typedef enum dap_chain_block_autocollect_type {
    DAP_CHAIN_BLOCK_COLLECT_FEES = 0,
    DAP_CHAIN_BLOCK_COLLECT_REWARDS,
    DAP_CHAIN_BLOCK_COLLECT_BOTH
} dap_chain_block_autocollect_type_t;

/**
 * @brief Block collection parameters
 * 
 * Common structure used by consensus modules (esbocs, etc) for block collection
 */
typedef struct dap_chain_block_collect_params {
    uint256_t collecting_level;
    uint256_t minimum_fee;
    dap_chain_t *chain;
    dap_enc_key_t *blocks_sign_key;
    dap_pkey_t *block_sign_pkey;
    dap_chain_addr_t *collecting_addr;
    dap_chain_cell_id_t cell_id;
} dap_chain_block_collect_params_t;

// Alias for backward compatibility with esbocs
typedef dap_chain_block_collect_params_t dap_chain_esbocs_block_collect_t;

#ifdef __cplusplus
}
#endif


