/*
 * Authors:
 * Cellframe Development Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 *
 * This file is part of CellFrame SDK
 *
 * CellFrame SDK is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * CellFrame SDK is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#pragma once

#include "dap_chain_common.h"
#include "dap_hash.h"
#include "dap_math_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Sovereign tax information for a validator key
 * 
 * This structure is returned by sovereign tax callback to allow
 * blocks module to apply tax without depending on stake module
 */
typedef struct dap_chain_sovereign_tax_info {
    bool has_tax;                    // Whether this key has sovereign tax
    dap_chain_addr_t sovereign_addr; // Address to receive tax
    uint256_t sovereign_tax;         // Tax percentage (0.0 - 100.0)
} dap_chain_sovereign_tax_info_t;

/**
 * @brief Callback type for checking sovereign tax on a validator key
 * 
 * Allows stake service to provide sovereign tax information to blocks
 * module without creating circular dependency
 * 
 * @param a_net_id Network ID
 * @param a_pkey_hash Hash of the signing public key
 * @return Tax info structure, or NULL if no tax applies
 */
typedef dap_chain_sovereign_tax_info_t* (*dap_chain_sovereign_tax_callback_t)(
    dap_chain_net_id_t a_net_id,
    dap_hash_fast_t *a_pkey_hash
);

/**
 * @brief Initialize block callbacks registry
 */
int dap_chain_block_callbacks_init(void);

/**
 * @brief Deinitialize block callbacks registry
 */
void dap_chain_block_callbacks_deinit(void);

/**
 * @brief Register sovereign tax callback
 * 
 * @param a_callback Callback function from stake service
 */
void dap_chain_block_callbacks_register_sovereign_tax(dap_chain_sovereign_tax_callback_t a_callback);

/**
 * @brief Get sovereign tax info for a key (calls registered callback)
 * 
 * @param a_net_id Network ID
 * @param a_pkey_hash Signing key hash
 * @return Tax info or NULL if no callback registered or no tax
 */
dap_chain_sovereign_tax_info_t* dap_chain_block_callbacks_get_sovereign_tax(
    dap_chain_net_id_t a_net_id,
    dap_hash_fast_t *a_pkey_hash
);

#ifdef __cplusplus
}
#endif


