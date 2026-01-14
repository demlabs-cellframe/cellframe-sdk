/*
 * Authors:
 * Daniil Frolov <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright (c) 2025, All rights reserved.
 */

#pragma once

#include "dap_chain_net.h"
#include "dap_chain_datum_decree.h"

/**
 * @brief Initialize blocks decree handlers
 * 
 * Registers handlers for block-related decrees like empty_blockgen
 */
void dap_chain_blocks_decree_init(void);

/**
 * @brief Deinitialize blocks decree handlers
 */
void dap_chain_blocks_decree_deinit(void);

