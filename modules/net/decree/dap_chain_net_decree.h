/*
 * Authors:
 * Dmitriy Gerasimov <naeper@demlabs.net>
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 */

#pragma once

#include "dap_chain_common.h"

/**
 * @brief Initialize network decree handlers
 * @details Registers handlers for network-related decree types (fee, PoA, etc.)
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_decree_init(void);

/**
 * @brief Deinitialize network decree handlers
 */
void dap_chain_net_decree_deinit(void);

