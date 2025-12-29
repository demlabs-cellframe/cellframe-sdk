/*
 * Authors:
 * Daniil Frolov <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright (c) 2025, All rights reserved.
 *
 * This file is part of CellFrame SDK the open source project
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize stake decree handlers
 * 
 * Registers all stake-related decree handlers with the decree registry.
 * @return 0 on success, negative on error
 */
int dap_chain_net_srv_stake_decree_init(void);

/**
 * @brief Deinitialize stake decree handlers
 * 
 * Unregisters all stake decree handlers.
 */
void dap_chain_net_srv_stake_decree_deinit(void);

#ifdef __cplusplus
}
#endif
