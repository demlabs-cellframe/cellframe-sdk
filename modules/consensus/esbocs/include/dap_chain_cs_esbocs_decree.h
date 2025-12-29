/*
 * Authors:
 * Daniil Frolov <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright (c) 2025, All rights reserved.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize ESBOCS decree handlers
 * 
 * Registers hardfork and consensus-related decree handlers.
 * @return 0 on success, negative on error
 */
int dap_chain_cs_esbocs_decree_init(void);

/**
 * @brief Deinitialize ESBOCS decree handlers
 */
void dap_chain_cs_esbocs_decree_deinit(void);

#ifdef __cplusplus
}
#endif







