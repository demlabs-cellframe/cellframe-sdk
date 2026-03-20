/*
 * Cellframe SDK — centralized initialization API
 *
 * Authors:
 *   Dmitry Gerasimov <ceo@cellframe.net>
 *   DeM Labs Inc.   https://demlabs.net
 * Copyright (c) 2025-2026
 * License: GPLv3
 */

#pragma once
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum cf_sdk_modules {
    CF_MODULE_CHAIN            = 0x00000001,
    CF_MODULE_CONSENSUS_DAG    = 0x00000002,
    CF_MODULE_CONSENSUS_POA    = 0x00000004,
    CF_MODULE_CONSENSUS_BLOCKS = 0x00000008,
    CF_MODULE_CONSENSUS_ESBOCS = 0x00000010,
    CF_MODULE_CONSENSUS_NONE   = 0x00000020,
    CF_MODULE_NETWORK          = 0x00000040,
    CF_MODULE_WALLET           = 0x00000080,
    CF_MODULE_WALLET_CACHE     = 0x00000100,
    CF_MODULE_SRV_XCHANGE      = 0x00000200,
    CF_MODULE_SRV_VOTING       = 0x00000400,
    CF_MODULE_SRV_BRIDGE       = 0x00000800,
    CF_MODULE_SRV_STAKE        = 0x00001000,
    CF_MODULE_SRV_STAKE_EXT    = 0x00002000,
    CF_MODULE_CLI              = 0x00004000,
    CF_MODULE_MEMPOOL          = 0x00008000,

    CF_MODULE_ALL_CONSENSUS = CF_MODULE_CONSENSUS_DAG | CF_MODULE_CONSENSUS_POA |
                              CF_MODULE_CONSENSUS_BLOCKS | CF_MODULE_CONSENSUS_ESBOCS |
                              CF_MODULE_CONSENSUS_NONE,
    CF_MODULE_ALL_SERVICES  = CF_MODULE_SRV_XCHANGE | CF_MODULE_SRV_VOTING |
                              CF_MODULE_SRV_BRIDGE | CF_MODULE_SRV_STAKE |
                              CF_MODULE_SRV_STAKE_EXT,

    CF_MODULE_NODE = 0xFFFFFFFF
} cf_sdk_modules_t;

/**
 * @brief Initialize Cellframe SDK modules
 * @param a_modules Bitmask of cf_sdk_modules_t
 * @return 0 on success
 * @note dap_sdk_init() MUST be called first
 */
int cellframe_sdk_init(uint32_t a_modules);

void cellframe_sdk_deinit(void);

bool     cellframe_sdk_is_initialized(void);
uint32_t cellframe_sdk_get_modules(void);

#ifdef __cplusplus
}
#endif
