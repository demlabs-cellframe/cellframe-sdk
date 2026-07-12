/*
 * dap_chain_tx_anon_compose.h — Compose builder registration for anonymous TX.
 *
 * Provides dap_chain_tx_anon_compose_register() to register the
 * "anon_transfer" builder in the TX compose registry.
 *
 * Once registered, anonymous TX can be created via:
 *   dap_chain_tx_compose_create("anon_transfer", ledger, NULL, &params);
 */

#pragma once

#include "dap_chain_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Parameters for "anon_transfer" compose builder.
 * Pass as a_params to dap_chain_tx_compose_create("anon_transfer", ...).
 */
typedef struct anon_transfer_compose_params {
    const char *wallet_name;
    const char *chain_name;
    const char *token_ticker;
    uint256_t value;
    dap_chain_addr_t addr_to;
    size_t anon_set;
    uint256_t fee;
    const char *hash_out_type;
} anon_transfer_compose_params_t;

/**
 * Register "anon_transfer" compose builder.
 * @return 0 on success, -1 on error
 */
int dap_chain_tx_anon_compose_register(void);

/**
 * Unregister "anon_transfer" compose builder.
 */
void dap_chain_tx_anon_compose_unregister(void);

#ifdef __cplusplus
}
#endif
