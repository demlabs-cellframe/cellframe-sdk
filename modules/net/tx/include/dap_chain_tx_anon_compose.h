/*
 * dap_chain_tx_anon_compose.h — Compose builder registration for anonymous TX.
 *
 * Provides dap_chain_tx_anon_compose_register() to register the
 * "anon_transfer" builder in the TX compose registry.
 *
 * Once registered, anonymous TX can be created via:
 *   dap_chain_tx_compose_create("anon_transfer", ledger, NULL, &params);
 *
 * Parameters struct (anon_transfer_compose_params_t) is defined in
 * dap_chain_tx_anon_compose.c — callers should construct it before
 * invoking compose_create.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

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
