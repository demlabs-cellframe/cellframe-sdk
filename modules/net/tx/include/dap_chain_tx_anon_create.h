/*
 * dap_chain_tx_anon_create.h — Anonymous transaction creation API (algorithm-agnostic).
 *
 * Creates anonymous transactions with SNARK ring proofs, key images for
 * double-spend prevention, and Pedersen commitments for confidential amounts.
 *
 * The signature algorithm is auto-detected from wallet key type or can be
 * specified explicitly via dap_chain_tx_anon_transfer_with_algo().
 *
 * Supported algorithms: "chipmunk_ring", "lrs"
 * Config: [ledger] anon_algo = "chipmunk_ring"
 */

#pragma once

#include "dap_chain_wallet.h"
#include "dap_chain.h"
#include "dap_chain_datum_tx.h"
#include "chipmunk_snark.h"
#include "chipmunk_pedersen.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Anonymous TX creation context */
typedef struct dap_chain_tx_anon_context {
    chipmunk_snark_ctx_t snark_ctx;
    chipmunk_pedersen_params_t pedersen_params;
    bool initialized;
} dap_chain_tx_anon_context_t;

/* Init/deinit */
int dap_chain_tx_anon_init(void);
void dap_chain_tx_anon_deinit(void);
dap_chain_tx_anon_context_t *dap_chain_tx_anon_get_context(void);

/**
 * Create anonymous transfer. Algorithm auto-detected from wallet key type.
 *
 * @param a_ring Ring of public keys (type depends on algorithm).
 *               For chipmunk_ring: chipmunk_ring_pk_t[]
 *               For lrs: chipmunk_lrs_public_key_t[]
 * @param a_ring_size Number of keys in ring (8-64).
 */
dap_chain_datum_t *dap_chain_tx_anon_transfer(
    dap_chain_wallet_t *a_wallet,
    dap_chain_t *a_chain,
    const char *a_token_ticker,
    uint256_t a_amount,
    const dap_chain_addr_t *a_addr_to,
    const void *a_ring,
    size_t a_ring_size);

/**
 * Create anonymous transfer with explicit algorithm selection.
 *
 * @param a_algo_name Algorithm name: "chipmunk_ring" or "lrs".
 */
dap_chain_datum_t *dap_chain_tx_anon_transfer_with_algo(
    dap_chain_wallet_t *a_wallet,
    dap_chain_t *a_chain,
    const char *a_token_ticker,
    uint256_t a_amount,
    const dap_chain_addr_t *a_addr_to,
    const void *a_ring,
    size_t a_ring_size,
    const char *a_algo_name);

/**
 * Create anonymous transfer with auto-selected ring from validator set.
 * Algorithm read from [ledger] anon_algo config (default: chipmunk_ring).
 */
dap_chain_datum_t *dap_chain_tx_anon_transfer_auto_ring(
    dap_chain_wallet_t *a_wallet,
    dap_chain_t *a_chain,
    const char *a_token_ticker,
    uint256_t a_amount,
    const dap_chain_addr_t *a_addr_to,
    size_t a_anon_set);

/**
 * Reveal anonymous balance (verify Pedersen commitment openings).
 * @param a_known_amount Amount the user claims to have committed.
 */
int dap_chain_tx_anon_reveal_balance(dap_ledger_t *a_ledger,
                                      const dap_chain_addr_t *a_addr,
                                      const char *a_token_ticker,
                                      const uint8_t a_randomness_seed[32],
                                      int64_t a_known_amount,
                                      uint256_t *a_balance_out);

#ifdef __cplusplus
}
#endif
