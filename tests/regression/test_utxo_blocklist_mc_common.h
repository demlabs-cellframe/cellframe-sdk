/**
 * @file test_utxo_blocklist_mc_common.h
 * @brief Shared scenario helpers for UTXO blocklist multichannel regression tests
 *
 * Problem background (verified on master):
 * Central validation (s_tx_cache_check -> dap_ledger_tx_check input loop) looks up the
 * UTXO blocklist by the PARENT transaction's cached main ticker
 * (dap_ledger_tx_item_t.cache_data.token_ticker), while wallet-side enumeration
 * (dap_ledger_get_list_tx_outs_unspent_by_addr) checks by the ACTUAL token of the
 * specific 'out' item. For multichannel parents (secondary OUT_EXT/OUT_STD in a token
 * different from the parent's main ticker) a blocklist entry made on the actual token
 * is invisible to central validation: a correctly signed handcrafted spend passes.
 *
 * Token layout used by the multichannel scenario:
 *   MCHN  - set as net native ticker; carried by parent out #0 (blocked target)
 *   SECND - becomes the parent's cached MAIN ticker (derivation: case "2 input tokens,
 *           main = the non-native one")
 *   parent inputs:  [SECND fund out, MCHN fund out]
 *   parent outputs: [#0 = OUT_EXT MCHN -> spender, #1 = OUT_EXT SECND -> spender]
 */

#pragma once

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_ledger.h"
#include "dap_chain_ledger_item.h"
#include "dap_cert.h"
#include "dap_enc_key.h"
#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_transaction_fixtures.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UTXO_MC_TOK_NATIVE "MCHN"
#define UTXO_MC_TOK_SECOND "SECND"
#define UTXO_MC_TOK_SINGLE "SINGLE"
#define UTXO_MC_FUND_VALUE "1000.0"

typedef struct utxo_mc_ctx {
    // Spender side
    dap_enc_key_t *spender_key;
    dap_chain_addr_t spender_addr;
    // Recipient for handcrafted spends
    dap_enc_key_t *dst_key;
    dap_chain_addr_t dst_addr;
    // Token owner cert wrapper (borrows spender_key, do not double free)
    dap_cert_t *owner_cert;
    // Multichannel scenario
    test_token_fixture_t *tok_native;    // UTXO_MC_TOK_NATIVE
    test_token_fixture_t *tok_second;    // UTXO_MC_TOK_SECOND
    test_tx_fixture_t *fund_native;
    test_tx_fixture_t *fund_second;
    dap_chain_hash_fast_t parent_hash;   // multichannel parent tx
    char parent_main_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    bool parent_multichannel;
    // Single-token scenario
    test_token_fixture_t *tok_single;    // UTXO_MC_TOK_SINGLE
    test_tx_fixture_t *fund_single;
    dap_chain_hash_fast_t single_parent_hash;
} utxo_mc_ctx_t;

/** Initialize test environment (dirs, env, net fixture). Return 0 on success. */
int utxo_mc_setup_env(void);

/** Tear down test environment. */
void utxo_mc_teardown_env(void);

/**
 * Build the multichannel scenario up to the parent tx added to ledger:
 * two tokens + emissions, two funding txs, multichannel parent tx.
 * Fills ctx fields (parent_hash, parent_main_ticker, parent_multichannel).
 * Return 0 on success.
 */
int utxo_mc_ctx_multichannel_init(utxo_mc_ctx_t *a_ctx);

/**
 * Build the single-token scenario: one token + emission, funding tx and a plain
 * (non-multichannel) parent tx with a single OUT_EXT output #0.
 * Return 0 on success.
 */
int utxo_mc_ctx_single_init(utxo_mc_ctx_t *a_ctx);

/** Free resources of a ctx built by the _init functions above (idempotent per field). */
void utxo_mc_ctx_free(utxo_mc_ctx_t *a_ctx);

/**
 * Apply token_update with UTXO_BLOCKED_ADD TSD: block (a_tx_hash:a_out_idx) in the
 * blocklist of token a_ticker (signed with the token fixture owner cert).
 * Return ledger result (0 on success).
 */
int utxo_mc_block(const char *a_ticker, test_token_fixture_t *a_token_fixture,
                  dap_chain_hash_fast_t *a_tx_hash, uint32_t a_out_idx);

/**
 * Run central validation (dap_ledger_tx_add_check) on a handcrafted spend of
 * (a_parent_hash:a_out_idx) in token a_token. Uses a plain 'in' item, or an
 * 'in_cond' item when a_in_cond is set (blocklist check fires for both before
 * the IN/IN_COND branch, so DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED is the expected
 * result for a blocked out in both shapes).
 * Return the ledger check code.
 */
int utxo_mc_check_spend(dap_chain_hash_fast_t *a_parent_hash, uint32_t a_out_idx,
                        const char *a_token, dap_enc_key_t *a_spender_key,
                        dap_chain_addr_t *a_dst, const char *a_value, bool a_in_cond);

/**
 * Check whether wallet-side enumeration (unspent outs by addr for a_token)
 * returns the output (a_tx_hash:a_out_idx).
 */
bool utxo_mc_wallet_lists(const char *a_token, dap_chain_addr_t *a_addr,
                          dap_chain_hash_fast_t *a_tx_hash, uint32_t a_out_idx);

#ifdef __cplusplus
}
#endif
