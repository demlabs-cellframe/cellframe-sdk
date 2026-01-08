/**
 * @file dap_chain_net_srv_voting_compose.h
 * @brief Voting service transaction compose API
 */

#pragma once

#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_net_srv_voting.h"
#include "dap_chain_tx_compose_api.h"  // NEW: Plugin-based TX compose API
#include "dap_json.h"
#include "dap_cert.h"
#include "dap_chain_ledger.h"  // For ledger access

// Forward declarations
typedef struct dap_ledger dap_ledger_t;

/**
 * @brief Register voting TX builders with TX Compose Plugin API
 */
int dap_chain_net_srv_voting_compose_init(void);

/**
 * @brief Unregister voting TX builders
 */
void dap_chain_net_srv_voting_compose_deinit(void);

// ========== TX BUILDER API (creates unsigned transactions) ==========

/**
 * @brief Create poll/voting transaction (PURE TX builder)
 * @param a_ledger Ledger for UTXO selection
 * @param a_question Poll question text
 * @param a_options List of poll options (dap_list_t of char*)
 * @param a_expire_vote Expiration timestamp
 * @param a_max_vote Maximum number of votes
 * @param a_fee Transaction fee
 * @param a_delegated_key_required Require delegated key for voting
 * @param a_vote_changing_allowed Allow changing vote
 * @param a_wallet_addr Wallet address for signing and change
 * @param a_token_ticker Token ticker for the poll
 * @return Unsigned transaction or NULL on error
 */
dap_chain_datum_tx_t *dap_voting_tx_create_poll(
    dap_ledger_t *a_ledger,
    const char *a_question,
    dap_list_t *a_options,
    dap_time_t a_expire_vote,
    uint64_t a_max_vote,
    uint256_t a_fee,
    bool a_delegated_key_required,
    bool a_vote_changing_allowed,
    dap_chain_addr_t *a_wallet_addr,
    const char *a_token_ticker);

/**
 * @brief Create vote transaction (PURE TX builder)
 * @param a_ledger Ledger for transaction lookup
 * @param a_poll_hash Hash of poll to vote on
 * @param a_option_idx Index of selected option
 * @param a_fee Transaction fee
 * @param a_wallet_addr Voter wallet address
 * @param a_cert Certificate for voting (if required by poll)
 * @return Unsigned transaction or NULL on error
 */
dap_chain_datum_tx_t *dap_voting_tx_create_vote(
    dap_ledger_t *a_ledger,
    dap_hash_fast_t *a_poll_hash,
    uint64_t a_option_idx,
    uint256_t a_fee,
    dap_chain_addr_t *a_wallet_addr,
    dap_cert_t *a_cert);

// ========== CLI/RPC WRAPPERS (return JSON responses) ==========

/**
 * @brief CLI wrapper for poll creation
 * @details Creates poll, signs it, puts to mempool, returns JSON response
 */
dap_json_t *dap_chain_tx_compose_poll_create(
    dap_chain_net_id_t a_net_id,
    const char *a_question_str,
    const char *a_options_list_str,
    const char *a_voting_expire_str,
    const char *a_max_votes_count_str,
    const char *a_fee_str, 
    bool a_is_delegated_key,
    bool a_is_vote_changing_allowed,
    dap_chain_addr_t *a_wallet_addr, 
    const char *a_token_str);

/**
 * @brief CLI wrapper for voting
 * @details Creates vote, signs, puts to mempool, returns JSON
 */
dap_json_t *dap_chain_tx_compose_poll_vote(
    dap_chain_net_id_t a_net_id,
    const char *a_hash_str,
    const char *a_cert_name,
    const char *a_fee_str,
    dap_chain_addr_t *a_wallet_addr,
    const char *a_option_idx_str);
