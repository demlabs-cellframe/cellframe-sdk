/**
 * @file dap_chain_net_srv_voting_compose.h
 * @brief Voting service transaction compose API
 */

#pragma once

#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_net_srv_voting.h"
#include "dap_chain_tx_compose.h"  // Voting depends on compose
#include "dap_json.h"
#include "dap_cert.h"

/**
 * @brief Register voting compose callbacks with compose module
 */
int dap_chain_net_srv_voting_compose_init(void);

// Voting compose functions (moved from modules/compose/)

/**
 * @brief CLI voting create compose
 */
dap_json_t* dap_cli_voting_compose(
    const char *a_net_name, 
    const char *a_question_str, 
    const char *a_options_list_str, 
    const char *a_voting_expire_str, 
    const char *a_max_votes_count_str,
    const char *a_fee_str, 
    bool a_is_delegated_key, 
    bool a_is_vote_changing_allowed,
    dap_chain_addr_t *a_wallet_addr, 
    const char *a_token_str, 
    const char *a_url_str,
    uint16_t a_port, 
    const char *a_enc_cert);

/**
 * @brief Create voting transaction
 */
dap_chain_datum_tx_t* dap_chain_net_vote_create_compose(
    const char *a_question, 
    dap_list_t *a_options, 
    dap_time_t a_expire_vote,
    uint64_t a_max_votes_count, 
    uint256_t a_fee, 
    bool a_is_delegated_key,
    bool a_is_vote_changing_allowed, 
    dap_chain_addr_t *a_wallet_addr,
    const char *a_token_ticker, 
    compose_config_t *a_config);

/**
 * @brief CLI vote compose
 */
dap_json_t* dap_cli_vote_compose(
    const char *a_net_str, 
    const char *a_hash_str, 
    const char *a_cert_name, 
    const char *a_fee_str, 
    dap_chain_addr_t *a_wallet_addr, 
    const char *a_option_idx_str, 
    const char *a_url_str,
    uint16_t a_port, 
    const char *a_enc_cert);

/**
 * @brief Create vote transaction
 */
dap_chain_datum_tx_t* dap_chain_net_vote_voting_compose(
    dap_cert_t *a_cert, 
    uint256_t a_fee, 
    dap_chain_addr_t *a_wallet_addr, 
    dap_hash_fast_t a_hash,
    uint64_t a_option_idx, 
    compose_config_t *a_config);

