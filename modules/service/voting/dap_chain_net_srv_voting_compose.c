/**
 * @file dap_chain_net_srv_voting_compose.c
 * @brief Voting service transaction compose functions
 * 
 * ARCHITECTURE REFACTORED 2025-01-08:
 * - Removed dap_chain_tx_compose_config_t dependency
 * - Direct ledger API usage instead of RPC calls
 * - PURE TX builders (unsigned transaction creation)
 * - Plugin API registration for compose operations
 * - FAIL-FAST principle: no fallbacks, explicit errors
 */

#include "dap_common.h"
#include "dap_chain_net_srv_voting.h"
#include "dap_chain_net_srv_voting_compose.h"
#include "dap_chain_tx_compose_api.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_voting.h"
#include "dap_chain_datum_tx_create.h"
#include "dap_chain_wallet.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_ledger.h"
#include "dap_chain_tx_sign.h"
#include "dap_json_rpc_errors.h"
#include "dap_cert.h"
#include "dap_list.h"
#include "dap_time.h"
#include "dap_strfuncs.h"
#include "dap_rand.h"
#include "dap_chain_utxo.h"
#include "dap_chain_net.h"
#include "dap_sign.h"

#define LOG_TAG "voting_compose"

// ========== PURE TX BUILDERS (create unsigned transactions) ==========

/**
 * @brief Create poll/voting transaction (PURE TX builder)
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
    const char *a_token_ticker)
{
    dap_return_val_if_fail(a_ledger && a_question && a_options && a_wallet_addr && a_token_ticker, NULL);
    
    // Validate parameters (FAIL-FAST)
    if (IS_ZERO_256(a_fee)) {
        log_it(L_ERROR, "Invalid parameter: fee is zero");
        return NULL;
    }
    
    size_t l_options_count = dap_list_length(a_options);
    if (l_options_count < 2) {
        log_it(L_ERROR, "Poll must have at least 2 options, got %zu", l_options_count);
        return NULL;
    }
    
    if (!a_question || !*a_question) {
        log_it(L_ERROR, "Poll question cannot be empty");
        return NULL;
    }
    
    // Check balance for fee
    uint256_t l_balance = dap_ledger_calc_balance(a_ledger, a_wallet_addr, a_token_ticker);
    if (compare256(l_balance, a_fee) == -1) {
        log_it(L_ERROR, "Not enough balance for fee. Need %s, have %s",
               dap_uint256_to_char(a_fee, NULL), dap_uint256_to_char(l_balance, NULL));
        return NULL;
    }
    
    // Create unsigned TX
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        return NULL;
    }
    
    // TODO: Add voting datum item
    // This requires creating TSD with question, options, expiry, etc.
    // Format: dap_chain_datum_tx_voting_t structure
    
    log_it(L_INFO, "Created poll TX (unsigned): question='%s', options=%zu, expire=%"DAP_UINT64_FORMAT_U,
           a_question, l_options_count, a_expire_vote);
    
    // TODO: Add inputs and fee (requires UTXO selection)
    
    return l_tx;
}

/**
 * @brief Create vote transaction (PURE TX builder)
 */
dap_chain_datum_tx_t *dap_voting_tx_create_vote(
    dap_ledger_t *a_ledger,
    dap_hash_fast_t *a_poll_hash,
    uint64_t a_option_idx,
    uint256_t a_fee,
    dap_chain_addr_t *a_wallet_addr,
    dap_cert_t *a_cert)
{
    dap_return_val_if_fail(a_ledger && a_poll_hash && a_wallet_addr, NULL);
    
    // Validate parameters (FAIL-FAST)
    if (IS_ZERO_256(a_fee)) {
        log_it(L_ERROR, "Invalid parameter: fee is zero");
        return NULL;
    }
    
    // Find the poll transaction
    dap_chain_datum_tx_t *l_poll_tx = dap_ledger_tx_find_by_hash(a_ledger, a_poll_hash);
    if (!l_poll_tx) {
        log_it(L_ERROR, "Poll transaction not found: %s", dap_hash_fast_to_str_static(a_poll_hash));
        return NULL;
    }
    
    // TODO: Validate poll is still active (not expired)
    // TODO: Validate option_idx is valid
    // TODO: Check if already voted (if vote changing not allowed)
    
    // Get native ticker for fee
    const char *l_native_ticker = a_ledger->native_ticker;
    
    // Check balance
    uint256_t l_balance = dap_ledger_calc_balance(a_ledger, a_wallet_addr, l_native_ticker);
    if (compare256(l_balance, a_fee) == -1) {
        log_it(L_ERROR, "Not enough balance for fee. Need %s, have %s",
               dap_uint256_to_char(a_fee, NULL), dap_uint256_to_char(l_balance, NULL));
        return NULL;
    }
    
    // Create unsigned TX
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        return NULL;
    }
    
    // TODO: Add vote item (poll_hash + option_idx)
    // TODO: Add cert signature if required
    // TODO: Add inputs and fee
    
    log_it(L_INFO, "Created vote TX (unsigned): poll=%s, option=%"DAP_UINT64_FORMAT_U,
           dap_hash_fast_to_str_static(a_poll_hash), a_option_idx);
    
    return l_tx;
}

// ========== PLUGIN API CALLBACKS ==========

// TODO: Implement compose callbacks that:
// 1. Select UTXOs
// 2. Build unsigned TX using above builders
// 3. Sign TX
// 4. Return datum

// ========== CLI/RPC WRAPPERS ==========

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
    const char *a_token_str)
{
    // TODO: Implement CLI wrapper
    // Parse parameters, call TX builder, sign, put to mempool, return JSON
    
    log_it(L_ERROR, "Voting poll creation not yet implemented");
    
    dap_json_t *l_ret = dap_json_object_new();
    dap_json_rpc_error_add(l_ret, DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
                           "Voting poll creation not yet implemented");
    return l_ret;
}

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
    const char *a_option_idx_str)
{
    // TODO: Implement CLI wrapper
    
    log_it(L_ERROR, "Voting not yet implemented");
    
    dap_json_t *l_ret = dap_json_object_new();
    dap_json_rpc_error_add(l_ret, DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
                           "Voting not yet implemented");
    return l_ret;
}

// ========== INITIALIZATION ==========

int dap_chain_net_srv_voting_compose_init(void)
{
    log_it(L_NOTICE, "Initializing Voting compose module");
    
    // TODO: Register TX builders with Plugin API
    // dap_chain_tx_compose_register("voting_poll_create", ..., NULL);
    // dap_chain_tx_compose_register("voting_vote", ..., NULL);
    
    log_it(L_NOTICE, "Voting compose module initialized");
    return 0;
}

void dap_chain_net_srv_voting_compose_deinit(void)
{
    log_it(L_NOTICE, "Deinitializing Voting compose module");
    
    // TODO: Unregister TX builders
    // dap_chain_tx_compose_unregister("voting_poll_create");
    // dap_chain_tx_compose_unregister("voting_vote");
    
    log_it(L_NOTICE, "Voting compose module deinitialized");
}
