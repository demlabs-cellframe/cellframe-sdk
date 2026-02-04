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

    // Add voting item
    dap_chain_tx_voting_t *l_voting_item = dap_chain_datum_tx_item_voting_create();
    if (!l_voting_item) {
        log_it(L_ERROR, "Failed to create voting item");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    if (dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_voting_item) != 1) {
        log_it(L_ERROR, "Failed to add voting item to transaction");
        DAP_DELETE(l_voting_item);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    DAP_DELETE(l_voting_item);

    // Add question TSD
    size_t l_question_len = dap_strlen(a_question);
    if (l_question_len > DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH) {
        log_it(L_ERROR, "Question too long: %zu > %d", l_question_len, DAP_CHAIN_DATUM_TX_VOTING_QUESTION_MAX_LENGTH);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    dap_chain_tx_tsd_t *l_question_tsd = dap_chain_datum_voting_question_tsd_create(a_question, l_question_len);
    if (!l_question_tsd) {
        log_it(L_ERROR, "Failed to create question TSD");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    if (dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_question_tsd) != 1) {
        log_it(L_ERROR, "Failed to add question TSD to transaction");
        DAP_DELETE(l_question_tsd);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    DAP_DELETE(l_question_tsd);

    // Add options TSDs
    if (l_options_count > DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT) {
        log_it(L_ERROR, "Too many options: %zu > %d", l_options_count, DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_COUNT);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    for (dap_list_t *l_iter = a_options; l_iter; l_iter = l_iter->next) {
        const char *l_option = (const char *)l_iter->data;
        if (!l_option || !*l_option) {
            log_it(L_ERROR, "Empty option in list");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }

        size_t l_option_len = dap_strlen(l_option);
        if (l_option_len > DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_LENGTH) {
            log_it(L_ERROR, "Option too long: %zu > %d", l_option_len, DAP_CHAIN_DATUM_TX_VOTING_OPTION_MAX_LENGTH);
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }

        dap_chain_tx_tsd_t *l_option_tsd = dap_chain_datum_voting_answer_tsd_create(l_option, l_option_len);
        if (!l_option_tsd) {
            log_it(L_ERROR, "Failed to create option TSD");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }

        if (dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_option_tsd) != 1) {
            log_it(L_ERROR, "Failed to add option TSD to transaction");
            DAP_DELETE(l_option_tsd);
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        DAP_DELETE(l_option_tsd);
    }

    // Add expire TSD
    dap_chain_tx_tsd_t *l_expire_tsd = dap_chain_datum_voting_expire_tsd_create(a_expire_vote);
    if (!l_expire_tsd) {
        log_it(L_ERROR, "Failed to create expire TSD");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    if (dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_expire_tsd) != 1) {
        log_it(L_ERROR, "Failed to add expire TSD to transaction");
        DAP_DELETE(l_expire_tsd);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    DAP_DELETE(l_expire_tsd);

    // Add max votes count TSD
    dap_chain_tx_tsd_t *l_max_votes_tsd = dap_chain_datum_voting_max_votes_count_tsd_create(a_max_vote);
    if (!l_max_votes_tsd) {
        log_it(L_ERROR, "Failed to create max votes TSD");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    if (dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_max_votes_tsd) != 1) {
        log_it(L_ERROR, "Failed to add max votes TSD to transaction");
        DAP_DELETE(l_max_votes_tsd);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    DAP_DELETE(l_max_votes_tsd);

    // Add delegated key required TSD
    dap_chain_tx_tsd_t *l_delegated_tsd = dap_chain_datum_voting_delegated_key_required_tsd_create(a_delegated_key_required);
    if (!l_delegated_tsd) {
        log_it(L_ERROR, "Failed to create delegated key required TSD");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    if (dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_delegated_tsd) != 1) {
        log_it(L_ERROR, "Failed to add delegated key required TSD to transaction");
        DAP_DELETE(l_delegated_tsd);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    DAP_DELETE(l_delegated_tsd);

    // Add vote changing allowed TSD
    dap_chain_tx_tsd_t *l_vote_changing_tsd = dap_chain_datum_voting_vote_changing_allowed_tsd_create(a_vote_changing_allowed);
    if (!l_vote_changing_tsd) {
        log_it(L_ERROR, "Failed to create vote changing allowed TSD");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    if (dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_vote_changing_tsd) != 1) {
        log_it(L_ERROR, "Failed to add vote changing allowed TSD to transaction");
        DAP_DELETE(l_vote_changing_tsd);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    DAP_DELETE(l_vote_changing_tsd);

    // Add token TSD
    dap_chain_tx_tsd_t *l_token_tsd = dap_chain_datum_voting_token_tsd_create(a_token_ticker);
    if (!l_token_tsd) {
        log_it(L_ERROR, "Failed to create token TSD");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    if (dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_token_tsd) != 1) {
        log_it(L_ERROR, "Failed to add token TSD to transaction");
        DAP_DELETE(l_token_tsd);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    DAP_DELETE(l_token_tsd);

    log_it(L_INFO, "Created poll TX (unsigned, inputs will be added by compose layer): question='%s', options=%zu, expire=%"DAP_UINT64_FORMAT_U,
           a_question, l_options_count, a_expire_vote);

    return l_tx;
}

/**
 * @brief Create vote transaction (PURE TX builder)
 */
dap_chain_datum_tx_t *dap_voting_tx_create_vote(
    dap_ledger_t *a_ledger,
    dap_hash_sha3_256_t *a_poll_hash,
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
        log_it(L_ERROR, "Poll transaction not found: %s", dap_hash_sha3_256_to_str_static(a_poll_hash));
        return NULL;
    }

    // Parse poll parameters to validate
    dap_chain_datum_tx_voting_params_t *l_poll_params = dap_chain_datum_tx_voting_parse_tsd(l_poll_tx);
    if (!l_poll_params) {
        log_it(L_ERROR, "Failed to parse poll parameters");
        return NULL;
    }

    // Validate poll is still active (not expired)
    dap_time_t l_current_time = dap_time_now();
    if (l_poll_params->voting_expire > 0 && l_current_time > l_poll_params->voting_expire) {
        log_it(L_ERROR, "Poll has expired");
        dap_chain_datum_tx_voting_params_delete(l_poll_params);
        return NULL;
    }

    // Validate option_idx is valid
    uint64_t l_options_count = dap_list_length(l_poll_params->options);
    if (a_option_idx >= l_options_count) {
        log_it(L_ERROR, "Invalid option index: %"DAP_UINT64_FORMAT_U" >= %"DAP_UINT64_FORMAT_U,
               a_option_idx, l_options_count);
        dap_chain_datum_tx_voting_params_delete(l_poll_params);
        return NULL;
    }

    // Check if delegated key is required
    if (l_poll_params->delegate_key_required && !a_cert) {
        log_it(L_ERROR, "Delegated key (certificate) is required for this poll");
        dap_chain_datum_tx_voting_params_delete(l_poll_params);
        return NULL;
    }

    // Check if already voted (if vote changing not allowed)
    // Note: This requires vote registry in ledger, which is verified by the verificator
    // The verificator will reject duplicate votes if vote_changing_allowed is false

    dap_chain_datum_tx_voting_params_delete(l_poll_params);

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

    // Add vote item (poll_hash + option_idx)
    dap_chain_tx_vote_t *l_vote_item = dap_chain_datum_tx_item_vote_create(a_poll_hash, &a_option_idx);
    if (!l_vote_item) {
        log_it(L_ERROR, "Failed to create vote item");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    if (dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_vote_item) != 1) {
        log_it(L_ERROR, "Failed to add vote item to transaction");
        DAP_DELETE(l_vote_item);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    DAP_DELETE(l_vote_item);

    log_it(L_INFO, "Created vote TX (unsigned, signature and inputs will be added by compose layer): poll=%s, option=%"DAP_UINT64_FORMAT_U,
           dap_hash_sha3_256_to_str_static(a_poll_hash), a_option_idx);

    return l_tx;
}

// ========== PLUGIN API CALLBACKS ==========

/**
 * @brief Parameters for voting_poll_create compose callback
 */
typedef struct voting_poll_create_params {
    const char *wallet_name;         // Wallet for signing
    dap_chain_addr_t *wallet_addr;   // Wallet address
    const char *question;             // Poll question
    dap_list_t *options;              // List of options (char*)
    dap_time_t expire_vote;           // Expiration timestamp
    uint64_t max_vote;                // Maximum votes
    uint256_t fee;                    // Transaction fee
    bool delegated_key_required;      // Require delegated key
    bool vote_changing_allowed;       // Allow vote changing
    const char *token_ticker;         // Token ticker for fee
} voting_poll_create_params_t;

/**
 * @brief Parameters for voting_vote compose callback
 */
typedef struct voting_vote_params {
    const char *wallet_name;         // Wallet for signing
    dap_chain_addr_t *wallet_addr;   // Voter wallet address
    dap_hash_sha3_256_t poll_hash;       // Poll hash to vote on
    uint64_t option_idx;             // Selected option index
    uint256_t fee;                   // Transaction fee
    dap_cert_t *cert;                // Certificate (if required by poll)
} voting_vote_params_t;

/**
 * @brief Compose callback for voting poll creation
 * @details Called by Plugin API with selected UTXOs
 */
static dap_chain_datum_t* s_voting_poll_create_compose_cb(
    dap_ledger_t *a_ledger,
    dap_list_t *a_list_used_outs,
    void *a_params
)
{
    voting_poll_create_params_t *l_params = (voting_poll_create_params_t *)a_params;
    if (!l_params || !l_params->wallet_name) {
        log_it(L_ERROR, "Invalid voting poll create parameters or missing wallet name");
        return NULL;
    }

    // 1. Build unsigned TX using PURE builder
    dap_chain_datum_tx_t *l_tx = dap_voting_tx_create_poll(
        a_ledger,
        l_params->question,
        l_params->options,
        l_params->expire_vote,
        l_params->max_vote,
        l_params->fee,
        l_params->delegated_key_required,
        l_params->vote_changing_allowed,
        l_params->wallet_addr,
        l_params->token_ticker
    );

    if (!l_tx) {
        log_it(L_ERROR, "Failed to build voting poll TX");
        return NULL;
    }

    // 2. Add inputs from selected UTXOs
    if (a_list_used_outs) {
        for (dap_list_t *l_iter = a_list_used_outs; l_iter; l_iter = l_iter->next) {
            dap_chain_tx_used_out_t *l_used_out = (dap_chain_tx_used_out_t *)l_iter->data;
            if (!l_used_out) continue;

            if (dap_chain_datum_tx_add_in_item(&l_tx, &l_used_out->tx_prev_hash, l_used_out->tx_out_prev_idx) != 1) {
                log_it(L_ERROR, "Failed to add input item");
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
    }

    // 3. Add fee output
    if (!IS_ZERO_256(l_params->fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, l_params->fee) != 1) {
            log_it(L_ERROR, "Failed to add fee");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }

    // 4. Get sign data
    size_t l_sign_data_size = 0;
    const void *l_sign_data = dap_chain_tx_get_signing_data(l_tx, &l_sign_data_size);
    if (!l_sign_data) {
        log_it(L_ERROR, "Failed to get signing data");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    // 3. Sign via ledger
    dap_sign_t *l_sign = dap_ledger_sign_data(a_ledger, l_params->wallet_name,
                                              l_sign_data, l_sign_data_size, 0);
    if (!l_sign) {
        log_it(L_ERROR, "Failed to sign voting poll TX");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    // 4. Add signature to TX
    if (dap_chain_tx_sign_add(&l_tx, l_sign) != 0) {
        log_it(L_ERROR, "Failed to add signature to TX");
        DAP_DELETE(l_sign);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    DAP_DELETE(l_sign);

    // 5. Convert to datum
    dap_chain_datum_t *l_datum = dap_chain_datum_create(
        DAP_CHAIN_DATUM_TX,
        l_tx,
        dap_chain_datum_tx_get_size(l_tx)
    );
    dap_chain_datum_tx_delete(l_tx);

    if (!l_datum) {
        log_it(L_ERROR, "Failed to create datum from voting poll TX");
        return NULL;
    }

    log_it(L_INFO, "Voting poll datum created successfully");
    return l_datum;
}

/**
 * @brief Compose callback for voting
 * @details Called by Plugin API with selected UTXOs
 */
static dap_chain_datum_t* s_voting_vote_compose_cb(
    dap_ledger_t *a_ledger,
    dap_list_t *a_list_used_outs,
    void *a_params
)
{
    voting_vote_params_t *l_params = (voting_vote_params_t *)a_params;
    if (!l_params || !l_params->wallet_name) {
        log_it(L_ERROR, "Invalid voting vote parameters or missing wallet name");
        return NULL;
    }

    // 1. Build unsigned TX using PURE builder
    dap_chain_datum_tx_t *l_tx = dap_voting_tx_create_vote(
        a_ledger,
        &l_params->poll_hash,
        l_params->option_idx,
        l_params->fee,
        l_params->wallet_addr,
        l_params->cert
    );

    if (!l_tx) {
        log_it(L_ERROR, "Failed to build voting vote TX");
        return NULL;
    }

    // 2. Add inputs from selected UTXOs
    if (a_list_used_outs) {
        for (dap_list_t *l_iter = a_list_used_outs; l_iter; l_iter = l_iter->next) {
            dap_chain_tx_used_out_t *l_used_out = (dap_chain_tx_used_out_t *)l_iter->data;
            if (!l_used_out) continue;

            if (dap_chain_datum_tx_add_in_item(&l_tx, &l_used_out->tx_prev_hash, l_used_out->tx_out_prev_idx) != 1) {
                log_it(L_ERROR, "Failed to add input item");
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
    }

    // 3. Add fee output
    if (!IS_ZERO_256(l_params->fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, l_params->fee) != 1) {
            log_it(L_ERROR, "Failed to add fee");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }

    // 4. Get sign data
    size_t l_sign_data_size = 0;
    const void *l_sign_data = dap_chain_tx_get_signing_data(l_tx, &l_sign_data_size);
    if (!l_sign_data) {
        log_it(L_ERROR, "Failed to get signing data");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    // 5. Sign via ledger
    dap_sign_t *l_sign = dap_ledger_sign_data(a_ledger, l_params->wallet_name,
                                              l_sign_data, l_sign_data_size, 0);
    if (!l_sign) {
        log_it(L_ERROR, "Failed to sign voting vote TX");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    // 6. Add signature to TX
    if (dap_chain_tx_sign_add(&l_tx, l_sign) != 0) {
        log_it(L_ERROR, "Failed to add signature to TX");
        DAP_DELETE(l_sign);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    DAP_DELETE(l_sign);

    // 7. Convert to datum
    dap_chain_datum_t *l_datum = dap_chain_datum_create(
        DAP_CHAIN_DATUM_TX,
        l_tx,
        dap_chain_datum_tx_get_size(l_tx)
    );
    dap_chain_datum_tx_delete(l_tx);

    if (!l_datum) {
        log_it(L_ERROR, "Failed to create datum from voting vote TX");
        return NULL;
    }

    log_it(L_INFO, "Voting vote datum created successfully for poll %s, option %"DAP_UINT64_FORMAT_U,
           dap_hash_sha3_256_to_str_static(&l_params->poll_hash), l_params->option_idx);
    return l_datum;
}

// ========== CLI/RPC WRAPPERS ==========

// TODO: Implement CLI wrappers that return JSON

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

    // Register voting_poll_create TX builder with Plugin API
    int l_ret = dap_chain_tx_compose_register(
        "voting_poll_create",
        s_voting_poll_create_compose_cb,
        NULL  // No user data needed
    );

    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to register voting_poll_create TX builder");
        return -1;
    }

    // Register voting_vote TX builder with Plugin API
    l_ret = dap_chain_tx_compose_register(
        "voting_vote",
        s_voting_vote_compose_cb,
        NULL  // No user data needed
    );

    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to register voting_vote TX builder");
        dap_chain_tx_compose_unregister("voting_poll_create");  // Cleanup on error
        return -1;
    }

    log_it(L_NOTICE, "Voting compose module initialized (poll_create and voting_vote registered)");
    return 0;
}

void dap_chain_net_srv_voting_compose_deinit(void)
{
    log_it(L_NOTICE, "Deinitializing Voting compose module");

    // Unregister TX builders
    dap_chain_tx_compose_unregister("voting_poll_create");
    dap_chain_tx_compose_unregister("voting_vote");

    log_it(L_NOTICE, "Voting compose module deinitialized");
}
