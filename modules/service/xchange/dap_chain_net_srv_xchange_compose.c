/**
 * @file dap_chain_net_srv_xchange_compose.c
 * @brief XChange service transaction compose functions
 *
 * ARCHITECTURE REFACTORED 2025-01-08:
 * - Removed dap_chain_tx_compose_config_t dependency
 * - Direct ledger API usage instead of RPC calls
 * - PURE TX builders (unsigned transaction creation)
 * - Plugin API registration for compose operations
 * - FAIL-FAST principle: no fallbacks, explicit errors
 */

#include "dap_common.h"
#include "dap_chain_net_srv_xchange.h"
#include "dap_chain_net_srv_xchange_compose.h"
#include "dap_chain_tx_compose_api.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_create.h"
#include "dap_chain_net_srv_order.h"
#include "dap_chain_wallet.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_ledger.h"
#include "dap_chain_tx_sign.h"
#include "dap_json_rpc_errors.h"
#include "dap_rand.h"
#include "dap_list.h"
#include "dap_chain_utxo.h"
#include "dap_chain_net.h"
#include "dap_sign.h"

#define LOG_TAG "xchange_compose"

// ========== HELPER FUNCTIONS ==========

/**
 * @brief Create price structure from order conditional transaction
 */
dap_chain_net_srv_xchange_price_t *dap_xchange_price_from_order(
    dap_ledger_t *a_ledger,
    dap_chain_tx_out_cond_t *a_cond_tx,
    dap_time_t a_ts_created,
    dap_hash_sha3_256_t *a_order_hash,
    dap_hash_sha3_256_t *a_hash_out,
    const char *a_token_ticker,
    uint256_t *a_fee,
    bool a_ret_is_invalid)
{
    dap_return_val_if_fail(a_ledger && a_cond_tx && a_order_hash, NULL);

    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
    if (!l_price) {
        log_it(L_ERROR, "Memory allocation failed");
        return NULL;
    }

    l_price->creation_date = a_ts_created;
    dap_strncpy(l_price->token_buy, a_cond_tx->subtype.srv_xchange.buy_token, sizeof(l_price->token_buy) - 1);
    l_price->order_hash = *a_order_hash;
    dap_strncpy(l_price->token_sell, a_token_ticker, sizeof(l_price->token_sell) - 1);
    l_price->token_sell[sizeof(l_price->token_sell) - 1] = '\0';

    if (a_fee)
        l_price->fee = *a_fee;

    l_price->datoshi_sell = a_cond_tx->header.value;
    l_price->creator_addr = a_cond_tx->subtype.srv_xchange.seller_addr;
    l_price->rate = a_cond_tx->subtype.srv_xchange.rate;

    if (!dap_hash_sha3_256_is_blank(a_hash_out)) {
        l_price->tx_hash = *a_hash_out;
        return l_price;
    } else {
        log_it(L_WARNING, "Order has no active conditional transaction");
        DAP_DELETE(l_price);
        return NULL;
    }
}

/**
 * @brief Find last transaction in xchange order chain
 * @return Last conditional output or NULL
 */
dap_chain_tx_out_cond_t *dap_xchange_find_last_tx(
    dap_ledger_t *a_ledger,
    dap_hash_sha3_256_t *a_order_hash,
    dap_chain_addr_t *a_seller_addr,
    dap_time_t *a_ts_created,
    char **a_token_ticker,
    int32_t *a_prev_cond_idx,
    dap_hash_sha3_256_t *a_hash_out)
{
    dap_return_val_if_fail(a_ledger && a_order_hash && a_seller_addr, NULL);

    // Get the initial transaction
    dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(a_ledger, a_order_hash);
    if (!l_tx) {
        log_it(L_ERROR, "Order transaction not found");
        return NULL;
    }

    // Find the conditional output in the initial TX
    dap_chain_tx_out_cond_t *l_tx_out_cond = NULL;
    int32_t l_cond_idx = 0;
    byte_t *l_tx_item;
    size_t l_tx_item_size;
    TX_ITEM_ITER_TX(l_tx_item, l_tx_item_size, l_tx) {
        if (l_tx_item[0] == TX_ITEM_TYPE_OUT_COND) {
            dap_chain_tx_out_cond_t *l_cond = (dap_chain_tx_out_cond_t *)(l_tx_item + 1);
            if (l_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE) {
                l_tx_out_cond = l_cond;
                if (a_prev_cond_idx)
                    *a_prev_cond_idx = l_cond_idx;
                break;
            }
            l_cond_idx++;
        }
    }

    if (!l_tx_out_cond) {
        log_it(L_ERROR, "No xchange conditional output found in order");
        return NULL;
    }

    // Get token ticker from TX
    if (a_token_ticker) {
        const char *l_ticker = dap_ledger_tx_get_token_ticker_by_hash(a_ledger, a_order_hash);
        if (l_ticker)
            *a_token_ticker = dap_strdup(l_ticker);
    }

    // Get timestamp
    if (a_ts_created) {
        *a_ts_created = l_tx->header.ts_created;
    }

    // Save hash
    if (a_hash_out)
        *a_hash_out = *a_order_hash;

    // Now use ledger API to find the final TX in the chain
    dap_hash_sha3_256_t l_final_hash = dap_ledger_get_final_chain_tx_hash(
        a_ledger,
        DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE,
        a_order_hash,
        false  // include spent
    );

    if (dap_hash_sha3_256_is_blank(&l_final_hash)) {
        // Order has no continuation - initial TX is the last
        if (a_prev_cond_idx)
            *a_prev_cond_idx = l_cond_idx;
        return l_tx_out_cond;
    }

    // Get the final TX
    dap_chain_datum_tx_t *l_final_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_final_hash);
    if (!l_final_tx) {
        log_it(L_ERROR, "Final TX not found");
        return NULL;
    }

    // Find conditional output in final TX
    l_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_final_cond = NULL;
    TX_ITEM_ITER_TX(l_tx_item, l_tx_item_size, l_final_tx) {
        if (l_tx_item[0] == TX_ITEM_TYPE_OUT_COND) {
            dap_chain_tx_out_cond_t *l_cond = (dap_chain_tx_out_cond_t *)(l_tx_item + 1);
            if (l_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE) {
                l_final_cond = l_cond;
                if (a_prev_cond_idx)
                    *a_prev_cond_idx = l_cond_idx;
                if (a_ts_created)
                    *a_ts_created = l_final_tx->header.ts_created;
                if (a_hash_out)
                    *a_hash_out = l_final_hash;
                break;
            }
            l_cond_idx++;
        }
    }

    return l_final_cond ? l_final_cond : l_tx_out_cond;
}

// ========== PURE TX BUILDERS (create unsigned transactions) ==========

/**
 * @brief Create xchange order transaction (PURE TX builder)
 */
dap_chain_datum_tx_t* dap_xchange_tx_create_order(
    dap_ledger_t *a_ledger,
    const char *a_token_buy,
    const char *a_token_sell,
    uint256_t a_datoshi_sell,
    uint256_t a_rate,
    uint256_t a_fee,
    dap_chain_addr_t *a_wallet_addr)
{
    dap_return_val_if_fail(a_ledger && a_token_buy && a_token_sell && a_wallet_addr, NULL);

    // Validate parameters (FAIL-FAST)
    if (IS_ZERO_256(a_rate)) {
        log_it(L_ERROR, "Invalid parameter: rate is zero");
        return NULL;
    }
    if (IS_ZERO_256(a_fee)) {
        log_it(L_ERROR, "Invalid parameter: fee is zero");
        return NULL;
    }
    if (IS_ZERO_256(a_datoshi_sell)) {
        log_it(L_ERROR, "Invalid parameter: value_sell is zero");
        return NULL;
    }

    // Get network ID from ledger
    dap_chain_net_id_t l_net_id = dap_ledger_get_net_id(a_ledger);

    // Get native ticker from ledger structure
    const char *l_native_ticker = a_ledger->native_ticker;
    if (!l_native_ticker || !*l_native_ticker) {
        log_it(L_ERROR, "Native ticker not set in ledger");
        return NULL;
    }

    // Check if both tokens exist in ledger
    // (This would require a new ledger API function - for now assume valid)

    // Calculate balance
    uint256_t l_balance_sell = dap_ledger_calc_balance(a_ledger, a_wallet_addr, a_token_sell);
    uint256_t l_value_needed = a_datoshi_sell;

    bool l_sell_is_native = !dap_strcmp(a_token_sell, l_native_ticker);

    if (l_sell_is_native) {
        // If selling native token, add fee to required amount
        uint256_t l_value_with_fee;
        if (SUM_256_256(a_datoshi_sell, a_fee, &l_value_with_fee)) {
            log_it(L_ERROR, "Integer overflow with sum of value and fee");
            return NULL;
        }
        l_value_needed = l_value_with_fee;
    } else {
        // If selling non-native, check native balance for fee
        uint256_t l_balance_native = dap_ledger_calc_balance(a_ledger, a_wallet_addr, l_native_ticker);
        if (compare256(l_balance_native, a_fee) == -1) {
            log_it(L_ERROR, "Not enough native tokens for fee. Need %s, have %s",
                   dap_uint256_to_char(a_fee, NULL), dap_uint256_to_char(l_balance_native, NULL));
            return NULL;
        }
    }

    // Check if enough balance
    if (compare256(l_balance_sell, l_value_needed) == -1) {
        log_it(L_ERROR, "Not enough %s tokens. Need %s, have %s",
               a_token_sell, dap_uint256_to_char(l_value_needed, NULL), dap_uint256_to_char(l_balance_sell, NULL));
        return NULL;
    }

    // Create xchange price structure
    dap_chain_net_srv_xchange_price_t l_price = {
        .datoshi_sell = a_datoshi_sell,
        .rate = a_rate,
        .fee = a_fee,
        .creation_date = dap_time_now()
    };
    dap_strncpy(l_price.token_sell, a_token_sell, sizeof(l_price.token_sell) - 1);
    dap_strncpy(l_price.token_buy, a_token_buy, sizeof(l_price.token_buy) - 1);
    memcpy(&l_price.creator_addr, a_wallet_addr, sizeof(dap_chain_addr_t));

    // Create unsigned TX with conditional output
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        return NULL;
    }

    // Get xchange service UID
    extern const dap_chain_srv_uid_t c_dap_chain_net_srv_xchange_uid;

    // Create conditional output for xchange
    // Parameters: srv_uid, sell_net_id, value_sell, buy_net_id, token_buy, rate, seller_addr, params, params_size
    dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_xchange(
        c_dap_chain_net_srv_xchange_uid,  // service UID
        l_net_id,                          // sell network ID
        a_datoshi_sell,                    // value to sell
        l_net_id,                          // buy network ID (same for now)
        a_token_buy,                       // token to buy
        a_rate,                            // exchange rate
        a_wallet_addr,                     // seller address
        NULL,                              // no extra params
        0                                  // params size
    );
    if (!l_tx_out_cond) {
        log_it(L_ERROR, "Failed to create xchange conditional output");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    if (dap_chain_datum_tx_add_item(&l_tx, (byte_t *)l_tx_out_cond) != 1) {
        log_it(L_ERROR, "Failed to add conditional output to TX");
        DAP_DELETE(l_tx_out_cond);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    DAP_DELETE(l_tx_out_cond);

    // Add fee output
    // NOTE: Inputs will be added by compose callback from UTXO selection
    if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
        log_it(L_ERROR, "Failed to add fee output");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    log_it(L_INFO, "Created xchange order TX (unsigned, inputs will be added by compose layer): sell %s %s for %s at rate %s",
           dap_uint256_to_char(a_datoshi_sell, NULL), a_token_sell, a_token_buy,
           dap_uint256_to_char(a_rate, NULL));

    return l_tx;
}

/**
 * @brief Invalidate xchange order (PURE TX builder)
 */
dap_chain_datum_tx_t *dap_xchange_tx_create_invalidate(
    dap_ledger_t *a_ledger,
    dap_hash_sha3_256_t *a_order_hash,
    uint256_t a_fee,
    dap_chain_addr_t *a_wallet_addr)
{
    dap_return_val_if_fail(a_ledger && a_order_hash && a_wallet_addr, NULL);

    // Validate fee
    if (IS_ZERO_256(a_fee)) {
        log_it(L_ERROR, "Invalid parameter: fee is zero");
        return NULL;
    }

    log_it(L_INFO, "Creating xchange invalidate TX for order %s",
           dap_hash_sha3_256_to_str_static(a_order_hash));

    // 1. Find last TX in order chain
    dap_time_t l_ts_created = 0;
    char *l_token_ticker = NULL;
    int32_t l_prev_cond_idx = 0;
    dap_hash_sha3_256_t l_tx_hash = {};

    dap_chain_tx_out_cond_t *l_cond_out = dap_xchange_find_last_tx(
        a_ledger,
        a_order_hash,
        a_wallet_addr,
        &l_ts_created,
        &l_token_ticker,
        &l_prev_cond_idx,
        &l_tx_hash
    );

    if (!l_cond_out) {
        log_it(L_ERROR, "Cannot find order conditional output");
        return NULL;
    }

    // 2. Verify caller owns the order
    if (memcmp(&l_cond_out->subtype.srv_xchange.seller_addr, a_wallet_addr, sizeof(dap_chain_addr_t)) != 0) {
        log_it(L_ERROR, "Order does not belong to specified wallet");
        DAP_DEL_Z(l_token_ticker);
        return NULL;
    }

    // 3. Get native ticker
    const char *l_native_ticker = a_ledger->native_ticker;
    if (!l_native_ticker || !*l_native_ticker) {
        log_it(L_ERROR, "Native ticker not set in ledger");
        DAP_DEL_Z(l_token_ticker);
        return NULL;
    }

    // 4. Check balance for fee
    uint256_t l_balance = dap_ledger_calc_balance(a_ledger, a_wallet_addr, l_native_ticker);
    if (compare256(l_balance, a_fee) == -1) {
        log_it(L_ERROR, "Not enough balance for fee. Need %s, have %s",
               dap_uint256_to_char(a_fee, NULL), dap_uint256_to_char(l_balance, NULL));
        DAP_DEL_Z(l_token_ticker);
        return NULL;
    }

    // 5. Create unsigned TX
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        DAP_DEL_Z(l_token_ticker);
        return NULL;
    }

    // 6. Add input spending the conditional output
    if (dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_tx_hash, l_prev_cond_idx, 0) != 1) {
        log_it(L_ERROR, "Failed to add conditional input");
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_Z(l_token_ticker);
        return NULL;
    }

    // 7. Add output returning funds to seller
    uint256_t l_value_return = l_cond_out->header.value;
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, l_value_return, l_token_ticker) != 1) {
        log_it(L_ERROR, "Failed to add return output");
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_Z(l_token_ticker);
        return NULL;
    }

    DAP_DEL_Z(l_token_ticker);

    // 8. Add fee output
    // NOTE: Inputs for fee will be added by compose callback from UTXO selection
    if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
        log_it(L_ERROR, "Failed to add fee output");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    log_it(L_INFO, "Created xchange invalidate TX (unsigned, inputs will be added by compose layer)");
    return l_tx;
}

/**
 * @brief Create xchange purchase transaction (PURE TX builder)
 */
dap_chain_datum_tx_t *dap_xchange_tx_create_purchase(
    dap_ledger_t *a_ledger,
    dap_hash_sha3_256_t *a_order_hash,
    uint256_t a_value,
    uint256_t a_fee,
    dap_chain_addr_t *a_wallet_addr)
{
    dap_return_val_if_fail(a_ledger && a_order_hash && a_wallet_addr, NULL);

    // Validate parameters
    if (IS_ZERO_256(a_value)) {
        log_it(L_ERROR, "Invalid parameter: value is zero");
        return NULL;
    }
    if (IS_ZERO_256(a_fee)) {
        log_it(L_ERROR, "Invalid parameter: fee is zero");
        return NULL;
    }

    log_it(L_INFO, "Creating xchange purchase TX for order %s, value %s",
           dap_hash_sha3_256_to_str_static(a_order_hash),
           dap_uint256_to_char(a_value, NULL));

    // 1. Find last TX in order chain
    dap_time_t l_ts_created = 0;
    char *l_token_ticker_sell = NULL;
    int32_t l_prev_cond_idx = 0;
    dap_hash_sha3_256_t l_tx_hash = {};
    dap_chain_addr_t l_seller_addr = {};

    dap_chain_tx_out_cond_t *l_cond_out = dap_xchange_find_last_tx(
        a_ledger,
        a_order_hash,
        &l_seller_addr,
        &l_ts_created,
        &l_token_ticker_sell,
        &l_prev_cond_idx,
        &l_tx_hash
    );

    if (!l_cond_out) {
        log_it(L_ERROR, "Cannot find order conditional output");
        return NULL;
    }

    // 2. Get order parameters
    uint256_t l_rate = l_cond_out->subtype.srv_xchange.rate;
    uint256_t l_value_available = l_cond_out->header.value;
    const char *l_token_buy = l_cond_out->subtype.srv_xchange.buy_token;
    dap_chain_addr_t l_seller = l_cond_out->subtype.srv_xchange.seller_addr;

    // 3. Validate purchase value
    if (compare256(a_value, l_value_available) == 1) {
        log_it(L_ERROR, "Purchase value %s exceeds available %s",
               dap_uint256_to_char(a_value, NULL),
               dap_uint256_to_char(l_value_available, NULL));
        DAP_DEL_Z(l_token_ticker_sell);
        return NULL;
    }

    // 4. Calculate amounts
    // value_to_pay = value * rate (in buy tokens)
    uint256_t l_value_to_pay = {};
    if (MULT_256_256(a_value, l_rate, &l_value_to_pay)) {
        log_it(L_ERROR, "Overflow calculating payment amount");
        DAP_DEL_Z(l_token_ticker_sell);
        return NULL;
    }

    // 5. Check buyer has enough buy tokens
    uint256_t l_balance_buy = dap_ledger_calc_balance(a_ledger, a_wallet_addr, l_token_buy);
    uint256_t l_total_needed = {};
    if (SUM_256_256(l_value_to_pay, a_fee, &l_total_needed)) {
        log_it(L_ERROR, "Overflow calculating total needed");
        DAP_DEL_Z(l_token_ticker_sell);
        return NULL;
    }

    if (compare256(l_balance_buy, l_total_needed) == -1) {
        log_it(L_ERROR, "Not enough %s tokens. Need %s, have %s",
               l_token_buy,
               dap_uint256_to_char(l_total_needed, NULL),
               dap_uint256_to_char(l_balance_buy, NULL));
        DAP_DEL_Z(l_token_ticker_sell);
        return NULL;
    }

    // 6. Create unsigned TX
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        DAP_DEL_Z(l_token_ticker_sell);
        return NULL;
    }

    // 7. Add input spending the conditional output
    if (dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_tx_hash, l_prev_cond_idx, 0) != 1) {
        log_it(L_ERROR, "Failed to add conditional input");
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_Z(l_token_ticker_sell);
        return NULL;
    }

    // 8. Add output to buyer (purchased tokens)
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_wallet_addr, a_value, l_token_ticker_sell) != 1) {
        log_it(L_ERROR, "Failed to add buyer output");
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_Z(l_token_ticker_sell);
        return NULL;
    }

    // 9. Add output to seller (payment)
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_seller, l_value_to_pay, l_token_buy) != 1) {
        log_it(L_ERROR, "Failed to add seller payment output");
        dap_chain_datum_tx_delete(l_tx);
        DAP_DEL_Z(l_token_ticker_sell);
        return NULL;
    }

    // 10. If order not fully filled, create new conditional output with remaining
    uint256_t l_value_remaining = {};
    SUBTRACT_256_256(l_value_available, a_value, &l_value_remaining);

    if (!IS_ZERO_256(l_value_remaining)) {
        // Get xchange service UID
        extern const dap_chain_srv_uid_t c_dap_chain_net_srv_xchange_uid;
        dap_chain_net_id_t l_net_id = dap_ledger_get_net_id(a_ledger);

        // Create new conditional output with remaining amount
        dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_xchange(
            c_dap_chain_net_srv_xchange_uid,
            l_net_id,
            l_value_remaining,
            l_net_id,
            l_token_buy,
            l_rate,
            &l_seller,
            NULL,
            0
        );

        if (!l_tx_out_cond) {
            log_it(L_ERROR, "Failed to create new conditional output");
            dap_chain_datum_tx_delete(l_tx);
            DAP_DEL_Z(l_token_ticker_sell);
            return NULL;
        }

        if (dap_chain_datum_tx_add_item(&l_tx, (byte_t *)l_tx_out_cond) != 1) {
            log_it(L_ERROR, "Failed to add new conditional output to TX");
            DAP_DELETE(l_tx_out_cond);
            dap_chain_datum_tx_delete(l_tx);
            DAP_DEL_Z(l_token_ticker_sell);
            return NULL;
        }
        DAP_DELETE(l_tx_out_cond);
    }

    DAP_DEL_Z(l_token_ticker_sell);

    // 11. Add fee output
    // NOTE: Inputs for payment and fee will be added by compose callback from UTXO selection
    if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
        log_it(L_ERROR, "Failed to add fee output");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    log_it(L_INFO, "Created xchange purchase TX (unsigned, inputs will be added by compose layer): bought %s, paid %s",
           dap_uint256_to_char(a_value, NULL),
           dap_uint256_to_char(l_value_to_pay, NULL));

    return l_tx;
}

// ========== PLUGIN API CALLBACKS ==========

/**
 * @brief Parameters for xchange_order_create compose callback
 */
typedef struct xchange_order_create_params {
    const char *wallet_name;        // Wallet for signing
    dap_chain_addr_t *wallet_addr;  // Wallet address
    const char *token_buy;           // Token to buy
    const char *token_sell;          // Token to sell
    uint256_t datoshi_sell;          // Amount to sell
    uint256_t rate;                  // Exchange rate
    uint256_t fee;                   // Transaction fee
} xchange_order_create_params_t;

/**
 * @brief Compose callback for xchange order creation
 * @details Called by Plugin API with selected UTXOs
 */
static dap_chain_datum_t* s_xchange_order_create_compose_cb(
    dap_ledger_t *a_ledger,
    dap_list_t *a_list_used_outs,
    void *a_params
)
{
    xchange_order_create_params_t *l_params = (xchange_order_create_params_t *)a_params;
    if (!l_params || !l_params->wallet_name) {
        log_it(L_ERROR, "Invalid xchange order create parameters or missing wallet name");
        return NULL;
    }

    // 1. Build unsigned TX using PURE builder
    dap_chain_datum_tx_t *l_tx = dap_xchange_tx_create_order(
        a_ledger,
        l_params->token_buy,
        l_params->token_sell,
        l_params->datoshi_sell,
        l_params->rate,
        l_params->fee,
        l_params->wallet_addr
    );

    if (!l_tx) {
        log_it(L_ERROR, "Failed to build xchange order TX");
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
        log_it(L_ERROR, "Failed to sign xchange order TX");
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
        log_it(L_ERROR, "Failed to create datum from xchange order TX");
        return NULL;
    }

    log_it(L_INFO, "XChange order datum created successfully");
    return l_datum;
}

/**
 * @brief Parameters for xchange_order_invalidate compose callback
 */
typedef struct xchange_order_invalidate_params {
    const char *wallet_name;        // Wallet for signing
    dap_chain_addr_t *wallet_addr;  // Wallet address (must be order owner)
    dap_hash_sha3_256_t *order_hash;    // Order hash to invalidate
    uint256_t fee;                   // Transaction fee
} xchange_order_invalidate_params_t;

/**
 * @brief Compose callback for xchange order invalidation
 */
static dap_chain_datum_t* s_xchange_order_invalidate_compose_cb(
    dap_ledger_t *a_ledger,
    dap_list_t *a_list_used_outs,
    void *a_params
)
{
    xchange_order_invalidate_params_t *l_params = (xchange_order_invalidate_params_t *)a_params;
    if (!l_params || !l_params->wallet_name || !l_params->order_hash) {
        log_it(L_ERROR, "Invalid xchange order invalidate parameters");
        return NULL;
    }

    // 1. Build unsigned TX using PURE builder
    dap_chain_datum_tx_t *l_tx = dap_xchange_tx_create_invalidate(
        a_ledger,
        l_params->order_hash,
        l_params->fee,
        l_params->wallet_addr
    );

    if (!l_tx) {
        log_it(L_ERROR, "Failed to build xchange invalidate TX");
        return NULL;
    }

    // 2. Add inputs from selected UTXOs (for fee payment)
    if (a_list_used_outs) {
        for (dap_list_t *l_iter = a_list_used_outs; l_iter; l_iter = l_iter->next) {
            dap_chain_tx_used_out_t *l_used_out = (dap_chain_tx_used_out_t *)l_iter->data;
            if (!l_used_out) continue;

            if (dap_chain_datum_tx_add_in_item(&l_tx, &l_used_out->tx_prev_hash, l_used_out->tx_out_prev_idx) != 1) {
                log_it(L_ERROR, "Failed to add input item for fee");
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
        log_it(L_ERROR, "Failed to sign xchange invalidate TX");
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
        log_it(L_ERROR, "Failed to create datum from xchange invalidate TX");
        return NULL;
    }

    log_it(L_INFO, "XChange invalidate datum created successfully");
    return l_datum;
}

/**
 * @brief Parameters for xchange_purchase compose callback
 */
typedef struct xchange_purchase_params {
    const char *wallet_name;        // Wallet for signing
    dap_chain_addr_t *wallet_addr;  // Buyer wallet address
    dap_hash_sha3_256_t *order_hash;    // Order hash to purchase from
    uint256_t value;                 // Amount to purchase
    uint256_t fee;                   // Transaction fee
} xchange_purchase_params_t;

/**
 * @brief Compose callback for xchange purchase
 */
static dap_chain_datum_t* s_xchange_purchase_compose_cb(
    dap_ledger_t *a_ledger,
    dap_list_t *a_list_used_outs,
    void *a_params
)
{
    xchange_purchase_params_t *l_params = (xchange_purchase_params_t *)a_params;
    if (!l_params || !l_params->wallet_name || !l_params->order_hash) {
        log_it(L_ERROR, "Invalid xchange purchase parameters");
        return NULL;
    }

    // 1. Build unsigned TX using PURE builder
    dap_chain_datum_tx_t *l_tx = dap_xchange_tx_create_purchase(
        a_ledger,
        l_params->order_hash,
        l_params->value,
        l_params->fee,
        l_params->wallet_addr
    );

    if (!l_tx) {
        log_it(L_ERROR, "Failed to build xchange purchase TX");
        return NULL;
    }

    // 2. Add inputs from selected UTXOs (for payment tokens + fee)
    if (a_list_used_outs) {
        for (dap_list_t *l_iter = a_list_used_outs; l_iter; l_iter = l_iter->next) {
            dap_chain_tx_used_out_t *l_used_out = (dap_chain_tx_used_out_t *)l_iter->data;
            if (!l_used_out) continue;

            if (dap_chain_datum_tx_add_in_item(&l_tx, &l_used_out->tx_prev_hash, l_used_out->tx_out_prev_idx) != 1) {
                log_it(L_ERROR, "Failed to add input item for payment");
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
        log_it(L_ERROR, "Failed to sign xchange purchase TX");
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
        log_it(L_ERROR, "Failed to create datum from xchange purchase TX");
        return NULL;
    }

    log_it(L_INFO, "XChange purchase datum created successfully");
    return l_datum;
}

// ========== CLI/RPC WRAPPERS ==========

// TODO: Implement CLI wrappers that return JSON

// ========== INITIALIZATION ==========

int dap_chain_net_srv_xchange_compose_init(void)
{
    log_it(L_NOTICE, "Initializing XChange compose module");

    // Register xchange_order_create TX builder with Plugin API
    int l_ret = dap_chain_tx_compose_register(
        "xchange_order_create",
        s_xchange_order_create_compose_cb,
        NULL
    );
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to register xchange_order_create TX builder");
        return -1;
    }

    // Register xchange_order_invalidate TX builder
    l_ret = dap_chain_tx_compose_register(
        "xchange_order_invalidate",
        s_xchange_order_invalidate_compose_cb,
        NULL
    );
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to register xchange_order_invalidate TX builder");
        dap_chain_tx_compose_unregister("xchange_order_create");
        return -1;
    }

    // Register xchange_purchase TX builder
    l_ret = dap_chain_tx_compose_register(
        "xchange_purchase",
        s_xchange_purchase_compose_cb,
        NULL
    );
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to register xchange_purchase TX builder");
        dap_chain_tx_compose_unregister("xchange_order_create");
        dap_chain_tx_compose_unregister("xchange_order_invalidate");
        return -1;
    }

    log_it(L_NOTICE, "XChange compose module initialized (all 3 TX builders registered)");
    return 0;
}

void dap_chain_net_srv_xchange_compose_deinit(void)
{
    log_it(L_NOTICE, "Deinitializing XChange compose module");

    // Unregister all TX builders
    dap_chain_tx_compose_unregister("xchange_order_create");
    dap_chain_tx_compose_unregister("xchange_order_invalidate");
    dap_chain_tx_compose_unregister("xchange_purchase");

    log_it(L_NOTICE, "XChange compose module deinitialized");
}
