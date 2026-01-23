/**
 * @file dex_migration_tests.c
 * @brief Legacy SRV_XCHANGE -> SRV_DEX migration tests
 */

#include "dex_migration_tests.h"
#include "dap_chain_net_srv_xchange.h"
#include "dap_chain_net_srv_dex.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_policy.h"
#include "dap_chain_ledger.h"
#include "dap_chain_wallet.h"
#include "dap_cli_server.h"

#undef LOG_TAG
#define LOG_TAG "dex_migration_tests"

static int s_xchange_create_order(dex_test_fixture_t *a_f, dap_chain_wallet_t *a_wallet,
                                  const char *a_token_sell, const char *a_token_buy,
                                  uint256_t a_value_sell, uint256_t a_rate, uint256_t a_fee,
                                  dap_hash_fast_t *a_out_hash, int *a_out_idx)
{
    dap_ret_val_if_any(-1, !a_f, !a_f->net, !a_f->net->net, !a_f->net->net->pub.ledger, !a_wallet,
                       !a_token_sell || !*a_token_sell, !a_token_buy || !*a_token_buy, !a_out_hash,
                       IS_ZERO_256(a_value_sell), IS_ZERO_256(a_rate), IS_ZERO_256(a_fee));
    
    dap_chain_net_t *l_net = a_f->net->net;
    dap_ledger_t *l_ledger = l_net->pub.ledger;
    const char *l_native = l_net->pub.native_ticker;
    bool l_single_channel = !dap_strcmp(a_token_sell, l_native);
    
    dap_chain_addr_t *l_addr_tmp = dap_chain_wallet_get_addr(a_wallet, l_net->pub.id);
    if (!l_addr_tmp)
        return -2;
    dap_chain_addr_t l_addr = *l_addr_tmp;
    DAP_DELETE(l_addr_tmp);
    
    uint256_t l_net_fee = uint256_0, l_total_fee = a_fee, l_fee_transfer = uint256_0;
    dap_chain_addr_t l_net_addr = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(l_net->pub.id, &l_net_fee, &l_net_addr);
    if (l_net_fee_used)
        SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);
    
    uint256_t l_value_need = a_value_sell, l_value_transfer = uint256_0;
    dap_list_t *l_fee_outs = NULL, *l_sell_outs = NULL;
    
    if (l_single_channel)
        SUM_256_256(l_value_need, l_total_fee, &l_value_need);
    else if (!IS_ZERO_256(l_total_fee)) {
        l_fee_outs = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native, &l_addr, l_total_fee, &l_fee_transfer);
        if (!l_fee_outs)
            return -3;
    }
    
    l_sell_outs = dap_ledger_get_list_tx_outs_with_val(l_ledger, a_token_sell, &l_addr, l_value_need, &l_value_transfer);
    if (!l_sell_outs) {
        dap_list_free_full(l_fee_outs, NULL);
        return -4;
    }
    
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        dap_list_free_full(l_sell_outs, NULL);
        dap_list_free_full(l_fee_outs, NULL);
        return -5;
    }
    
    uint256_t l_added = dap_chain_datum_tx_add_in_item_list(&l_tx, l_sell_outs);
    dap_list_free_full(l_sell_outs, NULL);
    if (!EQUAL_256(l_added, l_value_transfer)) {
        dap_list_free_full(l_fee_outs, NULL);
        dap_chain_datum_tx_delete(l_tx);
        return -6;
    }
    
    if (!l_single_channel && l_fee_outs) {
        uint256_t l_fee_added = dap_chain_datum_tx_add_in_item_list(&l_tx, l_fee_outs);
        dap_list_free_full(l_fee_outs, NULL);
        if (!EQUAL_256(l_fee_added, l_fee_transfer)) {
            dap_chain_datum_tx_delete(l_tx);
            return -7;
        }
    }
    
    dap_chain_tx_out_cond_t *l_out = dap_chain_datum_tx_item_out_cond_create_srv_xchange(
        (dap_chain_net_srv_uid_t){.uint64 = DAP_CHAIN_NET_SRV_XCHANGE_ID}, l_net->pub.id, a_value_sell,
        l_net->pub.id, a_token_buy, a_rate, &l_addr, NULL, 0);
    if (!l_out) {
        dap_chain_datum_tx_delete(l_tx);
        return -8;
    }
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_out);
    DAP_DELETE(l_out);
    
    int l_out_idx = 0;
    if (!dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_out_idx)) {
        dap_chain_datum_tx_delete(l_tx);
        return -9;
    }
    if (a_out_idx)
        *a_out_idx = l_out_idx;
    
    if (l_net_fee_used && dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_net_addr, l_net_fee, l_native) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return -10;
    }
    if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return -11;
    }
    
    uint256_t l_value_back = uint256_0;
    SUBTRACT_256_256(l_value_transfer, l_value_need, &l_value_back);
    if (!IS_ZERO_256(l_value_back)) {
        const char *l_back_token = l_single_channel ? l_native : a_token_sell;
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr, l_value_back, l_back_token) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return -12;
        }
    }
    
    if (!l_single_channel) {
        uint256_t l_fee_back = uint256_0;
        SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_fee_back);
        if (!IS_ZERO_256(l_fee_back) &&
            dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr, l_fee_back, l_native) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return -13;
        }
    }
    
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(a_wallet, 0);
    if (!l_key || dap_chain_datum_tx_add_sign_item(&l_tx, l_key) != 1) {
        dap_enc_key_delete(l_key);
        dap_chain_datum_tx_delete(l_tx);
        return -14;
    }
    dap_enc_key_delete(l_key);
    
    dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), a_out_hash);
    if (dap_ledger_tx_add(l_ledger, l_tx, a_out_hash, false, NULL) != 0) {
        dap_chain_datum_tx_delete(l_tx);
        return -15;
    }
    
    return 0;
}

static int s_apply_xchange_cutoffs(dex_test_fixture_t *a_f, dap_time_t a_legacy_ts, dap_time_t a_migrate_ts)
{
    dap_ret_val_if_any(-1, !a_f, !a_f->net, !a_f->net->net);
    char *l_nums[] = { "16", "17" };
    dap_chain_policy_t *l_deactivate = dap_chain_policy_create_deactivate(l_nums, 2);
    dap_chain_policy_t *l_legacy = dap_chain_policy_create_activate(DAP_CHAIN_POLICY_XCHANGE_LEGACY_TX_CUTOFF, a_legacy_ts, 0, (dap_chain_id_t){0}, 0);
    dap_chain_policy_t *l_migrate = dap_chain_policy_create_activate(DAP_CHAIN_POLICY_XCHANGE_MIGRATE_CUTOFF, a_migrate_ts, 0, (dap_chain_id_t){0}, 0);
    if (!l_deactivate || !l_legacy || !l_migrate)
        return -2;
    if (dap_chain_policy_apply(l_deactivate, a_f->net->net->pub.id) ||
            dap_chain_policy_apply(l_legacy, a_f->net->net->pub.id) ||
            dap_chain_policy_apply(l_migrate, a_f->net->net->pub.id))
        return -3;
    return 0;
}

static int s_dex_history_summary_by_order(dex_test_fixture_t *a_f, const dap_hash_fast_t *a_order_hash)
{
    dap_ret_val_if_any(-1, !a_f, !a_f->net, !a_f->net->net, !a_order_hash);
    const char *l_hash_str = dap_chain_hash_fast_to_str_static(a_order_hash);
    char l_json_request[1024];
    snprintf(l_json_request, sizeof(l_json_request),
        "{\"method\":\"srv_dex\",\"params\":[\"srv_dex;history;-net;%s;-order;%s;-view;summary\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
        a_f->net->net->pub.name, l_hash_str);
    char *l_reply = dap_cli_cmd_exec(l_json_request);
    if (!l_reply)
        return -2;
    json_object *l_json = json_tokener_parse(l_reply);
    DAP_DELETE(l_reply);
    if (!l_json)
        return -3;
    json_object *l_error = NULL;
    if (json_object_object_get_ex(l_json, "error", &l_error)) {
        log_it(L_ERROR, "DEX history summary error: %s", json_object_to_json_string(l_error));
        json_object_put(l_json);
        return -4;
    }
    json_object *l_result_raw = NULL;
    if (!json_object_object_get_ex(l_json, "result", &l_result_raw)) {
        json_object_put(l_json);
        return -5;
    }
    json_object *l_result = json_object_is_type(l_result_raw, json_type_array)
        ? json_object_array_get_idx(l_result_raw, 0) : l_result_raw;
    if (l_result) {
        json_object *l_summary = NULL;
        if (json_object_object_get_ex(l_result, "summary", &l_summary))
            log_it(L_NOTICE, "DEX order summary: %s", json_object_to_json_string(l_summary));
    }
    json_object_put(l_json);
    return 0;
}

static int s_dex_cancel_order(dex_test_fixture_t *a_f, const dap_hash_fast_t *a_order_hash)
{
    dap_ret_val_if_any(-1, !a_f, !a_f->net, !a_f->net->net, !a_order_hash);
    dap_chain_datum_tx_t *l_cancel_tx = NULL;
    dap_chain_net_srv_dex_remove_error_t l_err = dap_chain_net_srv_dex_remove(
        a_f->net->net, (dap_hash_fast_t *)a_order_hash, a_f->network_fee, a_f->alice, &l_cancel_tx);
    if (l_err != DEX_REMOVE_ERROR_OK || !l_cancel_tx)
        return -2;
    dap_hash_fast_t l_cancel_hash = {};
    dap_hash_fast(l_cancel_tx, dap_chain_datum_tx_get_size(l_cancel_tx), &l_cancel_hash);
    if (dap_ledger_tx_add(a_f->net->net->pub.ledger, l_cancel_tx, &l_cancel_hash, false, NULL) != 0) {
        dap_chain_datum_tx_delete(l_cancel_tx);
        return -3;
    }
    return 0;
}

int run_migration_tests(dex_test_fixture_t *f)
{
    dap_ret_val_if_any(-1, !f, !f->net, !f->net->net, !f->net->net->pub.ledger);
    
    log_it(L_NOTICE, "=== LEGACY MIGRATION TESTS (SRV_XCHANGE -> SRV_DEX) ===");
    
    const char *l_token_sell = "KEL";
    const char *l_token_buy = "USDC";
    uint8_t l_fee_cfg = 0x80 | 10;
    
    int l_ret = test_decree_pair_add(f->net->ledger, l_token_sell, l_token_buy, f->net->net->pub.id, l_fee_cfg);
    if (l_ret != 0) {
        log_it(L_ERROR, "Pair add failed for %s/%s: %d", l_token_sell, l_token_buy, l_ret);
        return -2;
    }
    
    uint256_t l_value_sell = dap_chain_coins_to_balance("100.0");
    uint256_t l_rate_old = dap_chain_coins_to_balance("2.0");
    uint256_t l_rate_new = dap_chain_coins_to_balance("2.5");
    
    dap_hash_fast_t l_xchange_hash_a = {}, l_xchange_hash_b = {};
    int l_xchange_out_idx_a = -1, l_xchange_out_idx_b = -1;
    l_ret = s_xchange_create_order(f, f->alice, l_token_sell, l_token_buy, l_value_sell, l_rate_old, f->network_fee,
                                   &l_xchange_hash_a, &l_xchange_out_idx_a);
    if (l_ret != 0) {
        log_it(L_ERROR, "Legacy XCHANGE order create A failed: %d", l_ret);
        return -3;
    }
    l_ret = s_xchange_create_order(f, f->alice, l_token_sell, l_token_buy, l_value_sell, l_rate_old, f->network_fee,
                                   &l_xchange_hash_b, &l_xchange_out_idx_b);
    if (l_ret != 0) {
        log_it(L_ERROR, "Legacy XCHANGE order create B failed: %d", l_ret);
        return -4;
    }
    
    dap_chain_datum_tx_t *l_migrate_tx = NULL;
    dap_chain_net_srv_dex_migrate_error_t l_err = dap_chain_net_srv_dex_migrate(
        f->net->net, &l_xchange_hash_a, l_rate_new, f->network_fee, f->alice, &l_migrate_tx);
    if (l_err != DEX_MIGRATE_ERROR_OK || !l_migrate_tx) {
        log_it(L_ERROR, "DEX migrate compose failed: %d", l_err);
        return -5;
    }
    
    dap_hash_fast_t l_migrate_hash = {};
    dap_hash_fast(l_migrate_tx, dap_chain_datum_tx_get_size(l_migrate_tx), &l_migrate_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, l_migrate_tx, &l_migrate_hash, false, NULL) != 0) {
        dap_chain_datum_tx_delete(l_migrate_tx);
        log_it(L_ERROR, "DEX migrate tx rejected by ledger");
        return -6;
    }
    
    if (l_xchange_out_idx_a < 0 ||
        !dap_ledger_tx_hash_is_used_out_item(f->net->net->pub.ledger, &l_xchange_hash_a, l_xchange_out_idx_a, NULL)) {
        log_it(L_ERROR, "Legacy XCHANGE out was not consumed by migration");
        return -7;
    }
    
    dex_order_info_t l_info = {};
    if (test_dex_order_get_info(f->net->net->pub.ledger, &l_migrate_hash, &l_info) != 0) {
        log_it(L_ERROR, "DEX order not found after migration");
        return -8;
    }
    
    if (dap_strcmp(l_info.token_sell, l_token_sell) || dap_strcmp(l_info.token_buy, l_token_buy)) {
        log_it(L_ERROR, "Migrated order tokens mismatch: sell=%s buy=%s", l_info.token_sell, l_info.token_buy);
        return -9;
    }
    
    if (compare256(l_info.value, l_value_sell) != 0) {
        log_it(L_ERROR, "Migrated order value mismatch");
        return -10;
    }
    
    if (compare256(l_info.price, l_rate_new) != 0) {
        log_it(L_ERROR, "Migrated order rate mismatch");
        return -11;
    }
    
    if (!dap_chain_addr_compare(&l_info.seller_addr, &f->alice_addr)) {
        log_it(L_ERROR, "Migrated order seller mismatch");
        return -12;
    }
    
    if (l_info.min_fill != 0) {
        log_it(L_ERROR, "Migrated order min_fill mismatch: %u", l_info.min_fill);
        return -13;
    }

    dap_time_t l_bc_time = dap_ledger_get_blockchain_time(f->net->net->pub.ledger);
    if (l_bc_time < 2) {
        log_it(L_ERROR, "Blockchain time too small for cutoff test");
        return -14;
    }
    dap_time_t l_cutoff_ts = l_bc_time - 1;
    l_ret = s_apply_xchange_cutoffs(f, l_cutoff_ts, l_cutoff_ts);
    if (l_ret != 0) {
        log_it(L_ERROR, "Policy cutoff apply failed: %d", l_ret);
        return -15;
    }

    dap_hash_fast_t l_xchange_hash_c = {};
    int l_xchange_out_idx_c = -1;
    l_ret = s_xchange_create_order(f, f->alice, l_token_sell, l_token_buy, l_value_sell, l_rate_old, f->network_fee,
                                   &l_xchange_hash_c, &l_xchange_out_idx_c);
    if (l_ret == 0) {
        log_it(L_ERROR, "Legacy XCHANGE order create accepted after cutoff");
        return -16;
    }

    dap_chain_datum_tx_t *l_migrate_tx_fail = NULL;
    l_err = dap_chain_net_srv_dex_migrate(f->net->net, &l_xchange_hash_b, l_rate_new, f->network_fee, f->alice, &l_migrate_tx_fail);
    if (l_err != DEX_MIGRATE_ERROR_OK || !l_migrate_tx_fail) {
        log_it(L_ERROR, "DEX migrate compose failed after cutoff: %d", l_err);
        return -17;
    }
    dap_hash_fast_t l_migrate_hash_fail = {};
    dap_hash_fast(l_migrate_tx_fail, dap_chain_datum_tx_get_size(l_migrate_tx_fail), &l_migrate_hash_fail);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, l_migrate_tx_fail, &l_migrate_hash_fail, false, NULL) == 0) {
        dap_chain_datum_tx_delete(l_migrate_tx_fail);
        log_it(L_ERROR, "DEX migrate tx accepted after cutoff");
        return -18;
    }
    dap_chain_datum_tx_delete(l_migrate_tx_fail);
    
    l_ret = s_dex_history_summary_by_order(f, &l_migrate_hash);
    if (l_ret != 0) {
        log_it(L_ERROR, "DEX history summary failed: %d", l_ret);
        return -19;
    }
    l_ret = s_dex_cancel_order(f, &l_migrate_hash);
    if (l_ret != 0) {
        log_it(L_ERROR, "DEX cancel failed: %d", l_ret);
        return -20;
    }

    log_it(L_NOTICE, "✓ Migration test passed: %s -> %s", dap_chain_hash_fast_to_str_static(&l_xchange_hash_a),
           dap_chain_hash_fast_to_str_static(&l_migrate_hash));
    return 0;
}
