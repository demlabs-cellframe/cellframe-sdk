/**
 * @file dex_migration_tests.c
 * @brief Legacy SRV_XCHANGE -> SRV_DEX migration tests
 */

#include "dex_migration_tests.h"
#include "dap_chain_net_srv_xchange.h"
#include "dap_chain_net_srv_dex.h"
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
                       !a_token_sell || !*a_token_sell, !a_token_buy || !*a_token_buy,
                       IS_ZERO_256(a_value_sell), IS_ZERO_256(a_rate), IS_ZERO_256(a_fee));
    
    dap_chain_net_t *l_net = a_f->net->net;
    char *l_hash_str = NULL;
    dap_chain_datum_tx_t *l_tx = NULL;
    int l_ret = dap_chain_net_srv_xchange_create(l_net, a_token_buy, a_token_sell, a_value_sell,
                                                 a_rate, a_fee, a_wallet, &l_hash_str, &l_tx);
    if (l_hash_str)
        DAP_DELETE(l_hash_str);
    if (l_ret != XCHANGE_CREATE_ERROR_OK || !l_tx)
        return l_ret ? -l_ret : -2;
    
    int l_out_idx = 0;
    if (!dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE, &l_out_idx)) {
        dap_chain_datum_tx_delete(l_tx);
        return -6;
    }
    
    dap_hash_fast_t l_hash = {};
    dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_hash);
    if (dap_ledger_tx_add(l_net->pub.ledger, l_tx, &l_hash, false, NULL) != 0) {
        dap_chain_datum_tx_delete(l_tx);
        return -7;
    }
    
    if (a_out_hash)
        *a_out_hash = l_hash;
    if (a_out_idx)
        *a_out_idx = l_out_idx;
    
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

static int s_xchange_orders_find(dex_test_fixture_t *a_f, const dap_chain_addr_t *a_addr,
                                 const dap_hash_fast_t *a_root_hash, dap_hash_fast_t *a_out_tail,
                                 bool *a_out_can_migrate)
{
    dap_ret_val_if_any(-1, !a_f, !a_f->net, !a_f->net->net, !a_addr, !a_root_hash, !a_out_tail);
    const char *l_addr_str = dap_chain_addr_to_str_static(a_addr);
    char l_json_request[1024];
    snprintf(l_json_request, sizeof(l_json_request),
        "{\"method\":\"srv_xchange\",\"params\":[\"srv_xchange;orders;-net;%s;-addr;%s\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
        a_f->net->net->pub.name, l_addr_str);
    char *l_reply = dap_cli_cmd_exec(l_json_request);
    if (!l_reply)
        return -2;
    json_object *l_json = json_tokener_parse(l_reply);
    DAP_DELETE(l_reply);
    if (!l_json)
        return -3;
    json_object *l_error = NULL;
    if (json_object_object_get_ex(l_json, "error", &l_error)) {
        log_it(L_ERROR, "XCHANGE orders error: %s", json_object_to_json_string(l_error));
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
    if (!l_result) {
        json_object_put(l_json);
        return -6;
    }
    json_object *l_orders = NULL;
    if (!json_object_object_get_ex(l_result, "orders", &l_orders) ||
            !json_object_is_type(l_orders, json_type_array)) {
        json_object_put(l_json);
        return -7;
    }
    
    size_t l_count = json_object_array_length(l_orders);
    for (size_t i = 0; i < l_count; i++) {
        json_object *l_item = json_object_array_get_idx(l_orders, i);
        json_object *l_hash_obj = NULL, *l_root_obj = NULL;
        const char *l_hash_str = json_object_object_get_ex(l_item, "order_hash", &l_hash_obj)
            ? json_object_get_string(l_hash_obj) : NULL;
        const char *l_root_str = json_object_object_get_ex(l_item, "order_root", &l_root_obj)
            ? json_object_get_string(l_root_obj) : NULL;
        if (!l_hash_str)
            continue;
        dap_hash_fast_t l_hash = {}, l_root = {};
        if (dap_chain_hash_fast_from_str(l_hash_str, &l_hash))
            continue;
        if (l_root_str && !dap_chain_hash_fast_from_str(l_root_str, &l_root)) {
            if (dap_hash_fast_compare(&l_root, a_root_hash)) {
                *a_out_tail = l_hash;
                if (a_out_can_migrate) {
                    json_object *l_avail = NULL;
                    const char *l_avail_str = json_object_object_get_ex(l_item, "availability", &l_avail)
                        ? json_object_get_string(l_avail) : NULL;
                    *a_out_can_migrate = l_avail_str && !dap_strcmp(l_avail_str, "migrate");
                }
                json_object_put(l_json);
                return 0;
            }
        } else if (dap_hash_fast_compare(&l_hash, a_root_hash)) {
            *a_out_tail = l_hash;
            if (a_out_can_migrate) {
                json_object *l_avail = NULL;
                const char *l_avail_str = json_object_object_get_ex(l_item, "availability", &l_avail)
                    ? json_object_get_string(l_avail) : NULL;
                *a_out_can_migrate = l_avail_str && !dap_strcmp(l_avail_str, "migrate");
            }
            json_object_put(l_json);
            return 0;
        }
    }
    
    json_object_put(l_json);
    return -8;
}

static int s_tx_out_cond_idx(dap_chain_datum_tx_t *a_tx, dap_chain_tx_out_cond_subtype_t a_subtype)
{
    dap_ret_val_if_any(-1, !a_tx);
    int l_idx = 0;
    byte_t *l_item; size_t l_size;
    TX_ITEM_ITER_TX(l_item, l_size, a_tx) {
        switch (*l_item) {
        case TX_ITEM_TYPE_OUT:
        case TX_ITEM_TYPE_OUT_OLD:
        case TX_ITEM_TYPE_OUT_EXT:
        case TX_ITEM_TYPE_OUT_STD:
            ++l_idx;
            break;
        case TX_ITEM_TYPE_OUT_COND: {
            dap_chain_tx_out_cond_t *l_out = (dap_chain_tx_out_cond_t *)l_item;
            if (l_out->header.subtype == a_subtype)
                return l_idx;
            ++l_idx;
        } break;
        default:
            break;
        }
    }
    return -1;
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

static int s_dex_find_matches_by_order(dex_test_fixture_t *a_f, const dap_hash_fast_t *a_order_hash,
                                       const dap_chain_addr_t *a_addr, const char *a_tag)
{
    dap_ret_val_if_any(-1, !a_f, !a_f->net, !a_f->net->net, !a_order_hash, !a_addr);
    const char *l_hash_str = dap_chain_hash_fast_to_str_static(a_order_hash);
    const char *l_addr_str = dap_chain_addr_to_str_static(a_addr);
    char l_json_request[1024];
    snprintf(l_json_request, sizeof(l_json_request),
        "{\"method\":\"srv_dex\",\"params\":[\"srv_dex;find_matches;-net;%s;-order;%s;-addr;%s\"],\"id\":1,\"jsonrpc\":\"2.0\"}",
        a_f->net->net->pub.name, l_hash_str, l_addr_str);
    char *l_reply = dap_cli_cmd_exec(l_json_request);
    if (!l_reply)
        return -2;
    json_object *l_json = json_tokener_parse(l_reply);
    DAP_DELETE(l_reply);
    if (!l_json)
        return -3;
    json_object *l_error = NULL;
    if (json_object_object_get_ex(l_json, "error", &l_error)) {
        log_it(L_ERROR, "DEX find_matches error (%s): %s", a_tag ? a_tag : "?", json_object_to_json_string(l_error));
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
    if (!l_result) {
        json_object_put(l_json);
        return -6;
    }
    json_object *l_matches = NULL, *l_count = NULL;
    if (!json_object_object_get_ex(l_result, "matches", &l_matches) ||
            !json_object_is_type(l_matches, json_type_array) ||
            !json_object_object_get_ex(l_result, "matches_count", &l_count)) {
        json_object_put(l_json);
        return -7;
    }
    int l_matches_count = json_object_get_int(l_count);
    if (l_matches_count <= 0 || json_object_array_length(l_matches) == 0) {
        log_it(L_ERROR, "DEX find_matches no matches (%s)", a_tag ? a_tag : "?");
        json_object_put(l_json);
        return -8;
    }
    json_object *l_first = json_object_array_get_idx(l_matches, 0);
    json_object *l_spend = NULL, *l_receive = NULL;
    const char *l_spend_str = (l_first && json_object_object_get_ex(l_first, "spend", &l_spend))
        ? json_object_get_string(l_spend) : NULL;
    const char *l_receive_str = (l_first && json_object_object_get_ex(l_first, "receive", &l_receive))
        ? json_object_get_string(l_receive) : NULL;
    if (!l_spend_str || !*l_spend_str || !l_receive_str || !*l_receive_str) {
        json_object_put(l_json);
        return -9;
    }
    log_it(L_NOTICE, "DEX find_matches %s: count=%d, spend=%s, receive=%s",
           a_tag ? a_tag : "?", l_matches_count, l_spend_str, l_receive_str);
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
    
    dap_hash_fast_t l_xchange_hash_a = {}, l_xchange_hash_b = {}, l_xchange_hash_c = {};
    int l_xchange_out_idx_a = -1, l_xchange_out_idx_b = -1, l_xchange_out_idx_c = -1;
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
    l_ret = s_xchange_create_order(f, f->alice, l_token_sell, l_token_buy, l_value_sell, l_rate_old, f->network_fee,
                                   &l_xchange_hash_c, &l_xchange_out_idx_c);
    if (l_ret != 0) {
        log_it(L_ERROR, "Legacy XCHANGE order create C failed: %d", l_ret);
        return -5;
    }
    
    dap_hash_fast_t l_xchange_tail_a = {}, l_xchange_tail_b = {}, l_xchange_tail_c = {};
    bool l_can_migrate = false;
    l_ret = s_xchange_orders_find(f, &f->alice_addr, &l_xchange_hash_a, &l_xchange_tail_a, &l_can_migrate);
    if (l_ret != 0) {
        log_it(L_ERROR, "XCHANGE orders missing A: %d", l_ret);
        return -5;
    }
    if (!dap_hash_fast_compare(&l_xchange_tail_a, &l_xchange_hash_a)) {
        log_it(L_ERROR, "XCHANGE orders tail mismatch for A");
        return -6;
    }
    if (!l_can_migrate) {
        log_it(L_ERROR, "XCHANGE orders availability is not migrate for A");
        return -7;
    }
    l_ret = s_xchange_orders_find(f, &f->alice_addr, &l_xchange_hash_b, &l_xchange_tail_b, NULL);
    if (l_ret != 0) {
        log_it(L_ERROR, "XCHANGE orders missing B: %d", l_ret);
        return -8;
    }
    if (!dap_hash_fast_compare(&l_xchange_tail_b, &l_xchange_hash_b)) {
        log_it(L_ERROR, "XCHANGE orders tail mismatch for B");
        return -9;
    }
    l_ret = s_xchange_orders_find(f, &f->alice_addr, &l_xchange_hash_c, &l_xchange_tail_c, NULL);
    if (l_ret != 0) {
        log_it(L_ERROR, "XCHANGE orders missing C: %d", l_ret);
        return -10;
    }
    if (!dap_hash_fast_compare(&l_xchange_tail_c, &l_xchange_hash_c)) {
        log_it(L_ERROR, "XCHANGE orders tail mismatch for C");
        return -11;
    }

    dap_hash_fast_t l_dex_match_hash = {};
    l_ret = test_dex_order_create(f, f->bob, l_token_sell, l_token_buy, "100.0", "2.5", &l_dex_match_hash);
    if (l_ret != 0) {
        log_it(L_ERROR, "DEX order create (match) failed: %d", l_ret);
        return -40;
    }
    l_ret = s_dex_find_matches_by_order(f, &l_xchange_hash_a, &f->alice_addr, "legacy");
    if (l_ret != 0) {
        log_it(L_ERROR, "DEX find_matches failed (legacy): %d", l_ret);
        return -41;
    }
    
    dap_chain_datum_tx_t *l_migrate_tx_a = NULL;
    dap_chain_net_srv_dex_migrate_error_t l_err = dap_chain_net_srv_dex_migrate(
        f->net->net, &l_xchange_tail_a, l_rate_new, f->network_fee, f->alice, &l_migrate_tx_a);
    if (l_err != DEX_MIGRATE_ERROR_OK || !l_migrate_tx_a) {
        log_it(L_ERROR, "DEX migrate compose failed: %d", l_err);
        return -12;
    }
    
    dap_hash_fast_t l_migrate_hash_a = {};
    int l_migrate_out_idx_a = s_tx_out_cond_idx(l_migrate_tx_a, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
    if (l_migrate_out_idx_a < 0) {
        dap_chain_datum_tx_delete(l_migrate_tx_a);
        log_it(L_ERROR, "DEX migrate OUT_COND not found");
        return -13;
    }
    dap_hash_fast(l_migrate_tx_a, dap_chain_datum_tx_get_size(l_migrate_tx_a), &l_migrate_hash_a);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, l_migrate_tx_a, &l_migrate_hash_a, false, NULL) != 0) {
        dap_chain_datum_tx_delete(l_migrate_tx_a);
        log_it(L_ERROR, "DEX migrate tx rejected by ledger");
        return -14;
    }
    
    if (l_xchange_out_idx_a < 0 ||
        !dap_ledger_tx_hash_is_used_out_item(f->net->net->pub.ledger, &l_xchange_hash_a, l_xchange_out_idx_a, NULL)) {
        log_it(L_ERROR, "Legacy XCHANGE out was not consumed by migration");
        return -15;
    }
    
    dex_order_info_t l_info = {};
    if (test_dex_order_get_info(f->net->net->pub.ledger, &l_migrate_hash_a, &l_info) != 0) {
        log_it(L_ERROR, "DEX order not found after migration");
        return -16;
    }
    
    if (dap_strcmp(l_info.token_sell, l_token_sell) || dap_strcmp(l_info.token_buy, l_token_buy)) {
        log_it(L_ERROR, "Migrated order tokens mismatch: sell=%s buy=%s", l_info.token_sell, l_info.token_buy);
        return -17;
    }
    
    if (compare256(l_info.value, l_value_sell) != 0) {
        log_it(L_ERROR, "Migrated order value mismatch");
        return -18;
    }
    
    if (compare256(l_info.price, l_rate_new) != 0) {
        log_it(L_ERROR, "Migrated order rate mismatch");
        return -19;
    }
    
    if (!dap_chain_addr_compare(&l_info.seller_addr, &f->alice_addr)) {
        log_it(L_ERROR, "Migrated order seller mismatch");
        return -20;
    }
    
    if (l_info.min_fill != 0) {
        log_it(L_ERROR, "Migrated order min_fill mismatch: %u", l_info.min_fill);
        return -21;
    }

    l_ret = s_dex_find_matches_by_order(f, &l_migrate_hash_a, &f->alice_addr, "dex");
    if (l_ret != 0) {
        log_it(L_ERROR, "DEX find_matches failed (dex): %d", l_ret);
        return -42;
    }

    dap_chain_datum_tx_t *l_migrate_tx_b = NULL;
    l_err = dap_chain_net_srv_dex_migrate(f->net->net, &l_xchange_tail_b, l_rate_new, f->network_fee, f->alice, &l_migrate_tx_b);
    if (l_err != DEX_MIGRATE_ERROR_OK || !l_migrate_tx_b) {
        log_it(L_ERROR, "DEX migrate compose failed for B: %d", l_err);
        return -22;
    }
    dap_hash_fast_t l_migrate_hash_b = {};
    int l_migrate_out_idx_b = s_tx_out_cond_idx(l_migrate_tx_b, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
    if (l_migrate_out_idx_b < 0) {
        dap_chain_datum_tx_delete(l_migrate_tx_b);
        log_it(L_ERROR, "DEX migrate OUT_COND not found for B");
        return -23;
    }
    dap_hash_fast(l_migrate_tx_b, dap_chain_datum_tx_get_size(l_migrate_tx_b), &l_migrate_hash_b);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, l_migrate_tx_b, &l_migrate_hash_b, false, NULL) != 0) {
        dap_chain_datum_tx_delete(l_migrate_tx_b);
        log_it(L_ERROR, "DEX migrate tx rejected by ledger for B");
        return -24;
    }
    if (l_xchange_out_idx_b < 0 ||
        !dap_ledger_tx_hash_is_used_out_item(f->net->net->pub.ledger, &l_xchange_hash_b, l_xchange_out_idx_b, NULL)) {
        log_it(L_ERROR, "Legacy XCHANGE out was not consumed by migration for B");
        return -25;
    }
    
    dap_hash_fast_t l_purchase_hash = {};
    l_ret = test_dex_order_purchase(f, f->bob, &l_migrate_hash_a, "100.0", &l_purchase_hash);
    if (l_ret != 0) {
        log_it(L_ERROR, "DEX purchase failed after migration: %d", l_ret);
        return -26;
    }
    dap_chain_datum_tx_t *l_purchase_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &l_purchase_hash);
    if (!l_purchase_tx) {
        log_it(L_ERROR, "Purchase tx not found in ledger");
        return -27;
    }
    int l_purchase_prev_idx = -1;
    byte_t *l_item; size_t l_size;
    TX_ITEM_ITER_TX(l_item, l_size, l_purchase_tx) {
        if (*l_item == TX_ITEM_TYPE_IN_COND) {
            l_purchase_prev_idx = (int)((dap_chain_tx_in_cond_t *)l_item)->header.tx_out_prev_idx;
            break;
        }
    }
    if (l_purchase_prev_idx < 0) {
        log_it(L_ERROR, "Purchase tx has no IN_COND");
        return -28;
    }
    if (l_purchase_prev_idx != l_migrate_out_idx_a) {
        log_it(L_ERROR, "Purchase prev_idx mismatch: %d != %d", l_purchase_prev_idx, l_migrate_out_idx_a);
        return -29;
    }
    if (!dap_ledger_tx_hash_is_used_out_item(f->net->net->pub.ledger, &l_migrate_hash_a, l_migrate_out_idx_a, NULL)) {
        log_it(L_ERROR, "Migrated DEX out was not consumed by purchase");
        return -30;
    }

    l_ret = s_dex_history_summary_by_order(f, &l_migrate_hash_a);
    if (l_ret != 0) {
        log_it(L_ERROR, "DEX history summary failed: %d", l_ret);
        return -36;
    }

    dap_time_t l_bc_time = dap_ledger_get_blockchain_time(f->net->net->pub.ledger);
    if (l_bc_time < 2) {
        log_it(L_ERROR, "Blockchain time too small for cutoff test");
        return -31;
    }
    dap_time_t l_cutoff_ts = l_bc_time - 1;
    l_ret = s_apply_xchange_cutoffs(f, l_cutoff_ts, l_cutoff_ts);
    if (l_ret != 0) {
        log_it(L_ERROR, "Policy cutoff apply failed: %d", l_ret);
        return -32;
    }

    dap_hash_fast_t l_xchange_hash_d = {};
    int l_xchange_out_idx_d = -1;
    l_ret = s_xchange_create_order(f, f->alice, l_token_sell, l_token_buy, l_value_sell, l_rate_old, f->network_fee,
                                   &l_xchange_hash_d, &l_xchange_out_idx_d);
    if (l_ret == 0) {
        log_it(L_ERROR, "Legacy XCHANGE order create accepted after cutoff");
        return -33;
    }

    dap_chain_datum_tx_t *l_migrate_tx_fail = NULL;
    l_err = dap_chain_net_srv_dex_migrate(f->net->net, &l_xchange_tail_c, l_rate_new, f->network_fee, f->alice,
                                          &l_migrate_tx_fail);
    if (l_err != DEX_MIGRATE_ERROR_OK || !l_migrate_tx_fail) {
        log_it(L_ERROR, "DEX migrate compose failed after cutoff: %d", l_err);
        return -34;
    }
    dap_hash_fast_t l_migrate_hash_fail = {};
    dap_hash_fast(l_migrate_tx_fail, dap_chain_datum_tx_get_size(l_migrate_tx_fail), &l_migrate_hash_fail);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, l_migrate_tx_fail, &l_migrate_hash_fail, false, NULL) == 0) {
        dap_chain_datum_tx_delete(l_migrate_tx_fail);
        log_it(L_ERROR, "DEX migrate tx accepted after cutoff");
        return -35;
    }
    dap_chain_datum_tx_delete(l_migrate_tx_fail);
    
    l_ret = s_dex_cancel_order(f, &l_migrate_hash_b);
    if (l_ret != 0) {
        log_it(L_ERROR, "DEX cancel failed: %d", l_ret);
        return -37;
    }

    log_it(L_NOTICE, "✓ Migration test passed: %s -> %s", dap_chain_hash_fast_to_str_static(&l_xchange_hash_a),
           dap_chain_hash_fast_to_str_static(&l_migrate_hash_a));
    return 0;
}
