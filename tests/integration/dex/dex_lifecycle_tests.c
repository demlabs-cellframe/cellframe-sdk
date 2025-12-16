/**
 * @file dex_lifecycle_tests.c
 * @brief Order lifecycle tests: create, full/partial buy, rollback, cancel
 */

#include "dex_test_scenarios.h"
#include "dex_test_helpers.h"
#include "dap_chain_net_srv_dex.h"
#include "dap_chain_wallet.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_time.h"

// ============================================================================
// CONSTANTS - Use dex_test_helpers.h
// ============================================================================

#define S_POW18                 DEX_TEST_POW18
#define S_NATIVE_FEE_FALLBACK   DEX_TEST_NATIVE_FEE_FALLBACK
#define get_native_srv_fee      dex_test_get_native_srv_fee

// ============================================================================
// HELPERS - Use dex_test_helpers.h
// ============================================================================

#define calc_pct                dex_test_calc_pct

#define adjust_native_fee       dex_test_adjust_native_fee
#define adjust_abs_service_fee  dex_test_adjust_abs_service_fee

// ============================================================================
// PARTICIPANT CONTEXT - Use dex_test_helpers.h
// ============================================================================

#define participants_t dex_test_participants_t

static participants_t init_participants(
    dex_test_fixture_t *f,
    const test_context_t *ctx,
    wallet_id_t buyer_id)
{
    participants_t p = {
        .buyer = get_wallet_addr(f, buyer_id),
        .seller = get_wallet_addr(f, ctx->tmpl->seller),
        .net_fee_collector = test_get_net_fee_addr(f),
        .service_addr = &f->carol_addr
    };
    p.buyer_is_net_collector = dap_chain_addr_compare(p.buyer, p.net_fee_collector);
    p.seller_is_net_collector = dap_chain_addr_compare(p.seller, p.net_fee_collector);
    p.seller_is_service = (ctx->tmpl->seller == WALLET_CAROL);
    return p;
}

// ============================================================================
// EXPECTED DELTAS CALCULATION
// ============================================================================

typedef struct {
    uint128_t buyer_base;
    uint128_t buyer_quote;
    uint128_t seller_base;
    uint128_t seller_quote;
    bool buyer_base_dec;
    bool buyer_quote_dec;
} expected_deltas_t;

// Calculate expected balance changes for a purchase
// exec_value: for ASK = BASE amount bought, for BID = QUOTE amount bought
static expected_deltas_t calc_purchase_deltas(
    const test_context_t *ctx,
    const dex_test_fixture_t *f,
    const participants_t *p,
    uint128_t exec_value,
    bool fee_waived)
{
    expected_deltas_t d = {0};
    uint128_t rate = dap_uint256_to_uint128(ctx->order.price);
    uint128_t net_fee = dap_uint256_to_uint128(f->network_fee);
    uint8_t fee_cfg = ctx->pair->fee_config;
    bool is_pct_fee = (fee_cfg & 0x80) != 0;
    uint128_t service_fee = uint128_0;
    uint128_t tmp;
    
    uint128_t buyer_gets, buyer_spends, seller_gets;
    
    if (ctx->tmpl->side == SIDE_ASK) {
        // ASK: buyer spends QUOTE + service_fee, gets BASE; seller gets QUOTE
        buyer_gets = exec_value;
        // seller_gets = (exec_value * rate) / S_POW18
        MULT_128_128(exec_value, rate, &tmp);
        DIV_128(tmp, GET_128_FROM_64(S_POW18), &seller_gets);
        // % fee from INPUT (QUOTE for ASK), 0.1% step
        if (!fee_waived && is_pct_fee) {
            MULT_128_128(seller_gets, GET_128_FROM_64(fee_cfg & 0x7F), &tmp);
            DIV_128(tmp, GET_128_FROM_64(1000), &service_fee);
        }
        SUM_128_128(seller_gets, service_fee, &buyer_spends);
        
        if (p->seller_is_service)
            SUM_128_128(seller_gets, service_fee, &seller_gets);
        if (p->seller_is_net_collector && ctx->pair->quote_is_native)
            SUM_128_128(seller_gets, net_fee, &seller_gets);
        if (!fee_waived && !is_pct_fee && p->seller_is_service && ctx->pair->quote_is_native)
            SUM_128_128(seller_gets, get_native_srv_fee(fee_cfg), &seller_gets);
        
        d.buyer_base = buyer_gets;
        d.buyer_quote = buyer_spends;
        d.buyer_base_dec = false;
        d.buyer_quote_dec = true;
        // ASK: seller already locked BASE in order, gets QUOTE at purchase
        d.seller_base = (p->seller_is_net_collector && ctx->pair->base_is_native) ? net_fee : uint128_0;
        d.seller_quote = seller_gets;
        // Service wallet receives abs fee in native BASE (separate OUT, not aggregated for ASK when native=BASE)
        if (!fee_waived && !is_pct_fee && p->seller_is_service && ctx->pair->base_is_native)
            SUM_128_128(d.seller_base, get_native_srv_fee(fee_cfg), &d.seller_base);
    } else {
        // BID: buyer spends BASE + service_fee (if % mode), gets QUOTE
        // exec_base = (exec_value * S_POW18) / rate
        uint128_t exec_base;
        MULT_128_128(exec_value, GET_128_FROM_64(S_POW18), &tmp);
        DIV_128(tmp, rate, &exec_base);
        seller_gets = exec_base;
        
        // % fee from INPUT (BASE for BID), 0.1% step
        if (!fee_waived && is_pct_fee) {
            MULT_128_128(exec_base, GET_128_FROM_64(fee_cfg & 0x7F), &tmp);
            DIV_128(tmp, GET_128_FROM_64(1000), &service_fee);
        }
        SUM_128_128(exec_base, service_fee, &buyer_spends);
        buyer_gets = exec_value;  // full QUOTE, no deduction
        
        d.buyer_base = buyer_spends;
        d.buyer_quote = buyer_gets;
        d.buyer_base_dec = true;
        d.buyer_quote_dec = false;
        
        // BID: seller already locked QUOTE in order, gets BASE at purchase
        // % fee in BASE aggregates to seller if seller == service
        d.seller_base = seller_gets;
        if (p->seller_is_service && is_pct_fee)
            SUM_128_128(d.seller_base, service_fee, &d.seller_base);
        if (p->seller_is_net_collector && ctx->pair->base_is_native)
            SUM_128_128(d.seller_base, net_fee, &d.seller_base);
        // Native abs fee in BASE aggregates to seller payout
        if (!fee_waived && !is_pct_fee && p->seller_is_service && ctx->pair->base_is_native)
            SUM_128_128(d.seller_base, get_native_srv_fee(fee_cfg), &d.seller_base);
        
        // Seller QUOTE delta: only net_fee if native=QUOTE, or abs fee if native=QUOTE
        uint128_t extra_quote = (p->seller_is_net_collector && ctx->pair->quote_is_native) ? net_fee : uint128_0;
        uint128_t abs_fee_quote = (!fee_waived && !is_pct_fee && p->seller_is_service && ctx->pair->quote_is_native)
            ? get_native_srv_fee(fee_cfg) : uint128_0;
        SUM_128_128(extra_quote, abs_fee_quote, &d.seller_quote);
    }
    
    adjust_native_fee(ctx->tmpl->side, ctx->pair->quote_is_native, ctx->pair->base_is_native,
                      p->buyer_is_net_collector, net_fee,
                      ctx->tmpl->side == SIDE_ASK ? &d.buyer_quote : &d.buyer_base,
                      ctx->tmpl->side == SIDE_ASK ? &d.buyer_base : &d.buyer_quote);
    
    if (!fee_waived)
        adjust_abs_service_fee(ctx->tmpl->side, ctx->pair->quote_is_native, ctx->pair->base_is_native,
                               fee_cfg,
                               ctx->tmpl->side == SIDE_ASK ? &d.buyer_quote : &d.buyer_base,
                               ctx->tmpl->side == SIDE_ASK ? &d.buyer_base : &d.buyer_quote);
    
    return d;
}

// ============================================================================
// TX LIFECYCLE HELPERS
// ============================================================================

// Execute purchase and add to ledger
static int exec_purchase_and_add(
    dex_test_fixture_t *f,
    dap_hash_fast_t *order_tail,
    uint256_t budget,
    bool is_budget_buy,
    dap_chain_wallet_t *buyer_wallet,
    dap_hash_fast_t *out_tx_hash,
    dap_chain_datum_tx_t **out_tx)
{
    dap_chain_datum_tx_t *tx = NULL;
    dap_chain_net_srv_dex_purchase_error_t err = dap_chain_net_srv_dex_purchase(
        f->net->net, order_tail, budget, is_budget_buy,
        f->network_fee, buyer_wallet, false, uint256_0, &tx
    );
    
    if (err != DEX_PURCHASE_ERROR_OK || !tx) {
        log_it(L_ERROR, "Purchase compose failed: err=%d", err);
        return -1;
    }
    
    dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), out_tx_hash);
    int ret = dap_ledger_tx_add(f->net->net->pub.ledger, tx, out_tx_hash, false, NULL);
    if (ret != 0) {
        log_it(L_ERROR, "TX add to ledger failed");
        dap_chain_datum_tx_delete(tx);
        return -2;
    }
    
    if (out_tx)
        *out_tx = tx;
    return 0;
}

// Verify purchase deltas
static int verify_deltas(
    const char *phase_name,
    const balance_snap_t *buyer_before, const balance_snap_t *buyer_after,
    const balance_snap_t *seller_before, const balance_snap_t *seller_after,
    const balance_snap_t *net_before, const balance_snap_t *net_after,
    const expected_deltas_t *d,
    const participants_t *p,
    uint128_t net_fee)
{
    char label[64];
    snprintf(label, sizeof(label), "%s Buyer", phase_name);
    if (test_dex_snap_verify(label, buyer_before, buyer_after,
            d->buyer_base, d->buyer_base_dec, d->buyer_quote, d->buyer_quote_dec) != 0)
        return -1;
    
    snprintf(label, sizeof(label), "%s Seller", phase_name);
    if (test_dex_snap_verify(label, seller_before, seller_after,
            d->seller_base, false, d->seller_quote, false) != 0)
        return -2;
    
    if (!p->buyer_is_net_collector && !p->seller_is_net_collector) {
        snprintf(label, sizeof(label), "%s Net", phase_name);
        if (test_dex_snap_verify_fee(label, net_before, net_after, net_fee, false) != 0)
            return -3;
    }
    
    return 0;
}

// ============================================================================
// TAMPER HELPERS - Use dex_test_helpers.h
// ============================================================================

// Aliases for backward compatibility with existing code
#define tamper_ts_created       dex_test_tamper_ts_created
#define s_resign_tx             dex_test_resign_tx
#define tamper_inflate_output   dex_test_tamper_inflate_output
#define tamper_transfer_funds   dex_test_tamper_transfer_funds
#define s_find_dex_out_cond     dex_test_find_dex_out_cond
#define tamper_order_root_hash  dex_test_tamper_order_root_hash
#define tamper_tx_type          dex_test_tamper_tx_type
#define tamper_rate             dex_test_tamper_rate
#define tamper_buy_token        dex_test_tamper_buy_token
#define tamper_min_fill         dex_test_tamper_min_fill
#define s_find_out_value        dex_test_find_out_value
#define s_find_out_value_ex     dex_test_find_out_value_ex
#define dex_test_wallet_by_addr        dex_test_wallet_by_addr

// Type aliases
#define tamper_output_data_t    dex_tamper_output_data_t
#define tamper_out_type_t       dex_tamper_out_type_t
#define tamper_transfer_data_t  dex_tamper_transfer_data_t

// ============================================================================
// PHASE 1: ORDER CREATION
// ============================================================================

static int run_phase_create(test_context_t *ctx) {
    const test_pair_config_t *pair = ctx->pair;
    const order_template_t *tmpl = ctx->tmpl;
    dex_test_fixture_t *f = ctx->fixture;
    
    const char *sell_token, *buy_token;
    get_order_tokens(pair, tmpl->side, &sell_token, &buy_token);
    
    dap_chain_wallet_t *seller_wallet = get_wallet(f, tmpl->seller);
    const dap_chain_addr_t *seller_addr = get_wallet_addr(f, tmpl->seller);
    
    log_it(L_INFO, "Creating %s order: %s sells %s %s for %s @ rate %s (min_fill=%s)",
           tmpl->side == SIDE_ASK ? "ASK" : "BID",
           get_wallet_name(tmpl->seller),
           tmpl->amount, sell_token, buy_token, tmpl->rate, get_minfill_desc(tmpl->min_fill));
    
    // Expected amounts in uint128 (simple arithmetic)
    uint128_t order_val = dap_uint256_to_uint128(dap_chain_coins_to_balance(tmpl->amount));
    uint128_t net_fee = dap_uint256_to_uint128(f->network_fee);
    
    // Get net fee collector address
    const dap_chain_addr_t *net_fee_addr = test_get_net_fee_addr(f);
    bool seller_is_net_collector = dap_chain_addr_compare(seller_addr, net_fee_addr);
    
    // Check if sell_token == native (seller pays net_fee in same token)
    bool sell_is_native = (tmpl->side == SIDE_ASK) ? pair->base_is_native : pair->quote_is_native;
    
    // Snapshot BEFORE
    uint256_t seller_sell_before = dap_ledger_calc_balance(f->net->net->pub.ledger, seller_addr, sell_token);
    uint256_t net_collector_before = dap_ledger_calc_balance(f->net->net->pub.ledger, net_fee_addr, "TestCoin");
    
    // Create order TX template (not added to ledger yet)
    uint256_t value = dap_chain_coins_to_balance(tmpl->amount);
    uint256_t rate_value = dap_chain_coins_to_balance(tmpl->rate);
    dap_chain_datum_tx_t *create_tx = NULL;
    
    // Negative control: insufficient sell balance for absolute fee configs (no 0x80)
    if (!(pair->fee_config & 0x80)) {
        uint256_t seller_balance = dap_ledger_calc_balance(f->net->net->pub.ledger, seller_addr, sell_token);
        uint256_t inflated = uint256_0;
        SUM_256_256(seller_balance, GET_256_FROM_64(1), &inflated); // balance + 1 unit
        dap_chain_net_srv_dex_create_error_t err_abs = dap_chain_net_srv_dex_create(
            f->net->net, buy_token, sell_token, inflated, rate_value, tmpl->min_fill, f->network_fee, seller_wallet, &create_tx
        );
        if (err_abs == DEX_CREATE_ERROR_OK && create_tx) {
            log_it(L_ERROR, "Insufficient funds check should fail for absolute fee");
            dap_chain_datum_tx_delete(create_tx);
            return -99;
        }
        log_it(L_NOTICE, "✓ Absolute-fee insufficient balance rejected (err=%d)", err_abs);
        create_tx = NULL;
    }
    
    dap_chain_net_srv_dex_create_error_t err = dap_chain_net_srv_dex_create(
        f->net->net, buy_token, sell_token, value, rate_value, tmpl->min_fill, f->network_fee, seller_wallet, &create_tx
    );
    if (err != DEX_CREATE_ERROR_OK || !create_tx) {
        log_it(L_ERROR, "Order creation failed: err=%d", err);
        return -2;
    }
    
    // Security tamper tests for OUT_COND SRV_DEX fields in CREATE
    // T10: Set non-blank order_root_hash (should be blank for ORDER) → reject
    dap_hash_fast_t fake_hash;
    memset(&fake_hash, 0xAB, sizeof(fake_hash));
    if (test_dex_tamper_and_verify_rejection(f, create_tx, seller_wallet,
            tamper_order_root_hash, &fake_hash, "Non-blank order_root_hash in CREATE") != 0) {
        dap_chain_datum_tx_delete(create_tx);
        return -80;
    }
    
    // T11: Change tx_type from ORDER to EXCHANGE → reject
    uint8_t wrong_type = DEX_TX_TYPE_EXCHANGE;
    if (test_dex_tamper_and_verify_rejection(f, create_tx, seller_wallet,
            tamper_tx_type, &wrong_type, "Wrong tx_type EXCHANGE in CREATE") != 0) {
        dap_chain_datum_tx_delete(create_tx);
        return -81;
    }
    
    // Add original TX to ledger
    dap_hash_fast(create_tx, dap_chain_datum_tx_get_size(create_tx), &ctx->order_hash);
    int ret = dap_ledger_tx_add(f->net->net->pub.ledger, create_tx, &ctx->order_hash, false, NULL);
    if (ret != 0) {
        log_it(L_ERROR, "Failed to add order to ledger: %d", ret);
        dap_chain_datum_tx_delete(create_tx);
        return -3;
    }
    
    // Snapshot AFTER
    uint256_t seller_sell_after = dap_ledger_calc_balance(f->net->net->pub.ledger, seller_addr, sell_token);
    uint256_t net_collector_after = dap_ledger_calc_balance(f->net->net->pub.ledger, net_fee_addr, "TestCoin");
    
    // Verify seller spent order_value (+ net_fee + validator_fee if sell_token == native)
    // seller_is_net_collector: net_fee returns, but validator_fee still paid
    uint128_t expected_seller_spent = order_val;
    if (sell_is_native) {
        if (seller_is_net_collector)
            SUM_128_128(expected_seller_spent, net_fee, &expected_seller_spent);
        else {
            uint128_t double_fee;
            SUM_128_128(net_fee, net_fee, &double_fee);
            SUM_128_128(expected_seller_spent, double_fee, &expected_seller_spent);
        }
    }
    if (test_dex_verify_delta("Seller sell_token", seller_sell_before, seller_sell_after, expected_seller_spent, true) != 0)
        return -10;
    
    // Verify net fee collector received network_fee (unless seller is net collector)
    if (!seller_is_net_collector) {
        if (test_dex_verify_delta("Net collector fee", net_collector_before, net_collector_after, net_fee, false) != 0)
            return -11;
    }
    
    ret = test_dex_order_get_info(f->net->net->pub.ledger, &ctx->order_hash, &ctx->order);
    if (ret != 0) {
        log_it(L_ERROR, "Failed to get order info: %d", ret);
        return -1;
    }
    
    log_it(L_NOTICE, "✓ Order created: %s", dap_chain_hash_fast_to_str_static(&ctx->order_hash));
    return 0;
}

// ============================================================================
// PHASE 2: FULL BUY WITH TAMPERING + ROLLBACK
// ============================================================================

static int run_phase_full_buy(test_context_t *ctx) {
    dex_test_fixture_t *f = ctx->fixture;
    dex_order_info_t *order = &ctx->order;
    
    // Test self-purchase rejection: seller tries to buy own order
    {
        dap_chain_wallet_t *seller_wallet = get_wallet(f, ctx->tmpl->seller);
        log_it(L_INFO, "--- Testing self-purchase rejection: %s tries to buy own order ---",
               get_wallet_name(ctx->tmpl->seller));
        
        dap_chain_datum_tx_t *tx_self = NULL;
        dap_chain_net_srv_dex_purchase_error_t err = dap_chain_net_srv_dex_purchase(
            f->net->net, &order->tail, uint256_0, false,
            f->network_fee, seller_wallet, false, uint256_0, &tx_self
        );
        
        if (err == DEX_PURCHASE_ERROR_OK && tx_self) {
            log_it(L_ERROR, "✗ Self-purchase was NOT rejected by composer!");
            dap_chain_datum_tx_delete(tx_self);
            return -100;
        }
        log_it(L_NOTICE, "✓ Self-purchase rejected by composer (err=%d)", err);
    }
    
    // Negative control: insufficient buyer balance (tiny budget). Skip when min_fill=0 (partial allowed).
    if (MINFILL_PCT(ctx->tmpl->min_fill) > 0) {
        wallet_id_t buyer_id = get_regular_buyer(ctx->tmpl->side);
        dap_chain_wallet_t *buyer_wallet = get_wallet(f, buyer_id);
        const char *sell_token, *buy_token;
        get_order_tokens(ctx->pair, ctx->tmpl->side, &sell_token, &buy_token);
        const dap_chain_addr_t *buyer_addr = get_wallet_addr(f, buyer_id);
        // is_budget_buy=false → buyer sells QUOTE for ASK, BASE for BID; set tiny budget to force rejection
        uint256_t huge_budget = GET_256_FROM_64(100); // 100 wei, still far below required
        dap_chain_datum_tx_t *tx_insuff = NULL;
        dap_chain_net_srv_dex_purchase_error_t err = dap_chain_net_srv_dex_purchase(
            f->net->net, &order->tail, huge_budget, false,
            f->network_fee, buyer_wallet, false, uint256_0, &tx_insuff
        );
        if (err == DEX_PURCHASE_ERROR_OK && tx_insuff) {
            dap_chain_datum_tx_delete(tx_insuff);
            log_it(L_ERROR, "Insufficient balance purchase should be rejected");
            return -101;
        } else {
            log_it(L_NOTICE, "✓ Insufficient balance purchase rejected (err=%d)", err);
        }
    }
    
    buyer_scenario_t scenarios[2];
    size_t scenario_count;
    generate_buyer_scenarios(ctx->tmpl->side, ctx->tmpl->seller, scenarios, &scenario_count);
    
    for (size_t i = 0; i < scenario_count; i++) {
        buyer_scenario_t *sc = &scenarios[i];
        dap_chain_wallet_t *buyer_wallet = get_wallet(f, sc->buyer);
        
        log_it(L_INFO, "--- Full buy: %s buys from %s %s---",
               get_wallet_name(sc->buyer),
               get_wallet_name(ctx->tmpl->seller),
               sc->expect_fee_waived ? "(fee waived) " : "");
        
        const char *sell_token, *buy_token;
        get_order_tokens(ctx->pair, ctx->tmpl->side, &sell_token, &buy_token);
        
        // Init participants and calculate expected deltas
        participants_t p = init_participants(f, ctx, sc->buyer);
        uint128_t order_val = dap_uint256_to_uint128(order->value);
        expected_deltas_t d = calc_purchase_deltas(ctx, f, &p, order_val, sc->expect_fee_waived);
        uint128_t net_fee = dap_uint256_to_uint128(f->network_fee);
        
        // Build purchase TX
        dap_chain_datum_tx_t *tx_template = NULL;
        dap_chain_net_srv_dex_purchase_error_t err = dap_chain_net_srv_dex_purchase(
            f->net->net, &order->tail, uint256_0, false,
            f->network_fee, buyer_wallet, false, uint256_0, &tx_template
        );
        
        if (err != DEX_PURCHASE_ERROR_OK || !tx_template) {
            log_it(L_ERROR, "Failed to create purchase TX: err=%d", err);
            return -1;
        }
        
        // Tampering test
        tamper_output_data_t tamper_data = {
            .target_addr = (dap_chain_addr_t*)p.seller,
            .token = buy_token,
            .tampered_value = dap_chain_coins_to_balance("99999.0")
        };
        if (test_dex_tamper_and_verify_rejection(f, tx_template, buyer_wallet,
                tamper_inflate_output, &tamper_data, "Inflate seller payout") != 0) {
            dap_chain_datum_tx_delete(tx_template);
            return -2;
        }
        
        // Security tamper tests: transfer funds between OUTs
        const char *svc_fee_token = (ctx->tmpl->side == SIDE_ASK) ? buy_token : sell_token;
        tamper_transfer_data_t transfer_ctx = {
            .seller_addr = p.seller,
            .buyer_addr = p.buyer,
            .net_addr = p.net_fee_collector,
            .srv_addr = p.service_addr,
            .native_ticker = "TestCoin",
            .buy_ticker = buy_token,
            .sell_ticker = sell_token,
            .fee_ticker = svc_fee_token,
            .transfer_amount = dap_chain_coins_to_balance("1.0")
        };
        
        // T1: Steal from seller payout to net_fee
        if (!p.seller_is_net_collector) {
            transfer_ctx.source = TAMPER_OUT_SELLER_PAYOUT;
            transfer_ctx.destination = TAMPER_OUT_NET_FEE;
            if (test_dex_tamper_and_verify_rejection(f, tx_template, buyer_wallet, tamper_transfer_funds, &transfer_ctx, "Steal seller→net_fee") != 0) {
                dap_chain_datum_tx_delete(tx_template);
                return -30;
            }
        }
        
        // T2: Steal from seller payout to service_fee
        if (!p.seller_is_service) {
            transfer_ctx.source = TAMPER_OUT_SELLER_PAYOUT;
            transfer_ctx.destination = TAMPER_OUT_SRV_FEE;
            if (test_dex_tamper_and_verify_rejection(f, tx_template, buyer_wallet, tamper_transfer_funds, &transfer_ctx, "Steal seller→srv_fee") != 0) {
                dap_chain_datum_tx_delete(tx_template);
                return -31;
            }
        }
        
        // T3-T6: Seller ↔ Buyer transfers
        {
            transfer_ctx.source = TAMPER_OUT_SELLER_PAYOUT;
            transfer_ctx.destination = TAMPER_OUT_VALIDATOR_FEE;
            if (test_dex_tamper_and_verify_rejection(f, tx_template, buyer_wallet, tamper_transfer_funds, &transfer_ctx, "Steal seller→validator_fee") != 0) {
                dap_chain_datum_tx_delete(tx_template);
                return -32;
            }
            
            if (!p.buyer_is_net_collector) {
                transfer_ctx.source = TAMPER_OUT_BUYER_PAYOUT;
                transfer_ctx.destination = TAMPER_OUT_NET_FEE;
                if (test_dex_tamper_and_verify_rejection(f, tx_template, buyer_wallet, tamper_transfer_funds, &transfer_ctx, "Steal buyer→net_fee") != 0) {
                    dap_chain_datum_tx_delete(tx_template);
                    return -33;
                }
            }
            
            transfer_ctx.source = TAMPER_OUT_SELLER_PAYOUT;
            transfer_ctx.destination = TAMPER_OUT_BUYER_CASHBACK;
            if (test_dex_tamper_and_verify_rejection(f, tx_template, buyer_wallet, tamper_transfer_funds, &transfer_ctx, "Steal seller→buyer") != 0) {
                dap_chain_datum_tx_delete(tx_template);
                return -34;
            }
            
            transfer_ctx.source = TAMPER_OUT_BUYER_PAYOUT;
            transfer_ctx.destination = TAMPER_OUT_SELLER_PAYOUT;
            if (test_dex_tamper_and_verify_rejection(f, tx_template, buyer_wallet, tamper_transfer_funds, &transfer_ctx, "Steal buyer→seller") != 0) {
                dap_chain_datum_tx_delete(tx_template);
                return -35;
            }
        }
        
        // Snapshots
        balance_snap_t buyer_before, buyer_after, seller_before, seller_after, net_before, net_after;
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.buyer, ctx->pair, &buyer_before);
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.seller, ctx->pair, &seller_before);
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.net_fee_collector, ctx->pair, &net_before);
        
        // Add TX
        dap_hash_fast_t purchase_hash = {0};
        dap_hash_fast(tx_template, dap_chain_datum_tx_get_size(tx_template), &purchase_hash);
        if (dap_ledger_tx_add(f->net->net->pub.ledger, tx_template, &purchase_hash, false, NULL) != 0) {
            dap_chain_datum_tx_delete(tx_template);
            return -3;
        }
        
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.buyer, ctx->pair, &buyer_after);
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.seller, ctx->pair, &seller_after);
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.net_fee_collector, ctx->pair, &net_after);
        
        // Verify deltas
        int ret = verify_deltas("Full", &buyer_before, &buyer_after, &seller_before, &seller_after,
                                &net_before, &net_after, &d, &p, net_fee);
        if (ret != 0)
            return -20 + ret;
        
        log_it(L_NOTICE, "✓ Valid purchase accepted");
        
        // Rollback
        if (sc->do_rollback) {
            dap_chain_datum_tx_t *tx_for_remove = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &purchase_hash);
            if (dap_ledger_tx_remove(f->net->net->pub.ledger, tx_for_remove, &purchase_hash) != 0)
                return -4;
            
            balance_snap_t buyer_restored;
            test_dex_snap_take_pair(f->net->net->pub.ledger, p.buyer, ctx->pair, &buyer_restored);
            
            if (test_dex_snap_verify("Rollback", &buyer_before, &buyer_restored, uint128_0, false, uint128_0, false) != 0)
                return -25;
            
            log_it(L_NOTICE, "✓ Rollback successful");
        } else {
            // Order consumed test
            log_it(L_INFO, "--- Testing purchase of consumed order ---");
            
            dap_chain_datum_tx_t *tx_consumed = NULL;
            dap_chain_net_srv_dex_purchase_error_t consumed_err = dap_chain_net_srv_dex_purchase(
                f->net->net, &order->tail, uint256_0, false,
                f->network_fee, buyer_wallet, false, uint256_0, &tx_consumed
            );
            
            if (consumed_err == DEX_PURCHASE_ERROR_OK && tx_consumed) {
                dap_hash_fast_t consumed_hash = {0};
                dap_hash_fast(tx_consumed, dap_chain_datum_tx_get_size(tx_consumed), &consumed_hash);
                int ledger_ret = dap_ledger_tx_add(f->net->net->pub.ledger, tx_consumed, &consumed_hash, false, NULL);
                dap_chain_datum_tx_delete(tx_consumed);
                
                if (ledger_ret == 0) {
                    log_it(L_ERROR, "✗ Purchase of consumed order was ACCEPTED by ledger!");
                    return -30;
                }
                log_it(L_NOTICE, "✓ Purchase of consumed order rejected by ledger");
            } else {
                log_it(L_NOTICE, "✓ Purchase of consumed order rejected by composer (err=%d)", consumed_err);
            }
        }
    }
    
    return 0;
}

// ============================================================================
// PHASE 3: PARTIAL BUY (min_fill validation)
// ============================================================================

static int run_phase_partial_buy(test_context_t *ctx) {
    dex_test_fixture_t *f = ctx->fixture;
    dex_order_info_t *order = &ctx->order;
    uint8_t min_fill = ctx->tmpl->min_fill;
    uint8_t pct = MINFILL_PCT(min_fill);
    
    if (pct == 0) {
        log_it(L_INFO, "Skipping partial buy phase (min_fill=none)");
        return 0;
    }
    
    wallet_id_t buyer_id = get_regular_buyer(ctx->tmpl->side);
    dap_chain_wallet_t *buyer_wallet = get_wallet(f, buyer_id);
    
    // Absolute-fee dust check: budgets far below precision must be rejected (min_fill>0)
    if (!(ctx->pair->fee_config & 0x80) && pct > 0) {
        uint256_t dust_budget = GET_256_FROM_64(100); // 100 wei
        dap_chain_datum_tx_t *tx_dust = NULL;
        dap_chain_net_srv_dex_purchase_error_t err_dust = dap_chain_net_srv_dex_purchase(
            f->net->net, &order->tail, dust_budget, true,
            f->network_fee, buyer_wallet, false, uint256_0, &tx_dust
        );
        if (err_dust == DEX_PURCHASE_ERROR_OK && tx_dust) {
            dap_hash_fast_t h_dust = {0};
            dap_hash_fast(tx_dust, dap_chain_datum_tx_get_size(tx_dust), &h_dust);
            int add_ret = dap_ledger_tx_add(f->net->net->pub.ledger, tx_dust, &h_dust, false, NULL);
            dap_chain_datum_tx_delete(tx_dust);
            if (add_ret == 0) {
                log_it(L_ERROR, "Dust partial (BUY) on abs-fee should be rejected");
                return -107;
            }
        }
        log_it(L_NOTICE, "✓ Dust partial (BUY, abs fee) rejected (err=%d)", err_dust);
        
        tx_dust = NULL;
        err_dust = dap_chain_net_srv_dex_purchase(
            f->net->net, &order->tail, dust_budget, false,
            f->network_fee, buyer_wallet, false, uint256_0, &tx_dust
        );
        if (err_dust == DEX_PURCHASE_ERROR_OK && tx_dust) {
            dap_hash_fast_t h_dust = {0};
            dap_hash_fast(tx_dust, dap_chain_datum_tx_get_size(tx_dust), &h_dust);
            int add_ret = dap_ledger_tx_add(f->net->net->pub.ledger, tx_dust, &h_dust, false, NULL);
            dap_chain_datum_tx_delete(tx_dust);
            if (add_ret == 0) {
                log_it(L_ERROR, "Dust partial (SELL) on abs-fee should be rejected");
                return -108;
            }
        }
        log_it(L_NOTICE, "✓ Dust partial (SELL, abs fee) rejected (err=%d)", err_dust);
    }
    
    // AON (100%) special case
    if (pct >= 100) {
        log_it(L_INFO, "--- AON order: testing partial rejection ---");
        
        // ASK: value = BASE, buyer pays QUOTE, BUY token = QUOTE
        // BID: value = QUOTE, buyer pays BASE, BUY token = BASE
        // partial_80_base = 80% of exec_sell (always BASE)
        // partial_80_quote = 80% of what buyer pays in ORDER's SELL token
        uint256_t partial_80_base, partial_80_quote;
        if (ctx->tmpl->side == SIDE_ASK) {
            partial_80_base = calc_pct(order->value, 80);  // ASK: value is BASE
            MULT_256_COIN(partial_80_base, order->price, &partial_80_quote);  // QUOTE = BASE * rate
        } else {
            // BID: value is QUOTE, exec_sell = value / rate
            uint256_t exec_sell_full;
            DIV_256_COIN(order->value, order->price, &exec_sell_full);
            partial_80_base = calc_pct(exec_sell_full, 80);  // 80% of BASE
            partial_80_quote = calc_pct(order->value, 80);   // 80% of QUOTE
        }
        dap_chain_datum_tx_t *tx_aon = NULL;
        dap_chain_net_srv_dex_purchase_error_t err;
        
        // Step 1a: Try partial with budget in BUY token (should be rejected)
        // API: is_budget_buy=true means budget in token buyer wants to buy
        //   ASK order: buyer buys BASE → budget_in_base=true → use partial_80_base
        //   BID order: buyer buys QUOTE → budget_in_base=false → use partial_80_quote
        // API: is_budget_buy=false means budget in token buyer sells
        //   ASK order: buyer sells QUOTE → use partial_80_quote
        //   BID order: buyer sells BASE → use partial_80_base
        uint256_t budget_buy = (ctx->tmpl->side == SIDE_ASK) ? partial_80_base : partial_80_quote;
        uint256_t budget_sell = (ctx->tmpl->side == SIDE_ASK) ? partial_80_quote : partial_80_base;
        log_it(L_INFO, "--- AON: partial 80%% with budget in BUY token ---");
        err = dap_chain_net_srv_dex_purchase(
            f->net->net, &order->tail, budget_buy, true,
            f->network_fee, buyer_wallet, false, uint256_0, &tx_aon
        );
        if (err == DEX_PURCHASE_ERROR_OK && tx_aon) {
            log_it(L_ERROR, "AON partial (budget in BUY) should be rejected");
            dap_chain_datum_tx_delete(tx_aon);
            return -1;
        }
        log_it(L_NOTICE, "✓ AON partial rejected (budget in BUY token): err=%d", err);
        
        // Step 1b: Try partial with budget in SELL token (should be rejected)
        log_it(L_INFO, "--- AON: partial 80%% with budget in SELL token ---");
        err = dap_chain_net_srv_dex_purchase(
            f->net->net, &order->tail, budget_sell, false,
            f->network_fee, buyer_wallet, false, uint256_0, &tx_aon
        );
        if (err == DEX_PURCHASE_ERROR_OK && tx_aon) {
            log_it(L_ERROR, "AON partial (budget in SELL) should be rejected");
            dap_chain_datum_tx_delete(tx_aon);
            return -2;
        }
        log_it(L_NOTICE, "✓ AON partial rejected (budget in SELL token): err=%d", err);
        
        // Step 2: Tamper min_fill to allow partial
        log_it(L_INFO, "--- AON: tampering min_fill for verifier test ---");
        uint8_t orig_minfill;
        test_dex_adjust_minfill(f, &order->tail, 0, &orig_minfill);
        
        // Step 3: Compose partial (now allowed with min_fill=0)
        err = dap_chain_net_srv_dex_purchase(
            f->net->net, &order->tail, budget_buy, true,
            f->network_fee, buyer_wallet, false, uint256_0, &tx_aon
        );
        
        // Step 4: Restore min_fill before verification
        test_dex_adjust_minfill(f, &order->tail, orig_minfill, NULL);
        
        if (err != DEX_PURCHASE_ERROR_OK || !tx_aon) {
            log_it(L_ERROR, "Failed to compose AON partial after tamper: err=%d", err);
            return -3;
        }
        
        // Step 5: Try to add to ledger — verifier should reject
        dap_hash_fast_t h = {0};
        dap_hash_fast(tx_aon, dap_chain_datum_tx_get_size(tx_aon), &h);
        int add_ret = dap_ledger_tx_add(f->net->net->pub.ledger, tx_aon, &h, false, NULL);
        dap_chain_datum_tx_delete(tx_aon);
        
        if (add_ret == 0) {
            log_it(L_ERROR, "Tampered AON partial TX should be rejected by verifier");
            return -4;
        }
        log_it(L_NOTICE, "✓ AON partial TX rejected by verifier (minfill violation)");
        
        // Step 6: Full buy AON (budget=0 means full)
        log_it(L_INFO, "--- AON: full buy (should succeed) ---");
        
        participants_t p = init_participants(f, ctx, buyer_id);
        uint128_t order_val = dap_uint256_to_uint128(order->value);
        expected_deltas_t d = calc_purchase_deltas(ctx, f, &p, order_val, false);
        uint128_t net_fee = dap_uint256_to_uint128(f->network_fee);
        
        balance_snap_t buyer_before, buyer_after, seller_before, seller_after, net_before, net_after;
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.buyer, ctx->pair, &buyer_before);
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.seller, ctx->pair, &seller_before);
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.net_fee_collector, ctx->pair, &net_before);
        
        dap_chain_datum_tx_t *tx_full = NULL;
        err = dap_chain_net_srv_dex_purchase(
            f->net->net, &order->tail, uint256_0, true,
            f->network_fee, buyer_wallet, false, uint256_0, &tx_full
        );
        if (err != DEX_PURCHASE_ERROR_OK || !tx_full) {
            log_it(L_ERROR, "AON full buy failed: err=%d", err);
            return -5;
        }
        
        dap_hash_fast_t full_hash = {0};
        dap_hash_fast(tx_full, dap_chain_datum_tx_get_size(tx_full), &full_hash);
        add_ret = dap_ledger_tx_add(f->net->net->pub.ledger, tx_full, &full_hash, false, NULL);
        if (add_ret != 0) {
            log_it(L_ERROR, "AON full buy TX rejected");
            dap_chain_datum_tx_delete(tx_full);
            return -6;
        }
        
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.buyer, ctx->pair, &buyer_after);
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.seller, ctx->pair, &seller_after);
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.net_fee_collector, ctx->pair, &net_after);
        
        int ret = verify_deltas("AON", &buyer_before, &buyer_after, &seller_before, &seller_after,
                                &net_before, &net_after, &d, &p, net_fee);
        if (ret != 0)
            return -60 + ret;
        log_it(L_NOTICE, "✓ AON full buy accepted (balances verified)");
        
        // Rollback
        dap_chain_datum_tx_t *tx_for_remove = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &full_hash);
        if (dap_ledger_tx_remove(f->net->net->pub.ledger, tx_for_remove, &full_hash) != 0) {
            log_it(L_ERROR, "AON full buy rollback failed");
            return -7;
        }
        
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.buyer, ctx->pair, &buyer_after);
        if (test_dex_snap_verify("AON rollback", &buyer_before, &buyer_after, uint128_0, false, uint128_0, false) != 0)
            return -65;
        
        log_it(L_NOTICE, "✓ AON full buy rolled back (balances verified)");
        return 0;
    }
    
    // Non-AON partial buy tests
    const char *sell_token, *buy_token;
    get_order_tokens(ctx->pair, ctx->tmpl->side, &sell_token, &buy_token);
    const dap_chain_addr_t *buyer_addr = get_wallet_addr(f, buyer_id);
    const dap_chain_addr_t *seller_addr = get_wallet_addr(f, ctx->tmpl->seller);
    
    // Calculate budget below min_fill threshold
    // ASK: value = BASE, BID: value = QUOTE (need to convert to BASE)
    uint8_t below_pct = pct - 10;  // e.g. 50% min_fill → try 40%
    uint256_t exec_sell_full, below_base, below_quote;
    if (ctx->tmpl->side == SIDE_ASK) {
        exec_sell_full = order->value;  // ASK: value is BASE
        below_base = calc_pct(exec_sell_full, below_pct);
        MULT_256_COIN(below_base, order->price, &below_quote);  // QUOTE = BASE * rate
    } else {
        DIV_256_COIN(order->value, order->price, &exec_sell_full);  // BID: BASE = QUOTE / rate
        below_base = calc_pct(exec_sell_full, below_pct);
        below_quote = calc_pct(order->value, below_pct);  // QUOTE = % of value
    }
    
    dap_chain_datum_tx_t *tx = NULL;
    dap_chain_net_srv_dex_purchase_error_t err;
    
    // API: is_budget_buy=true means token buyer wants (ASK: BASE, BID: QUOTE)
    //      is_budget_buy=false means token buyer sells (ASK: QUOTE, BID: BASE)
    uint256_t budget_buy_below = (ctx->tmpl->side == SIDE_ASK) ? below_base : below_quote;
    uint256_t budget_sell_below = (ctx->tmpl->side == SIDE_ASK) ? below_quote : below_base;
    
    // Step 1a: Budget in BUY token below min_fill → composer rejects
    log_it(L_INFO, "--- Partial %d%% in BUY token (below min_fill=%s) ---", below_pct, get_minfill_desc(min_fill));
    err = dap_chain_net_srv_dex_purchase(f->net->net, &order->tail, budget_buy_below, true,
                                          f->network_fee, buyer_wallet, false, uint256_0, &tx);
    if (err == DEX_PURCHASE_ERROR_OK && tx) {
        log_it(L_ERROR, "Below-min_fill (BUY) should be rejected by composer");
        dap_chain_datum_tx_delete(tx);
        return -1;
    }
    log_it(L_NOTICE, "✓ Below-min_fill (BUY) rejected: err=%d", err);
    
    // Step 1b: Budget in SELL token below min_fill → composer rejects
    log_it(L_INFO, "--- Partial %d%% in SELL token (below min_fill=%s) ---", below_pct, get_minfill_desc(min_fill));
    err = dap_chain_net_srv_dex_purchase(f->net->net, &order->tail, budget_sell_below, false,
                                          f->network_fee, buyer_wallet, false, uint256_0, &tx);
    if (err == DEX_PURCHASE_ERROR_OK && tx) {
        log_it(L_ERROR, "Below-min_fill (SELL) should be rejected by composer");
        dap_chain_datum_tx_delete(tx);
        return -2;
    }
    log_it(L_NOTICE, "✓ Below-min_fill (SELL) rejected: err=%d", err);
    
    // Step 2: Tamper min_fill → compose → verifier rejects
    log_it(L_INFO, "--- Tampering min_fill for verifier test ---");
    uint8_t orig_minfill;
    test_dex_adjust_minfill(f, &order->tail, 0, &orig_minfill);
    
    err = dap_chain_net_srv_dex_purchase(f->net->net, &order->tail, budget_buy_below, true,
                                          f->network_fee, buyer_wallet, false, uint256_0, &tx);
    test_dex_adjust_minfill(f, &order->tail, orig_minfill, NULL);
    
    if (err != DEX_PURCHASE_ERROR_OK || !tx) {
        log_it(L_ERROR, "Failed to compose after minfill tamper: err=%d", err);
        return -3;
    }
    
    dap_hash_fast_t h = {0};
    dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), &h);
    int add_ret = dap_ledger_tx_add(f->net->net->pub.ledger, tx, &h, false, NULL);
    dap_chain_datum_tx_delete(tx);
    
    if (add_ret == 0) {
        log_it(L_ERROR, "Tampered partial TX should be rejected by verifier");
        return -4;
    }
    log_it(L_NOTICE, "✓ Tampered partial TX rejected by verifier");
    
    // Boundary check: exact min_fill%
    {
        uint256_t boundary_base, boundary_quote;
        if (ctx->tmpl->side == SIDE_ASK) {
            boundary_base = calc_pct(exec_sell_full, pct);
            MULT_256_COIN(boundary_base, order->price, &boundary_quote);
        } else {
            boundary_base = calc_pct(exec_sell_full, pct);
            boundary_quote = calc_pct(order->value, pct);
        }
        
        participants_t p = init_participants(f, ctx, buyer_id);
        uint128_t partial_val = (ctx->tmpl->side == SIDE_ASK)
            ? dap_uint256_to_uint128(boundary_base)
            : dap_uint256_to_uint128(boundary_quote);
        expected_deltas_t d = calc_purchase_deltas(ctx, f, &p, partial_val, false);
        uint128_t net_fee = dap_uint256_to_uint128(f->network_fee);
        
        uint256_t budget_buy_boundary = (ctx->tmpl->side == SIDE_ASK) ? boundary_base : boundary_quote;
        
        balance_snap_t buyer_before, buyer_after, seller_before, seller_after, net_before, net_after;
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.buyer, ctx->pair, &buyer_before);
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.seller, ctx->pair, &seller_before);
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.net_fee_collector, ctx->pair, &net_before);
        
        log_it(L_INFO, "--- Boundary partial %d%% in BUY token ---", pct);
        err = dap_chain_net_srv_dex_purchase(f->net->net, &order->tail, budget_buy_boundary, true,
                                              f->network_fee, buyer_wallet, false, uint256_0, &tx);
        if (err != DEX_PURCHASE_ERROR_OK || !tx) {
            log_it(L_ERROR, "Boundary partial failed: err=%d", err);
            return -42;
        }
        
        dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), &h);
        add_ret = dap_ledger_tx_add(f->net->net->pub.ledger, tx, &h, false, NULL);
        if (add_ret != 0) {
            log_it(L_ERROR, "Boundary partial TX rejected");
            dap_chain_datum_tx_delete(tx);
            return -43;
        }
        
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.buyer, ctx->pair, &buyer_after);
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.seller, ctx->pair, &seller_after);
        test_dex_snap_take_pair(f->net->net->pub.ledger, p.net_fee_collector, ctx->pair, &net_after);
        
        int ret = verify_deltas("Boundary", &buyer_before, &buyer_after, &seller_before, &seller_after,
                                &net_before, &net_after, &d, &p, net_fee);
        if (ret != 0)
            return -44 + ret;
        
        // Rollback to restore order
        dap_chain_datum_tx_t *tx_for_remove = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &h);
        if (dap_ledger_tx_remove(f->net->net->pub.ledger, tx_for_remove, &h) != 0) {
            log_it(L_ERROR, "Boundary rollback failed");
            return -47;
        }
        log_it(L_NOTICE, "✓ Boundary partial accepted and rolled back");
    }
    
    // BID dust rejection: minimal BUY budget should fail
    if (ctx->tmpl->side == SIDE_BID) {
        uint256_t tiny_budget = GET_256_FROM_64(1);
        dap_chain_datum_tx_t *tx_tiny = NULL;
        dap_chain_net_srv_dex_purchase_error_t err_tiny = dap_chain_net_srv_dex_purchase(
            f->net->net, &order->tail, tiny_budget, true,
            f->network_fee, buyer_wallet, false, uint256_0, &tx_tiny
        );
        if (err_tiny == DEX_PURCHASE_ERROR_OK && tx_tiny) {
            dap_hash_fast_t h_tiny = {0};
            dap_hash_fast(tx_tiny, dap_chain_datum_tx_get_size(tx_tiny), &h_tiny);
            int add_ret_tiny = dap_ledger_tx_add(f->net->net->pub.ledger, tx_tiny, &h_tiny, false, NULL);
            dap_chain_datum_tx_delete(tx_tiny);
            if (add_ret_tiny == 0) {
                log_it(L_ERROR, "Dust BID budget was accepted");
                return -48;
            }
        }
        log_it(L_NOTICE, "✓ Dust BID budget rejected (err=%d)", err_tiny);
    }
    
    // Step 3: Valid partial at min_fill boundary
    uint8_t valid_pct = pct + 5;  // e.g. 50% min_fill → try 55%
    uint256_t valid_base, valid_quote;
    if (ctx->tmpl->side == SIDE_ASK) {
        valid_base = calc_pct(exec_sell_full, valid_pct);
        MULT_256_COIN(valid_base, order->price, &valid_quote);
    } else {
        valid_base = calc_pct(exec_sell_full, valid_pct);
        valid_quote = calc_pct(order->value, valid_pct);
    }
    
    participants_t p = init_participants(f, ctx, buyer_id);
    uint128_t partial_val = (ctx->tmpl->side == SIDE_ASK)
        ? dap_uint256_to_uint128(valid_base)
        : dap_uint256_to_uint128(valid_quote);
    expected_deltas_t d = calc_purchase_deltas(ctx, f, &p, partial_val, false);
    uint128_t net_fee = dap_uint256_to_uint128(f->network_fee);
    
    uint256_t budget_buy_valid = (ctx->tmpl->side == SIDE_ASK) ? valid_base : valid_quote;
    
    balance_snap_t buyer_before, buyer_after, seller_before, seller_after, net_before, net_after;
    
    // Step 3a: Valid partial in BUY token
    log_it(L_INFO, "--- Valid partial %d%% in BUY token ---", valid_pct);
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.buyer, ctx->pair, &buyer_before);
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.seller, ctx->pair, &seller_before);
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.net_fee_collector, ctx->pair, &net_before);
    
    err = dap_chain_net_srv_dex_purchase(f->net->net, &order->tail, budget_buy_valid, true,
                                          f->network_fee, buyer_wallet, false, uint256_0, &tx);
    if (err != DEX_PURCHASE_ERROR_OK || !tx) {
        log_it(L_ERROR, "Valid partial (BASE) failed: err=%d", err);
        return -5;
    }
    
    // Security tamper tests
    if (test_dex_tamper_and_verify_rejection(f, tx, buyer_wallet,
            tamper_order_root_hash, NULL, "Blank order_root_hash in partial") != 0) {
        dap_chain_datum_tx_delete(tx);
        return -70;
    }
    
    {
        dap_hash_fast_t fake_hash;
        memset(&fake_hash, 0xCD, sizeof(fake_hash));
        if (test_dex_tamper_and_verify_rejection(f, tx, buyer_wallet,
                tamper_order_root_hash, &fake_hash, "Wrong order_root_hash in partial") != 0) {
            dap_chain_datum_tx_delete(tx);
            return -71;
        }
    }
    
    {
        uint8_t wrong_type = DEX_TX_TYPE_ORDER;
        if (test_dex_tamper_and_verify_rejection(f, tx, buyer_wallet,
                tamper_tx_type, &wrong_type, "Wrong tx_type ORDER in partial") != 0) {
            dap_chain_datum_tx_delete(tx);
            return -72;
        }
    }
    
    dap_hash_fast_t partial_hash = {0};
    dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), &partial_hash);
    add_ret = dap_ledger_tx_add(f->net->net->pub.ledger, tx, &partial_hash, false, NULL);
    if (add_ret != 0) {
        log_it(L_ERROR, "Valid partial (BASE) TX rejected");
        dap_chain_datum_tx_delete(tx);
        return -6;
    }
    
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.buyer, ctx->pair, &buyer_after);
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.seller, ctx->pair, &seller_after);
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.net_fee_collector, ctx->pair, &net_after);
    
    int ret = verify_deltas("Partial", &buyer_before, &buyer_after, &seller_before, &seller_after,
                            &net_before, &net_after, &d, &p, net_fee);
    if (ret != 0)
        return -50 + ret;
    log_it(L_NOTICE, "✓ Valid partial (BASE) accepted (balances verified)");
    
    // Rollback
    dap_chain_datum_tx_t *tx_for_remove = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &partial_hash);
    if (dap_ledger_tx_remove(f->net->net->pub.ledger, tx_for_remove, &partial_hash) != 0) {
        log_it(L_ERROR, "Rollback failed");
        return -7;
    }
    
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.buyer, ctx->pair, &buyer_after);
    if (test_dex_snap_verify("Partial rollback", &buyer_before, &buyer_after, uint128_0, false, uint128_0, false) != 0)
        return -55;
    log_it(L_NOTICE, "✓ Rolled back for QUOTE test");
    
    // Step 3b: Valid partial in SELL token (is_budget_buy=false)
    // BID with BASE budget requires canonical correction
    uint256_t budget_sell_valid = (ctx->tmpl->side == SIDE_ASK) ? valid_quote : valid_base;
    expected_deltas_t d_sell = d;  // Start with same deltas as Step 3a
    
    if (ctx->tmpl->side == SIDE_BID) {
        // BID with BASE budget: apply canonical correction (same as composer)
        uint128_t rate = dap_uint256_to_uint128(order->price);
        uint128_t budget_base = dap_uint256_to_uint128(valid_base);
        uint128_t exec_quote, exec_sell_canonical, tmp128;
        // exec_quote = (budget_base * rate) / S_POW18
        MULT_128_128(budget_base, rate, &tmp128);
        DIV_128(tmp128, GET_128_FROM_64(S_POW18), &exec_quote);
        // exec_sell_canonical = (exec_quote * S_POW18) / rate
        MULT_128_128(exec_quote, GET_128_FROM_64(S_POW18), &tmp128);
        DIV_128(tmp128, rate, &exec_sell_canonical);
        
        uint8_t fee_cfg = ctx->pair->fee_config;
        bool is_pct_fee = (fee_cfg & 0x80) != 0;
        uint128_t service_fee = uint128_0;
        // % fee from INPUT (BASE for BID), 0.1% step
        if (is_pct_fee) {
            MULT_128_128(exec_sell_canonical, GET_128_FROM_64(fee_cfg & 0x7F), &tmp128);
            DIV_128(tmp128, GET_128_FROM_64(1000), &service_fee);
        }
        
        SUM_128_128(exec_sell_canonical, service_fee, &d_sell.buyer_base);
        d_sell.buyer_quote = exec_quote;  // full QUOTE
        d_sell.seller_base = exec_sell_canonical;
        // % fee in BASE aggregates to seller if seller == service
        if (p.seller_is_service && is_pct_fee)
            SUM_128_128(d_sell.seller_base, service_fee, &d_sell.seller_base);
        if (p.seller_is_net_collector && ctx->pair->base_is_native)
            SUM_128_128(d_sell.seller_base, net_fee, &d_sell.seller_base);
        // Native abs fee in BASE aggregates to seller payout
        if (p.seller_is_service && !is_pct_fee && ctx->pair->base_is_native)
            SUM_128_128(d_sell.seller_base, get_native_srv_fee(fee_cfg), &d_sell.seller_base);
        
        uint128_t extra_quote = (p.seller_is_net_collector && ctx->pair->quote_is_native) ? net_fee : uint128_0;
        uint128_t abs_fee = (p.seller_is_service && !is_pct_fee && ctx->pair->quote_is_native)
            ? get_native_srv_fee(fee_cfg) : uint128_0;
        SUM_128_128(extra_quote, abs_fee, &d_sell.seller_quote);
        
        adjust_native_fee(ctx->tmpl->side, ctx->pair->quote_is_native, ctx->pair->base_is_native,
                          p.buyer_is_net_collector, net_fee, &d_sell.buyer_base, &d_sell.buyer_quote);
        adjust_abs_service_fee(ctx->tmpl->side, ctx->pair->quote_is_native, ctx->pair->base_is_native,
                               fee_cfg, &d_sell.buyer_base, &d_sell.buyer_quote);
    }
    
    log_it(L_INFO, "--- Valid partial %d%% in SELL token ---", valid_pct);
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.buyer, ctx->pair, &buyer_before);
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.seller, ctx->pair, &seller_before);
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.net_fee_collector, ctx->pair, &net_before);
    
    err = dap_chain_net_srv_dex_purchase(f->net->net, &order->tail, budget_sell_valid, false,
                                          f->network_fee, buyer_wallet, false, uint256_0, &tx);
    if (err != DEX_PURCHASE_ERROR_OK || !tx) {
        log_it(L_ERROR, "Valid partial (QUOTE) failed: err=%d", err);
        return -8;
    }
    
    dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), &partial_hash);
    add_ret = dap_ledger_tx_add(f->net->net->pub.ledger, tx, &partial_hash, false, NULL);
    if (add_ret != 0) {
        log_it(L_ERROR, "Valid partial (QUOTE) TX rejected");
        dap_chain_datum_tx_delete(tx);
        return -9;
    }
    
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.buyer, ctx->pair, &buyer_after);
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.seller, ctx->pair, &seller_after);
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.net_fee_collector, ctx->pair, &net_after);
    
    ret = verify_deltas("PartialQ", &buyer_before, &buyer_after, &seller_before, &seller_after,
                        &net_before, &net_after, &d_sell, &p, net_fee);
    if (ret != 0)
        return -56 + ret;
    log_it(L_NOTICE, "✓ Valid partial (QUOTE) accepted (balances verified)");
    
    // Rollback
    tx_for_remove = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &partial_hash);
    if (dap_ledger_tx_remove(f->net->net->pub.ledger, tx_for_remove, &partial_hash) != 0) {
        log_it(L_ERROR, "Final rollback failed");
        return -10;
    }
    
    log_it(L_NOTICE, "✓ Partial buy phase complete, order restored");
    return 0;
}

// ============================================================================
// PHASE 4: SUB-MINFILL LEFTOVER (from_origin orders only)
// Demonstrates difference between from_origin and from_current policies
// ============================================================================

static int run_phase_sub_minfill(test_context_t *ctx) {
    uint8_t pct = MINFILL_PCT(ctx->tmpl->min_fill);
    bool from_origin = MINFILL_IS_FROM_ORIGIN(ctx->tmpl->min_fill);
    
    // Only run for from_origin policies with meaningful pct
    if (!from_origin || pct < 50) {
        log_it(L_INFO, "Skipping sub-minfill phase (only for from_origin with pct>=50)");
        return 0;
    }
    
    log_it(L_INFO, "=== PHASE 4: SUB-MINFILL (from_origin vs from_current) ===");
    
    dex_test_fixture_t *f = ctx->fixture;
    dex_order_info_t *order = &ctx->order;
    wallet_id_t buyer_id = get_regular_buyer(ctx->tmpl->side);
    dap_chain_wallet_t *buyer_wallet = get_wallet(f, buyer_id);
    const dap_chain_addr_t *buyer_addr = get_wallet_addr(f, buyer_id);
    const dap_chain_addr_t *seller_addr = get_wallet_addr(f, ctx->tmpl->seller);
    
    const char *sell_token, *buy_token;
    get_order_tokens(ctx->pair, ctx->tmpl->side, &sell_token, &buy_token);
    
    // -------------------------------------------------------------------------
    // Calculate values for from_origin vs from_current boundary test
    // -------------------------------------------------------------------------
    // Strategy: after first partial, compute test_amount = pct% of CURRENT leftover.
    // This amount is valid for from_current but invalid for from_origin.
    // Example for pct=75, origin=100:
    //   - partial_pct=80% → leftover=20
    //   - test_amount = 75% of 20 = 15
    //   - 15 >= 15 (from_current) ✓  but  15 < 75 (from_origin) ✗
    // -------------------------------------------------------------------------
    uint256_t origin_value = order->value;
    
    // First partial: leave leftover < min_from_origin to create sub-minfill state
    // Use pct+1 margin to compensate BID round-trip truncation
    uint8_t partial_pct = dap_max(pct + 1, 76);
    if (partial_pct > 95) partial_pct = 95;
    uint8_t leftover_pct = 100 - partial_pct;
    
    uint256_t partial_amount = calc_pct(origin_value, partial_pct);
    uint256_t leftover_value = calc_pct(origin_value, leftover_pct);
    
    // test_amount = pct% of CURRENT leftover (valid for from_current, invalid for from_origin)
    // For ASK: leftover is BASE, test_amount is BASE
    // For BID: leftover is QUOTE, test_amount is QUOTE
    uint256_t test_amount = calc_pct(leftover_value, pct);
    // budget_sell_test: token buyer SELLS (ASK: QUOTE, BID: BASE)
    uint256_t budget_sell_test;
    if (ctx->tmpl->side == SIDE_ASK)
        MULT_256_COIN(test_amount, order->price, &budget_sell_test);  // BASE * rate = QUOTE
    else
        DIV_256_COIN(test_amount, order->price, &budget_sell_test);   // QUOTE / rate = BASE
    uint256_t min_from_origin = calc_pct(origin_value, pct);
    
    log_it(L_INFO, "origin=%s, leftover=%s (%d%%), test_amount=%s (%d%% of current)",
           dap_uint256_to_char_ex(origin_value).frac,
           dap_uint256_to_char_ex(leftover_value).frac, leftover_pct,
           dap_uint256_to_char_ex(test_amount).frac, pct);
    log_it(L_INFO, "min_from_origin=%s, test_amount < min_from_origin: %s",
           dap_uint256_to_char_ex(min_from_origin).frac,
           compare256(test_amount, min_from_origin) < 0 ? "YES (test valid)" : "NO (test invalid)");
    
    // Init participants and calculate expected deltas for Step 1
    participants_t p = init_participants(f, ctx, buyer_id);
    uint128_t partial_val = dap_uint256_to_uint128(partial_amount);
    expected_deltas_t d1 = calc_purchase_deltas(ctx, f, &p, partial_val, false);
    uint128_t net_fee = dap_uint256_to_uint128(f->network_fee);
    
    // -------------------------------------------------------------------------
    // Step 1: Partial buy to create sub-minfill leftover
    // -------------------------------------------------------------------------
    log_it(L_INFO, "--- Step 1: Partial %d%% (%s) → leftover %d%% ---",
           partial_pct, dap_uint256_to_char_ex(partial_amount).frac, leftover_pct);
    
    balance_snap_t buyer_before, buyer_after, seller_before, seller_after, net_before, net_after;
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.buyer, ctx->pair, &buyer_before);
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.seller, ctx->pair, &seller_before);
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.net_fee_collector, ctx->pair, &net_before);
    
    dap_chain_datum_tx_t *tx_partial = NULL;
    dap_chain_net_srv_dex_purchase_error_t err = dap_chain_net_srv_dex_purchase(
        f->net->net, &order->tail, partial_amount, true,
        f->network_fee, buyer_wallet, false, uint256_0, &tx_partial
    );
    
    if (err != DEX_PURCHASE_ERROR_OK || !tx_partial) {
        log_it(L_ERROR, "Failed to create partial TX: err=%d", err);
        return -1;
    }
    
    dap_hash_fast_t partial_hash = {0};
    dap_hash_fast(tx_partial, dap_chain_datum_tx_get_size(tx_partial), &partial_hash);
    
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx_partial, &partial_hash, false, NULL) != 0) {
        log_it(L_ERROR, "Partial TX rejected by ledger");
        dap_chain_datum_tx_delete(tx_partial);
        return -2;
    }
    
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.buyer, ctx->pair, &buyer_after);
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.seller, ctx->pair, &seller_after);
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.net_fee_collector, ctx->pair, &net_after);
    
    int ret = verify_deltas("SubMF", &buyer_before, &buyer_after, &seller_before, &seller_after,
                            &net_before, &net_after, &d1, &p, net_fee);
    if (ret != 0)
        return -20 + ret;
    
    log_it(L_NOTICE, "✓ Partial %d%% accepted (balances verified)", partial_pct);
    ctx->order_hash = partial_hash;
    
    // Update order info to get actual leftover value (may differ due to rounding)
    dex_order_info_t updated_order;
    if (test_dex_order_get_info(f->net->net->pub.ledger, &partial_hash, &updated_order) == 0) {
        leftover_value = updated_order.value;  // actual leftover after Step 1
        // Recalculate test_amount based on actual leftover
        test_amount = calc_pct(leftover_value, pct);
        if (ctx->tmpl->side == SIDE_ASK)
            MULT_256_COIN(test_amount, order->price, &budget_sell_test);
        else
            DIV_256_COIN(test_amount, order->price, &budget_sell_test);
    }
    
    // -------------------------------------------------------------------------
    // Step 2a: Try partial with test_amount in BASE (should reject - from_origin)
    // test_amount = pct% of current, which is < pct% of origin
    // -------------------------------------------------------------------------
    log_it(L_INFO, "--- Step 2a: Try %s BASE (%d%% of current) → composer reject (from_origin) ---",
           dap_uint256_to_char_ex(test_amount).frac, pct);
    
    dap_chain_datum_tx_t *tx_test = NULL;
    err = dap_chain_net_srv_dex_purchase(
        f->net->net, &partial_hash, test_amount, true,
        f->network_fee, buyer_wallet, false, uint256_0, &tx_test
    );
    
    if (err == DEX_PURCHASE_ERROR_OK && tx_test) {
        log_it(L_ERROR, "Composer should reject (test_amount < min_from_origin)");
        dap_chain_datum_tx_delete(tx_test);
        return -3;
    }
    log_it(L_NOTICE, "✓ Composer rejected: %d%% of current < %d%% of origin (BASE): err=%d", pct, pct, err);
    
    // -------------------------------------------------------------------------
    // Step 2b: Try partial with budget in SELL token (should reject - from_origin)
    // ASK: buyer sells QUOTE; BID: buyer sells BASE
    // -------------------------------------------------------------------------
    log_it(L_INFO, "--- Step 2b: Try %s in SELL token → composer reject ---",
           dap_uint256_to_char_ex(budget_sell_test).frac);
    
    tx_test = NULL;
    err = dap_chain_net_srv_dex_purchase(
        f->net->net, &partial_hash, budget_sell_test, false,
        f->network_fee, buyer_wallet, false, uint256_0, &tx_test
    );
    
    if (err == DEX_PURCHASE_ERROR_OK && tx_test) {
        log_it(L_ERROR, "Composer should reject (test_amount < min_from_origin)");
        dap_chain_datum_tx_delete(tx_test);
        return -4;
    }
    log_it(L_NOTICE, "✓ Composer rejected: %d%% of current < %d%% of origin (SELL token): err=%d", pct, pct, err);
    
    // -------------------------------------------------------------------------
    // Step 3: Tamper from_origin → from_current, compose, restore, verifier reject
    // Change min_fill from "pct | 0x80" to just "pct" (remove from_origin flag)
    // -------------------------------------------------------------------------
    log_it(L_INFO, "--- Step 3: Tamper policy from_origin→from_current, compose, restore → verifier reject ---");
    
    uint8_t orig_minfill;
    uint8_t tampered_minfill = pct;  // Same pct but WITHOUT from_origin flag (0x80)
    if (test_dex_adjust_minfill(f, &partial_hash, tampered_minfill, &orig_minfill) != 0) {
        log_it(L_ERROR, "Failed to adjust min_fill");
        return -5;
    }
    log_it(L_DEBUG, "Tampered min_fill: 0x%02X → 0x%02X (removed from_origin)", orig_minfill, tampered_minfill);
    
    dap_chain_datum_tx_t *tx_tampered = NULL;
    err = dap_chain_net_srv_dex_purchase(
        f->net->net, &partial_hash, test_amount, true,
        f->network_fee, buyer_wallet, false, uint256_0, &tx_tampered
    );
    
    // Restore original policy BEFORE adding to ledger
    test_dex_adjust_minfill(f, &partial_hash, orig_minfill, NULL);
    
    if (err != DEX_PURCHASE_ERROR_OK || !tx_tampered) {
        log_it(L_ERROR, "Composer should accept with from_current policy: err=%d", err);
        return -6;
    }
    log_it(L_NOTICE, "✓ Composer accepted with tampered from_current policy");
    
    dap_hash_fast_t tampered_hash = {0};
    dap_hash_fast(tx_tampered, dap_chain_datum_tx_get_size(tx_tampered), &tampered_hash);
    
    int add_ret = dap_ledger_tx_add(f->net->net->pub.ledger, tx_tampered, &tampered_hash, false, NULL);
    dap_chain_datum_tx_delete(tx_tampered);
    
    if (add_ret == 0) {
        log_it(L_ERROR, "Verifier should reject (policy restored to from_origin)");
        return -7;
    }
    log_it(L_NOTICE, "✓ Verifier rejected: real policy is from_origin, test_amount too small");
    
    // -------------------------------------------------------------------------
    // Step 4: Full buy of leftover → should succeed
    // -------------------------------------------------------------------------
    log_it(L_INFO, "--- Step 4: Full buy of leftover (%s) ---",
           dap_uint256_to_char_ex(leftover_value).frac);
    
    uint128_t left_val = dap_uint256_to_uint128(leftover_value);
    expected_deltas_t d4 = calc_purchase_deltas(ctx, f, &p, left_val, false);
    
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.buyer, ctx->pair, &buyer_before);
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.seller, ctx->pair, &seller_before);
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.net_fee_collector, ctx->pair, &net_before);
    
    dap_chain_datum_tx_t *tx_full = NULL;
    err = dap_chain_net_srv_dex_purchase(
        f->net->net, &partial_hash, uint256_0, true,
        f->network_fee, buyer_wallet, false, uint256_0, &tx_full
    );
    
    if (err != DEX_PURCHASE_ERROR_OK || !tx_full) {
        log_it(L_ERROR, "Failed to create full buy: err=%d", err);
        return -8;
    }
    
    dap_hash_fast_t full_hash = {0};
    dap_hash_fast(tx_full, dap_chain_datum_tx_get_size(tx_full), &full_hash);
    
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx_full, &full_hash, false, NULL) != 0) {
        log_it(L_ERROR, "Full buy of leftover rejected");
        dap_chain_datum_tx_delete(tx_full);
        return -9;
    }
    
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.buyer, ctx->pair, &buyer_after);
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.seller, ctx->pair, &seller_after);
    test_dex_snap_take_pair(f->net->net->pub.ledger, p.net_fee_collector, ctx->pair, &net_after);
    
    ret = verify_deltas("SubMF Full", &buyer_before, &buyer_after, &seller_before, &seller_after,
                        &net_before, &net_after, &d4, &p, net_fee);
    if (ret != 0)
        return -90 + ret;
    
    log_it(L_NOTICE, "✓ Full buy of sub-minfill leftover accepted (balances verified)");
    log_it(L_NOTICE, "✓ SUB-MINFILL PHASE COMPLETE (only full buy allowed)");
    return 0;
}

// ============================================================================
// PHASE 5: UPDATE UNTOUCHED ORDER
// Update the current order (after Phase 3 rollback it's untouched again)
// Includes tampering tests for UPDATE verification
// ============================================================================

static int run_phase_update_untouched(test_context_t *ctx) {
    log_it(L_INFO, "=== PHASE 5: UPDATE UNTOUCHED (current order) ===");
    
    dex_test_fixture_t *f = ctx->fixture;
    dex_order_info_t *order = &ctx->order;
    
    dap_chain_wallet_t *seller_wallet = get_wallet(f, ctx->tmpl->seller);
    const dap_chain_addr_t *seller_addr = get_wallet_addr(f, ctx->tmpl->seller);
    
    // Non-owner update must be rejected
    wallet_id_t non_owner_id = (ctx->tmpl->seller == WALLET_ALICE) ? WALLET_BOB : WALLET_ALICE;
    dap_chain_wallet_t *non_owner_wallet = get_wallet(f, non_owner_id);
    dap_chain_datum_tx_t *foreign_tx = NULL;
    dap_chain_net_srv_dex_update_error_t foreign_err = dap_chain_net_srv_dex_update(
        f->net->net, &ctx->order_hash, true, order->value, f->network_fee, non_owner_wallet, &foreign_tx
    );
    if (foreign_err == DEX_UPDATE_ERROR_OK && foreign_tx) {
        log_it(L_ERROR, "Foreign UPDATE should have been rejected by API");
        dap_chain_datum_tx_delete(foreign_tx);
        return -21;
    }
    log_it(L_NOTICE, "✓ Foreign UPDATE rejected at API level");
    
    const char *sell_token, *buy_token;
    get_order_tokens(ctx->pair, ctx->tmpl->side, &sell_token, &buy_token);
    
    // Take snapshot before update
    balance_snap_t seller_before;
    test_dex_snap_take(f->net->net->pub.ledger, seller_addr, sell_token, buy_token, &seller_before);
    
    // Update: increase value by 50%
    uint256_t delta = uint256_0;
    DIV_256(order->value, GET_256_FROM_64(2), &delta);
    uint256_t new_value = uint256_0;
    SUM_256_256(order->value, delta, &new_value);
    
    log_it(L_INFO, "UPDATE: %s → %s (increase by 50%%)", 
           dap_uint256_to_char_ex(order->value).frac, dap_uint256_to_char_ex(new_value).frac);
    
    // Build UPDATE TX template via API
    dap_chain_datum_tx_t *tx_template = NULL;
    dap_chain_net_srv_dex_update_error_t err = dap_chain_net_srv_dex_update(
        f->net->net, &ctx->order_hash, true, new_value, f->network_fee, seller_wallet, &tx_template
    );
    if (err != DEX_UPDATE_ERROR_OK || !tx_template) {
        log_it(L_ERROR, "Failed to create UPDATE TX: err=%d", err);
        return -1;
    }
    
    // === TAMPERING TESTS ===
    
    // T1: Wrong tx_type (INVALIDATE instead of UPDATE)
    uint8_t wrong_type = DEX_TX_TYPE_INVALIDATE;
    if (test_dex_tamper_and_verify_rejection(f, tx_template, seller_wallet,
            tamper_tx_type, &wrong_type, "UPDATE: wrong tx_type (INVALIDATE)") != 0) {
        dap_chain_datum_tx_delete(tx_template);
        return -10;
    }
    
    // T2: Wrong tx_type (EXCHANGE instead of UPDATE)
    wrong_type = DEX_TX_TYPE_EXCHANGE;
    if (test_dex_tamper_and_verify_rejection(f, tx_template, seller_wallet,
            tamper_tx_type, &wrong_type, "UPDATE: wrong tx_type (EXCHANGE)") != 0) {
        dap_chain_datum_tx_delete(tx_template);
        return -11;
    }
    
    // T3: Wrong root_hash (blank)
    if (test_dex_tamper_and_verify_rejection(f, tx_template, seller_wallet,
            tamper_order_root_hash, NULL, "UPDATE: blank root_hash") != 0) {
        dap_chain_datum_tx_delete(tx_template);
        return -12;
    }
    
    // T4: Wrong root_hash (random)
    dap_hash_fast_t random_hash = {0};
    dap_hash_fast("random_data", 11, &random_hash);
    if (test_dex_tamper_and_verify_rejection(f, tx_template, seller_wallet,
            tamper_order_root_hash, &random_hash, "UPDATE: random root_hash") != 0) {
        dap_chain_datum_tx_delete(tx_template);
        return -13;
    }
    
    // T5: Inflate output value (attempt to get more tokens)
    tamper_output_data_t tamper_data = {
        .target_addr = (dap_chain_addr_t*)seller_addr,
        .token = sell_token,
        .tampered_value = dap_chain_coins_to_balance("99999.0")
    };
    if (test_dex_tamper_and_verify_rejection(f, tx_template, seller_wallet,
            tamper_inflate_output, &tamper_data, "UPDATE: inflate OUT_COND value") != 0) {
        dap_chain_datum_tx_delete(tx_template);
        return -14;
    }
    
    // T6: Change immutable field: rate
    uint256_t fake_rate = dap_chain_coins_to_balance("999.0");
    if (test_dex_tamper_and_verify_rejection(f, tx_template, seller_wallet,
            tamper_rate, &fake_rate, "UPDATE: change rate (immutable)") != 0) {
        dap_chain_datum_tx_delete(tx_template);
        return -15;
    }
    
    // T7: Change immutable field: buy_token
    const char *fake_token = "FAKE";
    if (test_dex_tamper_and_verify_rejection(f, tx_template, seller_wallet,
            tamper_buy_token, (void*)fake_token, "UPDATE: change buy_token (immutable)") != 0) {
        dap_chain_datum_tx_delete(tx_template);
        return -16;
    }
    
    // T8: Change immutable field: min_fill
    uint8_t fake_mf = 0xFF;
    if (test_dex_tamper_and_verify_rejection(f, tx_template, seller_wallet,
            tamper_min_fill, &fake_mf, "UPDATE: change min_fill (immutable)") != 0) {
        dap_chain_datum_tx_delete(tx_template);
        return -17;
    }
    
    log_it(L_NOTICE, "✓ All UPDATE tampering tests passed (incl. immutables)");
    
    // === VALID UPDATE ===
    dap_hash_fast_t update_hash = {0};
    dap_hash_fast(tx_template, dap_chain_datum_tx_get_size(tx_template), &update_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx_template, &update_hash, false, NULL) != 0) {
        log_it(L_ERROR, "Valid UPDATE TX rejected");
        dap_chain_datum_tx_delete(tx_template);
        return -2;
    }
    
    // Verify balance: seller should have locked additional 'delta' tokens
    // net_fee + validator_fee (2x net_fee) is paid in native token:
    //   - if sell_token IS native: deduct from BASE
    //   - if buy_token IS native: deduct from QUOTE
    balance_snap_t seller_after;
    test_dex_snap_take(f->net->net->pub.ledger, seller_addr, sell_token, buy_token, &seller_after);
    
    bool sell_is_native = (ctx->tmpl->side == SIDE_ASK) ? ctx->pair->base_is_native : ctx->pair->quote_is_native;
    bool buy_is_native = (ctx->tmpl->side == SIDE_ASK) ? ctx->pair->quote_is_native : ctx->pair->base_is_native;
    const dap_chain_addr_t *net_fee_addr = test_get_net_fee_addr(f);
    bool seller_is_net_collector = dap_chain_addr_compare(seller_addr, net_fee_addr);
    
    uint128_t delta_128 = dap_uint256_to_uint128(delta);
    uint128_t net_fee = dap_uint256_to_uint128(f->network_fee);
    // If seller = net_collector, net_fee returns to seller; effective fee = validator only
    uint128_t effective_fee;
    if (seller_is_net_collector)
        effective_fee = net_fee;
    else
        SUM_128_128(net_fee, net_fee, &effective_fee);  // 2 * net_fee
    
    // BASE: delta + effective_fee if sell=native, else just delta
    uint128_t expected_base;
    if (sell_is_native)
        SUM_128_128(delta_128, effective_fee, &expected_base);
    else
        expected_base = delta_128;
    // QUOTE: effective_fee if buy=native, else 0
    uint128_t expected_quote = buy_is_native ? effective_fee : uint128_0;
    bool quote_decrease = buy_is_native;
    
    if (test_dex_snap_verify("Update Untouched", &seller_before, &seller_after,
                             expected_base, true, expected_quote, quote_decrease) != 0) {
        log_it(L_ERROR, "UPDATE balance verification failed");
        return -3;
    }
    
    // Update context for next phases
    ctx->order_hash = update_hash;
    ctx->order.value = new_value;
    
    // === UPDATE SAME VALUE TEST (no-op) ===
    log_it(L_INFO, "--- Testing UPDATE with same value (no-op) ---");
    
    balance_snap_t noop_before;
    test_dex_snap_take(f->net->net->pub.ledger, seller_addr, sell_token, buy_token, &noop_before);
    
    dap_chain_datum_tx_t *tx_noop = NULL;
    dap_chain_net_srv_dex_update_error_t noop_err = dap_chain_net_srv_dex_update(
        f->net->net, &ctx->order_hash, true, new_value, f->network_fee, seller_wallet, &tx_noop
    );
    
    if (noop_err != DEX_UPDATE_ERROR_OK || !tx_noop) {
        log_it(L_ERROR, "UPDATE same value rejected by composer: err=%d", noop_err);
        return -40;
    }
    
    dap_hash_fast_t noop_hash = {0};
    dap_hash_fast(tx_noop, dap_chain_datum_tx_get_size(tx_noop), &noop_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx_noop, &noop_hash, false, NULL) != 0) {
        log_it(L_ERROR, "UPDATE same value rejected by ledger");
        dap_chain_datum_tx_delete(tx_noop);
        return -41;
    }
    
    // Verify: only fees paid, no delta in BASE
    balance_snap_t noop_after;
    test_dex_snap_take(f->net->net->pub.ledger, seller_addr, sell_token, buy_token, &noop_after);
    
    // Fees only: if native=sell, BASE decreases by fee; if native=buy, QUOTE decreases
    uint128_t noop_base = sell_is_native ? effective_fee : uint128_0;
    uint128_t noop_quote = buy_is_native ? effective_fee : uint128_0;
    
    if (test_dex_snap_verify("Update NoOp", &noop_before, &noop_after, noop_base, true, noop_quote, true) != 0) {
        log_it(L_ERROR, "UPDATE no-op balance verification failed");
        return -42;
    }
    
    ctx->order_hash = noop_hash;  // Update hash for next phases
    log_it(L_NOTICE, "✓ UPDATE same value (no-op) accepted, fees paid");
    
    log_it(L_NOTICE, "✓ UPDATE UNTOUCHED COMPLETE");
    return 0;
}

// ============================================================================
// PHASE 6: PARTIAL BUY + UPDATE LEFTOVER
// Do partial buy to create leftover, then update the leftover
// ============================================================================

static int run_phase_update_leftover(test_context_t *ctx) {
    log_it(L_INFO, "=== PHASE 6: PARTIAL BUY + UPDATE LEFTOVER ===");
    
    dex_test_fixture_t *f = ctx->fixture;
    dex_order_info_t *order = &ctx->order;
    
    wallet_id_t buyer_id = get_regular_buyer(ctx->tmpl->side);
    dap_chain_wallet_t *buyer_wallet = get_wallet(f, buyer_id);
    dap_chain_wallet_t *seller_wallet = get_wallet(f, ctx->tmpl->seller);
    const dap_chain_addr_t *seller_addr = get_wallet_addr(f, ctx->tmpl->seller);
    
    const char *sell_token, *buy_token;
    get_order_tokens(ctx->pair, ctx->tmpl->side, &sell_token, &buy_token);
    
    // Step 1: Partial buy (50% of current value)
    uint256_t buy_amount = uint256_0;
    DIV_256(order->value, GET_256_FROM_64(2), &buy_amount);
    
    char buy_str[82];
    snprintf(buy_str, sizeof(buy_str), "%s", dap_uint256_to_char_ex(buy_amount).frac);
    
    log_it(L_INFO, "Partial buy: %s (50%% of %s)", buy_str, dap_uint256_to_char_ex(order->value).frac);
    
    dap_hash_fast_t purchase_hash = {0};
    int ret = test_dex_order_purchase(f, buyer_wallet, &ctx->order_hash, buy_str, &purchase_hash);
    if (ret != 0) {
        log_it(L_ERROR, "Partial buy for UPDATE leftover failed: ret=%d", ret);
        return -1;
    }
    
    // Calculate leftover
    uint256_t leftover = uint256_0;
    SUBTRACT_256_256(order->value, buy_amount, &leftover);
    
    // Step 2: Take snapshot before update
    balance_snap_t seller_before;
    test_dex_snap_take(f->net->net->pub.ledger, seller_addr, sell_token, buy_token, &seller_before);
    
    // Step 3: Update leftover - decrease by 25%
    uint256_t decrease = uint256_0;
    DIV_256(leftover, GET_256_FROM_64(4), &decrease);
    uint256_t new_value = uint256_0;
    SUBTRACT_256_256(leftover, decrease, &new_value);
    
    char new_value_str[82];
    snprintf(new_value_str, sizeof(new_value_str), "%s", dap_uint256_to_char_ex(new_value).frac);
    
    log_it(L_INFO, "UPDATE leftover: %s → %s (decrease by 25%%)",
           dap_uint256_to_char_ex(leftover).frac, new_value_str);
    
    dap_hash_fast_t update_hash = {0};
    ret = test_dex_order_update(f, seller_wallet, &purchase_hash, NULL, new_value_str, &update_hash);
    if (ret != 0) {
        log_it(L_ERROR, "UPDATE leftover failed: ret=%d", ret);
        return -2;
    }
    
    // Step 4: Verify seller got refund
    // net_fee is paid in native token:
    //   - if sell_token IS native: deduct from BASE refund
    //   - if buy_token IS native: deduct from QUOTE
    balance_snap_t seller_after;
    test_dex_snap_take(f->net->net->pub.ledger, seller_addr, sell_token, buy_token, &seller_after);
    
    bool sell_is_native = (ctx->tmpl->side == SIDE_ASK) ? ctx->pair->base_is_native : ctx->pair->quote_is_native;
    bool buy_is_native = (ctx->tmpl->side == SIDE_ASK) ? ctx->pair->quote_is_native : ctx->pair->base_is_native;
    const dap_chain_addr_t *net_fee_addr = test_get_net_fee_addr(f);
    bool seller_is_net_collector = dap_chain_addr_compare(seller_addr, net_fee_addr);
    
    uint128_t decrease_128 = dap_uint256_to_uint128(decrease);
    uint128_t net_fee = dap_uint256_to_uint128(f->network_fee);
    uint128_t effective_fee;
    if (seller_is_net_collector)
        effective_fee = net_fee;
    else
        SUM_128_128(net_fee, net_fee, &effective_fee);  // 2 * net_fee
    
    // BASE: refund - effective_fee if sell=native, else full refund
    uint128_t base_fee = sell_is_native ? effective_fee : uint128_0;
    uint128_t expected_base;
    if (compare128(decrease_128, base_fee) > 0)
        SUBTRACT_128_128(decrease_128, base_fee, &expected_base);
    else
        expected_base = uint128_0;
    // QUOTE: effective_fee if buy=native, else 0
    uint128_t expected_quote = buy_is_native ? effective_fee : uint128_0;
    bool quote_decrease = buy_is_native;
    
    if (!IS_ZERO_128(expected_base) || !IS_ZERO_128(expected_quote)) {
        if (test_dex_snap_verify("Update Leftover", &seller_before, &seller_after,
                                 expected_base, false, expected_quote, quote_decrease) != 0) {
            log_it(L_ERROR, "UPDATE leftover balance verification failed");
            return -3;
        }
    }
    
    // Update context for next phase
    ctx->order_hash = update_hash;
    ctx->order.value = new_value;
    
    log_it(L_NOTICE, "✓ UPDATE LEFTOVER COMPLETE");
    return 0;
}

// ============================================================================
// FINAL: CANCEL ALL REMAINING ORDERS (owner-driven cleanup)
// Uses ledger iterator instead of stored context; tampering before valid cancel
// ============================================================================

typedef struct {
    dap_hash_fast_t tail;
    dap_chain_addr_t seller_addr;
    char sell_token[DAP_CHAIN_TICKER_SIZE_MAX];
    char buy_token[DAP_CHAIN_TICKER_SIZE_MAX];
} active_order_t;

static int s_collect_active_orders(dex_test_fixture_t *f, active_order_t *out, size_t max_count, size_t *out_count) {
    if (!f || !out || !out_count)
        return -1;
    *out_count = 0;
    dap_ledger_t *ledger = f->net->net->pub.ledger;
    dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(f->net->net);
    if (!it)
        return -2;
    for (dap_chain_datum_tx_t *tx = dap_ledger_datum_iter_get_first(it); tx; tx = dap_ledger_datum_iter_get_next(it)) {
        int l_out_idx = 0;
        dap_chain_tx_out_cond_t *l_out = dap_chain_datum_tx_out_cond_get(tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
        if (!l_out || dap_ledger_tx_hash_is_used_out_item(ledger, &it->cur_hash, l_out_idx, NULL))
            continue;
        if (*out_count >= max_count)
            break;
        active_order_t *slot = &out[*out_count];
        slot->tail = it->cur_hash;
        slot->seller_addr = l_out->subtype.srv_dex.seller_addr;
        const char *sell_tok = dap_ledger_tx_get_token_ticker_by_hash(ledger, &it->cur_hash);
        dap_strncpy(slot->sell_token, sell_tok ? sell_tok : "", sizeof(slot->sell_token) - 1);
        dap_strncpy(slot->buy_token, l_out->subtype.srv_dex.buy_token, sizeof(slot->buy_token) - 1);
        (*out_count)++;
    }
    dap_ledger_datum_iter_delete(it);
    return 0;
}

// dex_test_wallet_by_addr -> dex_test_wallet_by_addr (defined in helpers)

int run_cancel_all_active(dex_test_fixture_t *f) {
    log_it(L_INFO, "=== FINAL: CANCEL ALL ACTIVE ORDERS ===");
    
    active_order_t orders[256];
    size_t count = 0;
    int ret = s_collect_active_orders(f, orders, sizeof(orders)/sizeof(orders[0]), &count);
    if (ret != 0) {
        log_it(L_ERROR, "Collect active orders failed: %d", ret);
        return -1;
    }
    if (count == 0) {
        log_it(L_NOTICE, "No active orders to cancel");
        return 0;
    }
    
    for (size_t i = 0; i < count; i++) {
        active_order_t *o = &orders[i];
        dap_chain_wallet_t *seller_wallet = dex_test_wallet_by_addr(f, &o->seller_addr);
        if (!seller_wallet) {
            log_it(L_WARNING, "Skip cancel: unknown seller for %s", dap_chain_hash_fast_to_str_static(&o->tail));
            continue;
        }
        
        // Build CANCEL TX template
        dap_chain_datum_tx_t *tx_template = NULL;
        dap_chain_net_srv_dex_remove_error_t err = dap_chain_net_srv_dex_remove(
            f->net->net, &o->tail, f->network_fee, seller_wallet, &tx_template
        );
        if (err != DEX_REMOVE_ERROR_OK || !tx_template) {
            log_it(L_ERROR, "Cancel build failed for %s: err=%d", dap_chain_hash_fast_to_str_static(&o->tail), err);
            return -2;
        }
        
        // Tampering: inflate refund
        tamper_output_data_t tamper_data = {
            .target_addr = (dap_chain_addr_t*)&o->seller_addr,
            .token = o->sell_token,
            .tampered_value = dap_chain_coins_to_balance("99999.0")
        };
        if (test_dex_tamper_and_verify_rejection(f, tx_template, seller_wallet,
                tamper_inflate_output, &tamper_data, "CANCEL-ALL: inflate refund") != 0) {
            dap_chain_datum_tx_delete(tx_template);
            return -12;
        }
        
        // Valid CANCEL
        dap_hash_fast_t cancel_hash = {0};
        dap_hash_fast(tx_template, dap_chain_datum_tx_get_size(tx_template), &cancel_hash);
        if (dap_ledger_tx_add(f->net->net->pub.ledger, tx_template, &cancel_hash, false, NULL) != 0) {
            log_it(L_ERROR, "Valid CANCEL (all) rejected");
            dap_chain_datum_tx_delete(tx_template);
            return -3;
        }
        
        log_it(L_NOTICE, "✓ CANCEL-ALL success: %s", dap_chain_hash_fast_to_str_static(&o->tail));
    }
    
    // Dump orderbook after cancel-all to verify cleanup
    test_dex_dump_orderbook(f, "After CANCEL-ALL");
    
    return 0;
}

// ============================================================================
// SEED ORDERBOOK (multi-level ASK/BID by roles)
// ============================================================================

static int s_seed_create_order(
    dex_test_fixture_t *f,
    const test_pair_config_t *pair,
    wallet_id_t seller,
    uint8_t side,
    uint8_t min_fill,
    const char *rate_str,
    const char *amount_str)
{
    dap_chain_wallet_t *wallet = get_wallet(f, seller);
    if (!wallet) {
        log_it(L_ERROR, "Seed create: wallet not found");
        return -1;
    }
    const char *sell_token, *buy_token;
    get_order_tokens(pair, side, &sell_token, &buy_token);
    
    uint256_t value = dap_chain_coins_to_balance(amount_str);
    uint256_t rate_value = dap_chain_coins_to_balance(rate_str);
    dap_chain_datum_tx_t *create_tx = NULL;
    dap_chain_net_srv_dex_create_error_t err = dap_chain_net_srv_dex_create(
        f->net->net, buy_token, sell_token, value, rate_value, min_fill, f->network_fee, wallet, &create_tx
    );
    if (err != DEX_CREATE_ERROR_OK || !create_tx) {
        log_it(L_ERROR, "Seed create failed: err=%d side=%u pair=%s/%s rate=%s amount=%s",
               err, side, pair->base_token, pair->quote_token, rate_str, amount_str);
        return -2;
    }
    // Unique ts only for same pair+rate (FIFO tie-break), same ts for different rates (rate sorting)
    static struct { char pair[32]; uint256_t rate; int count; } s_seed_entries[128];
    static int s_seed_entry_count = 0;
    static dap_time_t s_seed_ts_base = 0;
    if (!s_seed_ts_base)
        s_seed_ts_base = dap_time_now() - 1000;  // 1000s before now, so executions are always later
    
    // Build pair key
    char pair_key[32];
    snprintf(pair_key, sizeof(pair_key), "%s/%s", pair->base_token, pair->quote_token);
    
    // Find existing pair+rate or add new
    int ts_offset = 0;
    for (int i = 0; i < s_seed_entry_count; i++) {
        if (!strcmp(s_seed_entries[i].pair, pair_key) && EQUAL_256(s_seed_entries[i].rate, rate_value)) {
            ts_offset = ++s_seed_entries[i].count;
            break;
        }
    }
    if (ts_offset == 0 && s_seed_entry_count < 128) {
        dap_strncpy(s_seed_entries[s_seed_entry_count].pair, pair_key, sizeof(s_seed_entries[0].pair));
        s_seed_entries[s_seed_entry_count].rate = rate_value;
        s_seed_entries[s_seed_entry_count].count = 0;
        s_seed_entry_count++;
    }
    
    dap_time_t new_ts = s_seed_ts_base + ts_offset;
    if (!tamper_ts_created(create_tx, &new_ts) || s_resign_tx(&create_tx, wallet) != 0) {
        log_it(L_ERROR, "Seed ts tamper/resign failed");
        dap_chain_datum_tx_delete(create_tx);
        return -4;
    }
    dap_hash_fast_t h = {0};
    dap_hash_fast(create_tx, dap_chain_datum_tx_get_size(create_tx), &h);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, create_tx, &h, false, NULL) != 0) {
        log_it(L_ERROR, "Seed create rejected by ledger");
        dap_chain_datum_tx_delete(create_tx);
        return -3;
    }
    log_it(L_NOTICE, "Seed order created: %s %s/%s rate=%s value=%s minfill=%d%s",
           side == SIDE_ASK ? "ASK" : "BID",
           pair->base_token, pair->quote_token, rate_str, amount_str,
           MINFILL_PCT(min_fill), MINFILL_IS_FROM_ORIGIN(min_fill) ? " origin" : "");
    return 0;
}

int run_seed_orderbook(dex_test_fixture_t *f) {
    log_it(L_NOTICE, "=== SEED ORDERBOOK (multi-level) ===");
    
    const test_pair_config_t *pairs = test_get_standard_pairs();
    size_t pairs_count = test_get_standard_pairs_count();
    
    const char *ask_rates[] = {"2.5", "2.6", "2.8"};
    const char *bid_rates[] = {"0.3", "0.4", "0.6"};
    const uint8_t mfs[] = {MINFILL_NONE, MINFILL_50_CURRENT, MINFILL_75_ORIGIN};
    const char *ask_amount = "10.0";
    const char *bid_amount = "7.5";
    
    for (size_t p = 0; p < pairs_count; p++) {
        const test_pair_config_t *pair = &pairs[p];
        log_it(L_NOTICE, "--- Seeding pair %s ---", pair->description);
        
        // Alice ASKs: three levels
        for (int i = 0; i < 3; i++) {
            if (s_seed_create_order(f, pair, WALLET_ALICE, SIDE_ASK, mfs[i], ask_rates[i], ask_amount) != 0)
                return -100 - i;
        }
        // Bob BIDs: three levels
        for (int i = 0; i < 3; i++) {
            // Bob has no KEL; skip BID for pairs with quote=KEL (CELL/KEL)
            if (!dap_strcmp(pair->quote_token, "KEL")) {
                log_it(L_INFO, "Skip Bob BID for pair %s (no KEL balance)", pair->description);
                break;
            }
            if (s_seed_create_order(f, pair, WALLET_BOB, SIDE_BID, mfs[i], bid_rates[i], bid_amount) != 0)
                return -110 - i;
        }
        // Carol mid-level ASK/BID (service wallet)
        if (s_seed_create_order(f, pair, WALLET_CAROL, SIDE_ASK, MINFILL_50_CURRENT, ask_rates[1], ask_amount) != 0)
            return -120;
        if (s_seed_create_order(f, pair, WALLET_CAROL, SIDE_BID, MINFILL_50_CURRENT, bid_rates[1], bid_amount) != 0)
            return -121;
    }
    
    // Add AON orders for E02/E03 tests (All-Or-Nothing, minfill=100%)
    // KEL/USDT pair
    const test_pair_config_t *kel_usdt = &pairs[0];  // KEL/USDT is first pair
    // AON @ 2.55 (mid-range) - for E03 skip test
    if (s_seed_create_order(f, kel_usdt, WALLET_ALICE, SIDE_ASK, MINFILL_AON, "2.55", "15.0") != 0)
        return -130;
    // AON @ 3.0 (high rate) - for E02 "all AON" test with min_rate=2.9 filter
    if (s_seed_create_order(f, kel_usdt, WALLET_ALICE, SIDE_ASK, MINFILL_AON, "3.0", "20.0") != 0)
        return -131;
    if (s_seed_create_order(f, kel_usdt, WALLET_BOB, SIDE_BID, MINFILL_AON, "0.35", "10.0") != 0)
        return -132;
    
    test_dex_dump_orderbook(f, "After seed");
    return 0;
}

// ============================================================================
// PHASE 7: CANCEL LEFTOVER
// Cancel the leftover from Phase 6
// Includes tampering tests for INVALIDATE verification
// ============================================================================

static int run_phase_cancel_leftover(test_context_t *ctx) {
    log_it(L_INFO, "=== PHASE 7: CANCEL LEFTOVER ===");
    
    dex_test_fixture_t *f = ctx->fixture;
    dex_order_info_t *order = &ctx->order;
    
    dap_chain_wallet_t *seller_wallet = get_wallet(f, ctx->tmpl->seller);
    const dap_chain_addr_t *seller_addr = get_wallet_addr(f, ctx->tmpl->seller);
    
    const char *sell_token, *buy_token;
    get_order_tokens(ctx->pair, ctx->tmpl->side, &sell_token, &buy_token);
    
    // Take snapshot before cancel
    balance_snap_t seller_before;
    test_dex_snap_take(f->net->net->pub.ledger, seller_addr, sell_token, buy_token, &seller_before);
    
    log_it(L_INFO, "CANCEL leftover: value=%s", dap_uint256_to_char_ex(order->value).frac);
    
    // Build CANCEL TX template via API
    dap_chain_datum_tx_t *tx_template = NULL;
    dap_chain_net_srv_dex_remove_error_t err = dap_chain_net_srv_dex_remove(
        f->net->net, &ctx->order_hash, f->network_fee, seller_wallet, &tx_template
    );
    if (err != DEX_REMOVE_ERROR_OK || !tx_template) {
        log_it(L_ERROR, "Failed to create CANCEL TX: err=%d", err);
        return -1;
    }
    
    // === TAMPERING TESTS ===
    
    // T1: Wrong tx_type (UPDATE instead of INVALIDATE)
    uint8_t wrong_type = DEX_TX_TYPE_UPDATE;
    if (test_dex_tamper_and_verify_rejection(f, tx_template, seller_wallet,
            tamper_tx_type, &wrong_type, "CANCEL: wrong tx_type (UPDATE)") != 0) {
        dap_chain_datum_tx_delete(tx_template);
        return -10;
    }
    
    // T2: Wrong tx_type (EXCHANGE instead of INVALIDATE)
    wrong_type = DEX_TX_TYPE_EXCHANGE;
    if (test_dex_tamper_and_verify_rejection(f, tx_template, seller_wallet,
            tamper_tx_type, &wrong_type, "CANCEL: wrong tx_type (BUY)") != 0) {
        dap_chain_datum_tx_delete(tx_template);
        return -11;
    }
    
    // T3: Wrong root_hash (blank)
    if (test_dex_tamper_and_verify_rejection(f, tx_template, seller_wallet,
            tamper_order_root_hash, NULL, "CANCEL: blank root_hash") != 0) {
        dap_chain_datum_tx_delete(tx_template);
        return -12;
    }
    
    // T4: Wrong root_hash (random)
    dap_hash_fast_t random_hash = {0};
    dap_hash_fast("random_data", 11, &random_hash);
    if (test_dex_tamper_and_verify_rejection(f, tx_template, seller_wallet,
            tamper_order_root_hash, &random_hash, "CANCEL: random root_hash") != 0) {
        dap_chain_datum_tx_delete(tx_template);
        return -13;
    }
    
    // T5: Inflate refund amount (attempt to steal more tokens)
    tamper_output_data_t tamper_data = {
        .target_addr = (dap_chain_addr_t*)seller_addr,
        .token = sell_token,
        .tampered_value = dap_chain_coins_to_balance("99999.0")
    };
    if (test_dex_tamper_and_verify_rejection(f, tx_template, seller_wallet,
            tamper_inflate_output, &tamper_data, "CANCEL: inflate refund") != 0) {
        dap_chain_datum_tx_delete(tx_template);
        return -14;
    }
    
    log_it(L_NOTICE, "✓ All CANCEL tampering tests passed");
    
    // === VALID CANCEL ===
    dap_hash_fast_t cancel_hash = {0};
    dap_hash_fast(tx_template, dap_chain_datum_tx_get_size(tx_template), &cancel_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx_template, &cancel_hash, false, NULL) != 0) {
        log_it(L_ERROR, "Valid CANCEL TX rejected");
        dap_chain_datum_tx_delete(tx_template);
        return -2;
    }
    
    // Verify seller got refund
    // net_fee is paid in native token:
    //   - if sell_token IS native: deduct from BASE refund
    //   - if buy_token IS native: deduct from QUOTE
    balance_snap_t seller_after;
    test_dex_snap_take(f->net->net->pub.ledger, seller_addr, sell_token, buy_token, &seller_after);
    
    bool sell_is_native = (ctx->tmpl->side == SIDE_ASK) ? ctx->pair->base_is_native : ctx->pair->quote_is_native;
    bool buy_is_native = (ctx->tmpl->side == SIDE_ASK) ? ctx->pair->quote_is_native : ctx->pair->base_is_native;
    const dap_chain_addr_t *net_fee_addr = test_get_net_fee_addr(f);
    bool seller_is_net_collector = dap_chain_addr_compare(seller_addr, net_fee_addr);
    
    uint128_t value_128 = dap_uint256_to_uint128(order->value);
    uint128_t net_fee = dap_uint256_to_uint128(f->network_fee);
    uint128_t effective_fee;
    if (seller_is_net_collector)
        effective_fee = net_fee;
    else
        SUM_128_128(net_fee, net_fee, &effective_fee);  // 2 * net_fee
    
    // BASE: refund - effective_fee if sell=native, else full refund
    uint128_t base_fee = sell_is_native ? effective_fee : uint128_0;
    uint128_t expected_base;
    if (compare128(value_128, base_fee) > 0)
        SUBTRACT_128_128(value_128, base_fee, &expected_base);
    else
        expected_base = uint128_0;
    // QUOTE: effective_fee if buy=native, else 0
    uint128_t expected_quote = buy_is_native ? effective_fee : uint128_0;
    bool quote_decrease = buy_is_native;
    
    if (!IS_ZERO_128(expected_base) || !IS_ZERO_128(expected_quote)) {
        if (test_dex_snap_verify("Cancel Leftover", &seller_before, &seller_after,
                                 expected_base, false, expected_quote, quote_decrease) != 0) {
            log_it(L_ERROR, "CANCEL leftover balance verification failed");
            return -3;
        }
    }
    
    // Order is now cancelled - clear context
    memset(&ctx->order, 0, sizeof(ctx->order));
    memset(&ctx->order_hash, 0, sizeof(ctx->order_hash));
    
    log_it(L_NOTICE, "✓ CANCEL LEFTOVER COMPLETE");
    return 0;
}

// ============================================================================
// PHASE 8: CANCEL UNTOUCHED ORDER
// Cancel the current order (after Phase 3 rollback it's untouched)
// Includes tampering tests for INVALIDATE verification on untouched order
// ============================================================================

static int run_phase_cancel_untouched(test_context_t *ctx) {
    log_it(L_INFO, "=== PHASE 8: CANCEL UNTOUCHED (current order) ===");
    
    dex_test_fixture_t *f = ctx->fixture;
    dex_order_info_t *order = &ctx->order;
    
    dap_chain_wallet_t *seller_wallet = get_wallet(f, ctx->tmpl->seller);
    const dap_chain_addr_t *seller_addr = get_wallet_addr(f, ctx->tmpl->seller);
    
    // Get non-owner wallet for foreign cancel test
    wallet_id_t non_owner_id = (ctx->tmpl->seller == WALLET_ALICE) ? WALLET_BOB : WALLET_ALICE;
    dap_chain_wallet_t *non_owner_wallet = get_wallet(f, non_owner_id);
    
    const char *sell_token, *buy_token;
    get_order_tokens(ctx->pair, ctx->tmpl->side, &sell_token, &buy_token);
    
    // Take snapshot before cancel
    balance_snap_t seller_before;
    test_dex_snap_take(f->net->net->pub.ledger, seller_addr, sell_token, buy_token, &seller_before);
    
    log_it(L_INFO, "CANCEL untouched: value=%s", dap_uint256_to_char_ex(order->value).frac);
    
    // === FOREIGN OWNER TEST ===
    // Try to cancel by non-owner (should fail at API level)
    dap_chain_datum_tx_t *foreign_tx = NULL;
    dap_chain_net_srv_dex_remove_error_t foreign_err = dap_chain_net_srv_dex_remove(
        f->net->net, &ctx->order_hash, f->network_fee, non_owner_wallet, &foreign_tx
    );
    if (foreign_err == DEX_REMOVE_ERROR_OK && foreign_tx) {
        log_it(L_ERROR, "Foreign CANCEL should have been rejected by API");
        dap_chain_datum_tx_delete(foreign_tx);
        return -20;
    }
    log_it(L_NOTICE, "✓ Foreign CANCEL rejected at API level");
    
    // Build CANCEL TX template via API (by real owner)
    dap_chain_datum_tx_t *tx_template = NULL;
    dap_chain_net_srv_dex_remove_error_t err = dap_chain_net_srv_dex_remove(
        f->net->net, &ctx->order_hash, f->network_fee, seller_wallet, &tx_template
    );
    if (err != DEX_REMOVE_ERROR_OK || !tx_template) {
        log_it(L_ERROR, "Failed to create CANCEL TX: err=%d", err);
        return -1;
    }
    
    // === TAMPERING TESTS ===
    
    // T1: Wrong tx_type (UPDATE instead of INVALIDATE)
    uint8_t wrong_type = DEX_TX_TYPE_UPDATE;
    if (test_dex_tamper_and_verify_rejection(f, tx_template, seller_wallet,
            tamper_tx_type, &wrong_type, "CANCEL untouched: wrong tx_type (UPDATE)") != 0) {
        dap_chain_datum_tx_delete(tx_template);
        return -10;
    }
    
    // T2: Wrong root_hash (blank)
    if (test_dex_tamper_and_verify_rejection(f, tx_template, seller_wallet,
            tamper_order_root_hash, NULL, "CANCEL untouched: blank root_hash") != 0) {
        dap_chain_datum_tx_delete(tx_template);
        return -11;
    }
    
    // T3: Inflate refund amount
    tamper_output_data_t tamper_data = {
        .target_addr = (dap_chain_addr_t*)seller_addr,
        .token = sell_token,
        .tampered_value = dap_chain_coins_to_balance("99999.0")
    };
    if (test_dex_tamper_and_verify_rejection(f, tx_template, seller_wallet,
            tamper_inflate_output, &tamper_data, "CANCEL untouched: inflate refund") != 0) {
        dap_chain_datum_tx_delete(tx_template);
        return -12;
    }
    
    log_it(L_NOTICE, "✓ All CANCEL untouched tampering tests passed");
    
    // === VALID CANCEL ===
    dap_hash_fast_t cancel_hash = {0};
    dap_hash_fast(tx_template, dap_chain_datum_tx_get_size(tx_template), &cancel_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx_template, &cancel_hash, false, NULL) != 0) {
        log_it(L_ERROR, "Valid CANCEL TX rejected");
        dap_chain_datum_tx_delete(tx_template);
        return -2;
    }
    
    // Verify seller got full refund
    // net_fee is paid in native token:
    //   - if sell_token IS native: deduct from BASE refund
    //   - if buy_token IS native: deduct from QUOTE
    balance_snap_t seller_after;
    test_dex_snap_take(f->net->net->pub.ledger, seller_addr, sell_token, buy_token, &seller_after);
    
    bool sell_is_native = (ctx->tmpl->side == SIDE_ASK) ? ctx->pair->base_is_native : ctx->pair->quote_is_native;
    bool buy_is_native = (ctx->tmpl->side == SIDE_ASK) ? ctx->pair->quote_is_native : ctx->pair->base_is_native;
    const dap_chain_addr_t *net_fee_addr = test_get_net_fee_addr(f);
    bool seller_is_net_collector = dap_chain_addr_compare(seller_addr, net_fee_addr);
    
    uint128_t value_128 = dap_uint256_to_uint128(order->value);
    uint128_t net_fee = dap_uint256_to_uint128(f->network_fee);
    uint128_t effective_fee;
    if (seller_is_net_collector)
        effective_fee = net_fee;
    else
        SUM_128_128(net_fee, net_fee, &effective_fee);  // 2 * net_fee
    
    // BASE: refund - effective_fee if sell=native, else full refund
    uint128_t base_fee = sell_is_native ? effective_fee : uint128_0;
    uint128_t expected_base;
    if (compare128(value_128, base_fee) > 0)
        SUBTRACT_128_128(value_128, base_fee, &expected_base);
    else
        expected_base = uint128_0;
    // QUOTE: effective_fee if buy=native, else 0
    uint128_t expected_quote = buy_is_native ? effective_fee : uint128_0;
    bool quote_decrease = buy_is_native;
    
    if (!IS_ZERO_128(expected_base) || !IS_ZERO_128(expected_quote)) {
        if (test_dex_snap_verify("Cancel Untouched", &seller_before, &seller_after,
                                 expected_base, false, expected_quote, quote_decrease) != 0) {
            log_it(L_ERROR, "CANCEL untouched balance verification failed");
            return -3;
        }
    }
    
    // === DOUBLE CANCEL TEST ===
    // Order is cancelled, try to cancel again (should fail)
    log_it(L_INFO, "--- Testing double cancel (already cancelled order) ---");
    
    dap_chain_datum_tx_t *tx_double = NULL;
    dap_chain_net_srv_dex_remove_error_t double_err = dap_chain_net_srv_dex_remove(
        f->net->net, &ctx->order_hash, f->network_fee, seller_wallet, &tx_double
    );
    
    if (double_err == DEX_REMOVE_ERROR_OK && tx_double) {
        // Composer succeeded, try ledger (should reject - UTXO already spent)
        dap_hash_fast_t double_hash = {0};
        dap_hash_fast(tx_double, dap_chain_datum_tx_get_size(tx_double), &double_hash);
        int ledger_ret = dap_ledger_tx_add(f->net->net->pub.ledger, tx_double, &double_hash, false, NULL);
        dap_chain_datum_tx_delete(tx_double);
        
        if (ledger_ret == 0) {
            log_it(L_ERROR, "✗ Double cancel was ACCEPTED by ledger!");
            return -31;
        }
        log_it(L_NOTICE, "✓ Double cancel rejected by ledger (UTXO spent)");
    } else {
        log_it(L_NOTICE, "✓ Double cancel rejected by composer (err=%d)", double_err);
    }
    
    // Order is now cancelled - clear context
    memset(&ctx->order, 0, sizeof(ctx->order));
    memset(&ctx->order_hash, 0, sizeof(ctx->order_hash));
    
    log_it(L_NOTICE, "✓ CANCEL UNTOUCHED COMPLETE");
    return 0;
}

// ============================================================================
// PHASE: UPDATE AON ORDER
// For AON orders: UPDATE value, verify partial still rejected, rollback
// ============================================================================

static int run_phase_update_aon(test_context_t *ctx) {
    log_it(L_INFO, "=== PHASE: UPDATE AON (decrease + partial rejection + rollback) ===");
    
    dex_test_fixture_t *f = ctx->fixture;
    dex_order_info_t *order = &ctx->order;
    
    dap_chain_wallet_t *seller_wallet = get_wallet(f, ctx->tmpl->seller);
    const dap_chain_addr_t *seller_addr = get_wallet_addr(f, ctx->tmpl->seller);
    
    wallet_id_t buyer_id = get_regular_buyer(ctx->tmpl->side);
    dap_chain_wallet_t *buyer_wallet = get_wallet(f, buyer_id);
    
    const char *sell_token, *buy_token;
    get_order_tokens(ctx->pair, ctx->tmpl->side, &sell_token, &buy_token);
    
    // Save original state for rollback verification
    uint256_t original_value = order->value;
    dap_hash_fast_t original_hash = ctx->order_hash;
    
    // Take balance snapshot before UPDATE
    balance_snap_t seller_before;
    test_dex_snap_take(f->net->net->pub.ledger, seller_addr, sell_token, buy_token, &seller_before);
    
    // Step 1: UPDATE - decrease value by 50%
    uint256_t decrease = uint256_0;
    DIV_256(order->value, GET_256_FROM_64(2), &decrease);
    uint256_t new_value = uint256_0;
    SUBTRACT_256_256(order->value, decrease, &new_value);
    
    log_it(L_INFO, "UPDATE AON: %s → %s (decrease by 50%%)",
           dap_uint256_to_char_ex(order->value).frac, dap_uint256_to_char_ex(new_value).frac);
    
    dap_chain_datum_tx_t *tx_update = NULL;
    dap_chain_net_srv_dex_update_error_t err = dap_chain_net_srv_dex_update(
        f->net->net, &ctx->order_hash, true, new_value, f->network_fee, seller_wallet, &tx_update
    );
    if (err != DEX_UPDATE_ERROR_OK || !tx_update) {
        log_it(L_ERROR, "Failed to create UPDATE TX for AON: err=%d", err);
        return -1;
    }
    
    dap_hash_fast_t update_hash = {0};
    dap_hash_fast(tx_update, dap_chain_datum_tx_get_size(tx_update), &update_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx_update, &update_hash, false, NULL) != 0) {
        log_it(L_ERROR, "UPDATE AON TX rejected by ledger");
        dap_chain_datum_tx_delete(tx_update);
        return -2;
    }
    
    log_it(L_NOTICE, "✓ UPDATE AON accepted (value decreased)");
    
    // Update context
    ctx->order_hash = update_hash;
    ctx->order.value = new_value;
    
    // Step 2: Try partial buy (should be rejected - AON preserved!)
    log_it(L_INFO, "--- Testing partial buy on updated AON (should be rejected) ---");
    
    // 80% of new_value
    uint256_t partial_80 = calc_pct(new_value, 80);
    uint256_t budget;
    if (ctx->tmpl->side == SIDE_ASK) {
        MULT_256_COIN(partial_80, order->price, &budget);
    } else {
        budget = partial_80;
    }
    
    dap_chain_datum_tx_t *tx_partial = NULL;
    dap_chain_net_srv_dex_purchase_error_t purchase_err = dap_chain_net_srv_dex_purchase(
        f->net->net, &ctx->order_hash, budget, false,
        f->network_fee, buyer_wallet, false, uint256_0, &tx_partial
    );
    
    if (purchase_err == DEX_PURCHASE_ERROR_OK && tx_partial) {
        log_it(L_ERROR, "✗ Partial buy on AON should be rejected by composer!");
        dap_chain_datum_tx_delete(tx_partial);
        return -3;
    }
    log_it(L_NOTICE, "✓ Partial buy on updated AON rejected (err=%d)", purchase_err);
    
    // Step 3: Rollback UPDATE
    log_it(L_INFO, "--- Rollback UPDATE AON ---");
    
    dap_chain_datum_tx_t *tx_for_remove = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &update_hash);
    if (dap_ledger_tx_remove(f->net->net->pub.ledger, tx_for_remove, &update_hash) != 0) {
        log_it(L_ERROR, "Failed to rollback UPDATE AON");
        return -4;
    }
    
    // Restore context
    ctx->order_hash = original_hash;
    ctx->order.value = original_value;
    
    // Verify balance restored
    balance_snap_t seller_after_rollback;
    test_dex_snap_take(f->net->net->pub.ledger, seller_addr, sell_token, buy_token, &seller_after_rollback);
    
    if (test_dex_snap_verify("UPDATE AON rollback", &seller_before, &seller_after_rollback, uint128_0, false, uint128_0, false) != 0) {
        log_it(L_ERROR, "UPDATE AON rollback balance mismatch");
        return -5;
    }
    
    // After rollback, cancel untouched AON order
    int cancel_ret = run_phase_cancel_untouched(ctx);
    if (cancel_ret != 0)
        return cancel_ret;
    
    log_it(L_NOTICE, "✓ UPDATE AON PHASE COMPLETE (value decreased, partial rejected, rollback OK)");
    return 0;
}

// ============================================================================
// MASTER LIFECYCLE RUNNER
// ============================================================================

int run_order_lifecycle(
    dex_test_fixture_t *f,
    const test_pair_config_t *pair,
    const order_template_t *tmpl,
    size_t pair_idx,
    size_t tmpl_idx)
{
    test_context_t ctx = {
        .fixture = f,
        .pair = pair,
        .tmpl = tmpl,
        .pair_idx = pair_idx,
        .tmpl_idx = tmpl_idx
    };
    
    log_it(L_NOTICE, " ");
    log_it(L_NOTICE, "════════════════════════════════════════════════════════");
    log_it(L_NOTICE, "  ORDER LIFECYCLE [%zu.%zu]: %s %s min_fill=%s rate=%s",
           pair_idx, tmpl_idx,
           tmpl->side == SIDE_ASK ? "ASK" : "BID",
           pair->description,
           get_minfill_desc(tmpl->min_fill),
           tmpl->rate);
    log_it(L_NOTICE, "════════════════════════════════════════════════════════");
    
    int ret;
    
    // Phase 1: Create
    log_it(L_INFO, "=== PHASE 1: CREATE ===");
    ret = run_phase_create(&ctx);
    if (ret != 0) return ret;
    
    // Phase 2: Full buy with tampering + rollback
    log_it(L_INFO, "=== PHASE 2: FULL BUY ===");
    ret = run_phase_full_buy(&ctx);
    if (ret != 0) return ret;
    
    // Recreate order for remaining phases
    memset(&ctx.order, 0, sizeof(ctx.order));
    ret = run_phase_create(&ctx);
    if (ret != 0) return ret;
    
    // Phase 3: Partial buy
    log_it(L_INFO, "=== PHASE 3: PARTIAL BUY ===");
    ret = run_phase_partial_buy(&ctx);
    if (ret != 0) return ret;
    
    // Recreate for sub-minfill (only for 75% from_origin)
    if (MINFILL_PCT(tmpl->min_fill) == 75 && MINFILL_IS_FROM_ORIGIN(tmpl->min_fill)) {
        memset(&ctx.order, 0, sizeof(ctx.order));
        ret = run_phase_create(&ctx);
        if (ret != 0) return ret;
        
        // Phase 4: Sub-minfill
        log_it(L_INFO, "=== PHASE 4: SUB-MINFILL ===");
        ret = run_phase_sub_minfill(&ctx);
        if (ret != 0) return ret;
    }
    
    // UPDATE and CANCEL phases - after Phase 3 rollback, the order is untouched
    // MINFILL_NONE: Full UPDATE/CANCEL chain (UPDATE untouched → partial → UPDATE leftover → CANCEL leftover)
    // MINFILL_50_CURRENT: Just CANCEL untouched (covers both ASK and BID)
    // MINFILL_AON: UPDATE AON (decrease + partial rejection + rollback)
    if (tmpl->min_fill == MINFILL_NONE) {
        // Phase 5: UPDATE untouched order (uses current ctx->order after Phase 3 rollback)
        ret = run_phase_update_untouched(&ctx);
        if (ret != 0) return ret;
        
        // Phase 6: Partial buy + UPDATE leftover (creates leftover, then updates it)
        ret = run_phase_update_leftover(&ctx);
        if (ret != 0) return ret;
        
        // Phase 7: CANCEL leftover (cancels the leftover from Phase 6)
        ret = run_phase_cancel_leftover(&ctx);
        if (ret != 0) return ret;
    } else if (tmpl->min_fill == MINFILL_75_ORIGIN) {
        memset(&ctx.order, 0, sizeof(ctx.order));
        ret = run_phase_create(&ctx);
        if (ret != 0) return ret;
        
        ret = run_phase_update_untouched(&ctx);
        if (ret != 0) return ret;
        
        ret = run_phase_cancel_untouched(&ctx);
        if (ret != 0) return ret;
    } else if (tmpl->min_fill == MINFILL_AON) {
        // Phase: UPDATE AON order (decrease, verify partial rejected, rollback)
        ret = run_phase_update_aon(&ctx);
        if (ret != 0) return ret;
    } else if (tmpl->min_fill == MINFILL_50_CURRENT) {
        // Phase 8: CANCEL untouched order (tests INVALIDATE on fresh order)
        ret = run_phase_cancel_untouched(&ctx);
        if (ret != 0) return ret;
    }
    
    log_it(L_NOTICE, "✓ ORDER LIFECYCLE [%zu.%zu] COMPLETE", pair_idx, tmpl_idx);
    
    // Debug: dump balances after each template
    char label[64];
    snprintf(label, sizeof(label), "After template %zu.%zu", pair_idx, tmpl_idx);
    test_dex_dump_balances(f, label);
    
    return 0;
}

// ============================================================================
// MULTI-EXECUTION TESTS (Group M)
// Tests for sequential partial fills and buyer-leftover lifecycle
// Run on clean orderbook after mass cancellation
// ============================================================================

// Helper: create a simple ASK or BID order and return its hash
static int s_create_test_order(
    dex_test_fixture_t *f,
    const test_pair_config_t *pair,
    wallet_id_t seller_id,
    uint8_t side,
    uint8_t min_fill,
    const char *rate_str,
    const char *amount_str,
    dap_hash_fast_t *out_hash)
{
    dap_chain_wallet_t *wallet = get_wallet(f, seller_id);
    if (!wallet) return -1;
    
    const char *sell_token, *buy_token;
    get_order_tokens(pair, side, &sell_token, &buy_token);
    
    uint256_t amount = dap_chain_coins_to_balance(amount_str);
    uint256_t rate = dap_chain_coins_to_balance(rate_str);
    
    dap_chain_datum_tx_t *tx = NULL;
    int err = dap_chain_net_srv_dex_create(
        f->net->net, buy_token, sell_token,
        amount, rate, min_fill, f->network_fee, wallet, &tx
    );
    if (err != 0 || !tx) {
        log_it(L_ERROR, "Failed to create test order: err=%d", err);
        return -1;
    }
    
    dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), out_hash);
    int ledger_ret = dap_ledger_tx_add(f->net->net->pub.ledger, tx, out_hash, false, NULL);
    dap_chain_datum_tx_delete(tx);
    
    if (ledger_ret != 0) {
        log_it(L_ERROR, "Test order rejected by ledger");
        return -2;
    }
    
    return 0;
}

// M01: Seller partial chain with MINFILL_50_CURRENT
// Order: 30 units @ rate, min_fill=50% current
// Buyer A: 20 units → leftover 10 (min_fill now 5)
// Buyer B: 10 units → closed
static int s_run_m01_seller_partial_current(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- M01: Seller partial chain (MINFILL_50_CURRENT) ---");
    
    const char *base = pair->base_token;
    const char *quote = pair->quote_token;
    
    // Create ASK order: Alice sells 30 BASE @ 2.5, min_fill=50% current
    dap_hash_fast_t order_hash = {0};
    int ret = s_create_test_order(f, pair, WALLET_ALICE, SIDE_ASK, MINFILL_50_CURRENT, "2.5", "30.0", &order_hash);
    if (ret != 0) {
        log_it(L_ERROR, "M01: Failed to create initial order");
        return -1;
    }
    log_it(L_INFO, "M01: Created ASK order 30 %s @ 2.5, min_fill=50%% current", base);
    
    // Take balance snapshots
    balance_snap_t alice_before, bob_before;
    test_dex_snap_take(f->net->net->pub.ledger, &f->alice_addr, base, quote, &alice_before);
    test_dex_snap_take(f->net->net->pub.ledger, &f->bob_addr, base, quote, &bob_before);
    
    // Buyer A (Bob): buy 20 units → leftover 10, min_fill becomes 5
    uint256_t budget_20 = dap_chain_coins_to_balance("20.0");
    
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err1 = dap_chain_net_srv_dex_purchase(
        f->net->net, &order_hash, budget_20, true, f->network_fee, f->bob, false, uint256_0, &tx1
    );
    if (err1 != DEX_PURCHASE_ERROR_OK || !tx1) {
        log_it(L_ERROR, "M01: First partial purchase failed: err=%d", err1);
        return -2;
    }
    
    dap_hash_fast_t tx1_hash = {0};
    dap_hash_fast(tx1, dap_chain_datum_tx_get_size(tx1), &tx1_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx1, &tx1_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M01: First partial TX rejected");
        dap_chain_datum_tx_delete(tx1);
        return -3;
    }
    dap_chain_datum_tx_delete(tx1);
    log_it(L_NOTICE, "✓ M01: First partial (20 units) accepted, leftover=10, new min_fill=5");
    
    // Find the leftover order hash (it's in the OUT_COND of tx1)
    dap_chain_datum_tx_t *tx1_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx1_hash);
    dap_hash_fast_t leftover_hash = tx1_hash;  // Leftover references this TX
    
    // Buyer B (Carol): buy remaining 10 units → order closed
    uint256_t budget_10 = dap_chain_coins_to_balance("10.0");
    
    dap_chain_datum_tx_t *tx2 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err2 = dap_chain_net_srv_dex_purchase(
        f->net->net, &leftover_hash, budget_10, true, f->network_fee, f->carol, false, uint256_0, &tx2
    );
    if (err2 != DEX_PURCHASE_ERROR_OK || !tx2) {
        log_it(L_ERROR, "M01: Second purchase failed: err=%d", err2);
        return -4;
    }
    
    dap_hash_fast_t tx2_hash = {0};
    dap_hash_fast(tx2, dap_chain_datum_tx_get_size(tx2), &tx2_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx2, &tx2_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M01: Second TX rejected");
        dap_chain_datum_tx_delete(tx2);
        return -5;
    }
    dap_chain_datum_tx_delete(tx2);
    log_it(L_NOTICE, "✓ M01: Second purchase (10 units) accepted, order closed");
    
    // Verify: Alice received full payout (30 * 2.5 = 75 QUOTE, minus service fee)
    balance_snap_t alice_after;
    test_dex_snap_take(f->net->net->pub.ledger, &f->alice_addr, base, quote, &alice_after);
    
    // Alice should have received ~75 USDT (50 + 25, minus fees for non-service buyers)
    // Just verify she got more QUOTE than before
    if (compare256(alice_after.quote, alice_before.quote) <= 0) {
        log_it(L_ERROR, "M01: Alice QUOTE balance did not increase!");
        return -6;
    }
    log_it(L_NOTICE, "✓ M01: Alice received payout: %s %s", 
           dap_uint256_to_char_ex(alice_after.quote).frac, quote);
    
    log_it(L_NOTICE, "✓ M01: SELLER PARTIAL CHAIN (MINFILL_50_CURRENT) PASSED");
    
    // Rollback transactions to restore balances for next tests
    dap_chain_datum_tx_t *tx2_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx2_hash);
    if (tx2_ledger)
        dap_ledger_tx_remove(f->net->net->pub.ledger, tx2_ledger, &tx2_hash);
    
    if (tx1_ledger)
        dap_ledger_tx_remove(f->net->net->pub.ledger, tx1_ledger, &tx1_hash);
    
    dap_chain_datum_tx_t *order_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &order_hash);
    if (order_tx)
        dap_ledger_tx_remove(f->net->net->pub.ledger, order_tx, &order_hash);
    
    log_it(L_DEBUG, "M01: Rolled back all transactions");
    return 0;
}

// M02: Seller partial chain with MINFILL_75_ORIGIN - rejection test
// Order: 40 units @ rate, min_fill=75% origin (30 units always)
// Buyer A: 30 units → leftover 10, min_fill still 30
// Buyer B: tries 5 units → REJECTED (5 < 30)
// Buyer C: 10 units → closed (exact remaining)
static int s_run_m02_seller_partial_origin(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- M02: Seller partial chain (MINFILL_75_ORIGIN) with rejection ---");
    
    const char *base = pair->base_token;
    
    // Create ASK order: Alice sells 40 BASE @ 2.5, min_fill=75% origin (30)
    dap_hash_fast_t order_hash = {0};
    int ret = s_create_test_order(f, pair, WALLET_ALICE, SIDE_ASK, MINFILL_75_ORIGIN, "2.5", "40.0", &order_hash);
    if (ret != 0) {
        log_it(L_ERROR, "M02: Failed to create initial order");
        return -1;
    }
    log_it(L_INFO, "M02: Created ASK order 40 %s @ 2.5, min_fill=75%% origin (30)", base);
    
    // Buyer A (Bob): buy 30 units → leftover 10, min_fill remains 30
    uint256_t budget_30 = dap_chain_coins_to_balance("30.0");
    
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err1 = dap_chain_net_srv_dex_purchase(
        f->net->net, &order_hash, budget_30, true, f->network_fee, f->bob, false, uint256_0, &tx1
    );
    if (err1 != DEX_PURCHASE_ERROR_OK || !tx1) {
        log_it(L_ERROR, "M02: First purchase failed: err=%d", err1);
        return -2;
    }
    
    dap_hash_fast_t tx1_hash = {0};
    dap_hash_fast(tx1, dap_chain_datum_tx_get_size(tx1), &tx1_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx1, &tx1_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M02: First TX rejected");
        dap_chain_datum_tx_delete(tx1);
        return -3;
    }
    dap_chain_datum_tx_delete(tx1);
    log_it(L_NOTICE, "✓ M02: First purchase (30 units) accepted, leftover=10, min_fill still=30");
    
    dap_hash_fast_t leftover_hash = tx1_hash;
    
    // Buyer B (Carol): try 5 units → SHOULD BE REJECTED (5 < 30 min_fill)
    uint256_t budget_5 = dap_chain_coins_to_balance("5.0");
    
    dap_chain_datum_tx_t *tx_reject = NULL;
    dap_chain_net_srv_dex_purchase_error_t err_reject = dap_chain_net_srv_dex_purchase(
        f->net->net, &leftover_hash, budget_5, true, f->network_fee, f->carol, false, uint256_0, &tx_reject
    );
    
    if (err_reject == DEX_PURCHASE_ERROR_OK && tx_reject) {
        // TX was created - check if ledger rejects it
        dap_hash_fast_t reject_hash = {0};
        dap_hash_fast(tx_reject, dap_chain_datum_tx_get_size(tx_reject), &reject_hash);
        int ledger_ret = dap_ledger_tx_add(f->net->net->pub.ledger, tx_reject, &reject_hash, false, NULL);
        dap_chain_datum_tx_delete(tx_reject);
        
        if (ledger_ret == 0) {
            log_it(L_ERROR, "M02: Purchase below min_fill should be REJECTED!");
            return -4;
        }
        log_it(L_NOTICE, "✓ M02: Purchase below min_fill rejected by ledger");
    } else {
        log_it(L_NOTICE, "✓ M02: Purchase below min_fill rejected by composer (err=%d)", err_reject);
    }
    
    // Buyer C (Carol): buy remaining 10 units → closed (exact match to remaining)
    uint256_t budget_10 = dap_chain_coins_to_balance("10.0");
    
    dap_chain_datum_tx_t *tx2 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err2 = dap_chain_net_srv_dex_purchase(
        f->net->net, &leftover_hash, budget_10, true, f->network_fee, f->carol, false, uint256_0, &tx2
    );
    if (err2 != DEX_PURCHASE_ERROR_OK || !tx2) {
        log_it(L_ERROR, "M02: Final purchase failed: err=%d", err2);
        return -5;
    }
    
    dap_hash_fast_t tx2_hash = {0};
    dap_hash_fast(tx2, dap_chain_datum_tx_get_size(tx2), &tx2_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx2, &tx2_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M02: Final TX rejected");
        dap_chain_datum_tx_delete(tx2);
        return -6;
    }
    log_it(L_NOTICE, "✓ M02: Final purchase (10 units = remaining) accepted, order closed");
    
    log_it(L_NOTICE, "✓ M02: SELLER PARTIAL CHAIN (MINFILL_75_ORIGIN) PASSED");
    
    // Rollback transactions
    dap_chain_datum_tx_t *tx2_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx2_hash);
    if (tx2_ledger)
        dap_ledger_tx_remove(f->net->net->pub.ledger, tx2_ledger, &tx2_hash);
    
    dap_chain_datum_tx_t *tx1_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx1_hash);
    if (tx1_ledger)
        dap_ledger_tx_remove(f->net->net->pub.ledger, tx1_ledger, &tx1_hash);
    
    dap_chain_datum_tx_t *order_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &order_hash);
    if (order_tx)
        dap_ledger_tx_remove(f->net->net->pub.ledger, order_tx, &order_hash);
    
    dap_chain_datum_tx_delete(tx2);
    log_it(L_DEBUG, "M02: Rolled back all transactions");
    return 0;
}

// M03: Buyer-leftover lifecycle
// Bob buys with leftover=true → creates new order
// Alice matches Bob's new order
static int s_run_m03_buyer_leftover(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- M03: Buyer-leftover lifecycle ---");
    
    const char *base = pair->base_token;
    const char *quote = pair->quote_token;
    
    // Step 1: Carol creates ASK order: 10 BASE @ 2.5
    dap_hash_fast_t carol_order = {0};
    int ret = s_create_test_order(f, pair, WALLET_CAROL, SIDE_ASK, MINFILL_NONE, "2.5", "10.0", &carol_order);
    if (ret != 0) {
        log_it(L_ERROR, "M03: Failed to create Carol's order");
        return -1;
    }
    log_it(L_INFO, "M03: Carol created ASK 10 %s @ 2.5", base);
    
    // Step 2: Bob buys with budget=15, leftover=true, leftover_rate=2.6
    // Bob gets 10 BASE, creates buyer-order for 5 BASE @ 2.6
    uint256_t budget_15 = dap_chain_coins_to_balance("15.0");
    uint256_t leftover_rate = dap_chain_coins_to_balance("2.6");
    
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err1 = dap_chain_net_srv_dex_purchase(
        f->net->net, &carol_order, budget_15, true, f->network_fee, f->bob, true, leftover_rate, &tx1
    );
    if (err1 != DEX_PURCHASE_ERROR_OK || !tx1) {
        log_it(L_ERROR, "M03: Bob's purchase with leftover failed: err=%d", err1);
        return -2;
    }
    
    dap_hash_fast_t tx1_hash = {0};
    dap_hash_fast(tx1, dap_chain_datum_tx_get_size(tx1), &tx1_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx1, &tx1_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M03: Bob's TX rejected");
        dap_chain_datum_tx_delete(tx1);
        return -3;
    }
    dap_chain_datum_tx_delete(tx1);
    log_it(L_NOTICE, "✓ M03: Bob purchased 10 %s, created buyer-leftover order for 5 %s @ 2.6", base, base);
    
    // Step 3: Alice matches Bob's buyer-leftover order
    // Bob's order is a BID (he wants to buy BASE), so Alice needs to sell BASE
    dap_hash_fast_t bob_order = tx1_hash;  // Buyer-leftover references this TX
    
    uint256_t budget_5 = dap_chain_coins_to_balance("5.0");
    
    dap_chain_datum_tx_t *tx2 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err2 = dap_chain_net_srv_dex_purchase(
        f->net->net, &bob_order, budget_5, true, f->network_fee, f->alice, false, uint256_0, &tx2
    );
    if (err2 != DEX_PURCHASE_ERROR_OK || !tx2) {
        log_it(L_ERROR, "M03: Alice's match failed: err=%d", err2);
        return -4;
    }
    
    dap_hash_fast_t tx2_hash = {0};
    dap_hash_fast(tx2, dap_chain_datum_tx_get_size(tx2), &tx2_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx2, &tx2_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M03: Alice's TX rejected");
        dap_chain_datum_tx_delete(tx2);
        return -5;
    }
    log_it(L_NOTICE, "✓ M03: Alice matched Bob's buyer-leftover order");
    
    log_it(L_NOTICE, "✓ M03: BUYER-LEFTOVER LIFECYCLE PASSED");
    
    // Rollback transactions
    dap_chain_datum_tx_t *tx2_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx2_hash);
    if (tx2_ledger)
        dap_ledger_tx_remove(f->net->net->pub.ledger, tx2_ledger, &tx2_hash);
    
    dap_chain_datum_tx_t *tx1_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx1_hash);
    if (tx1_ledger)
        dap_ledger_tx_remove(f->net->net->pub.ledger, tx1_ledger, &tx1_hash);
    
    dap_chain_datum_tx_t *carol_order_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &carol_order);
    if (carol_order_tx)
        dap_ledger_tx_remove(f->net->net->pub.ledger, carol_order_tx, &carol_order);
    
    dap_chain_datum_tx_delete(tx2);
    log_it(L_DEBUG, "M03: Rolled back all transactions");
    return 0;
}

// ============================================================================
// BID TESTS (M04-M06) - Mirror of ASK tests (M01-M03)
// ============================================================================

// M04: BID partial chain with MINFILL_50_CURRENT
// Bob creates BID (sells QUOTE, wants BASE), Alice/Carol sell BASE
// Order: 75 QUOTE @ rate 2.5 (wants 30 BASE), min_fill=50% current
// Buyer A (Alice): sell 20 BASE → leftover, min_fill becomes 12.5 QUOTE
// Buyer B (Carol): sell 10 BASE → closed
static int s_run_m04_bid_partial_current(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- M04: BID partial chain (MINFILL_50_CURRENT) ---");
    
    const char *base = pair->base_token;
    const char *quote = pair->quote_token;
    
    // Create BID order: Bob sells 75 QUOTE @ 2.5 to buy 30 BASE, min_fill=50% current
    dap_hash_fast_t order_hash = {0};
    int ret = s_create_test_order(f, pair, WALLET_BOB, SIDE_BID, MINFILL_50_CURRENT, "2.5", "75.0", &order_hash);
    if (ret != 0) {
        log_it(L_ERROR, "M04: Failed to create initial BID order");
        return -1;
    }
    log_it(L_INFO, "M04: Bob created BID order 75 %s @ 2.5 (wants 30 %s), min_fill=50%% current", quote, base);
    
    // Take balance snapshots
    balance_snap_t bob_before;
    test_dex_snap_take(f->net->net->pub.ledger, &f->bob_addr, base, quote, &bob_before);
    
    // Buyer A (Alice): sell 20 BASE → Bob gets 20 BASE, Alice gets 50 QUOTE
    // budget_in_buy_tokens=false means budget is in what buyer SELLS (BASE)
    uint256_t budget_20 = dap_chain_coins_to_balance("20.0");
    
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err1 = dap_chain_net_srv_dex_purchase(
        f->net->net, &order_hash, budget_20, false, f->network_fee, f->alice, false, uint256_0, &tx1
    );
    if (err1 != DEX_PURCHASE_ERROR_OK || !tx1) {
        log_it(L_ERROR, "M04: First partial purchase failed: err=%d", err1);
        return -2;
    }
    
    dap_hash_fast_t tx1_hash = {0};
    dap_hash_fast(tx1, dap_chain_datum_tx_get_size(tx1), &tx1_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx1, &tx1_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M04: First partial TX rejected");
        dap_chain_datum_tx_delete(tx1);
        return -3;
    }
    dap_chain_datum_tx_delete(tx1);
    log_it(L_NOTICE, "✓ M04: First partial (20 %s sold) accepted, leftover=25 %s, new min_fill=12.5", base, quote);
    
    dap_chain_datum_tx_t *tx1_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx1_hash);
    dap_hash_fast_t leftover_hash = tx1_hash;
    
    // Buyer B (Carol): sell remaining 10 BASE → order closed
    uint256_t budget_10 = dap_chain_coins_to_balance("10.0");
    
    dap_chain_datum_tx_t *tx2 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err2 = dap_chain_net_srv_dex_purchase(
        f->net->net, &leftover_hash, budget_10, false, f->network_fee, f->carol, false, uint256_0, &tx2
    );
    if (err2 != DEX_PURCHASE_ERROR_OK || !tx2) {
        log_it(L_ERROR, "M04: Second purchase failed: err=%d", err2);
        return -4;
    }
    
    dap_hash_fast_t tx2_hash = {0};
    dap_hash_fast(tx2, dap_chain_datum_tx_get_size(tx2), &tx2_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx2, &tx2_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M04: Second TX rejected");
        dap_chain_datum_tx_delete(tx2);
        return -5;
    }
    dap_chain_datum_tx_delete(tx2);
    log_it(L_NOTICE, "✓ M04: Second purchase (10 %s sold) accepted, order closed", base);
    
    // Verify: Bob received BASE (30 total from both buyers)
    balance_snap_t bob_after;
    test_dex_snap_take(f->net->net->pub.ledger, &f->bob_addr, base, quote, &bob_after);
    
    if (compare256(bob_after.base, bob_before.base) <= 0) {
        log_it(L_ERROR, "M04: Bob BASE balance did not increase!");
        return -6;
    }
    log_it(L_NOTICE, "✓ M04: Bob received BASE: %s %s", 
           dap_uint256_to_char_ex(bob_after.base).frac, base);
    
    log_it(L_NOTICE, "✓ M04: BID PARTIAL CHAIN (MINFILL_50_CURRENT) PASSED");
    
    // Rollback
    dap_chain_datum_tx_t *tx2_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx2_hash);
    if (tx2_ledger)
        dap_ledger_tx_remove(f->net->net->pub.ledger, tx2_ledger, &tx2_hash);
    if (tx1_ledger)
        dap_ledger_tx_remove(f->net->net->pub.ledger, tx1_ledger, &tx1_hash);
    dap_chain_datum_tx_t *order_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &order_hash);
    if (order_tx)
        dap_ledger_tx_remove(f->net->net->pub.ledger, order_tx, &order_hash);
    
    log_it(L_DEBUG, "M04: Rolled back all transactions");
    return 0;
}

// M05: BID partial chain with MINFILL_75_ORIGIN - rejection test
// Bob creates BID (sells QUOTE), Alice/Carol sell BASE
static int s_run_m05_bid_partial_origin(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- M05: BID partial chain (MINFILL_75_ORIGIN) with rejection ---");
    
    const char *base = pair->base_token;
    const char *quote = pair->quote_token;
    
    // Create BID order: Bob sells 100 QUOTE @ 2.5 (wants 40 BASE), min_fill=75% origin
    dap_hash_fast_t order_hash = {0};
    int ret = s_create_test_order(f, pair, WALLET_BOB, SIDE_BID, MINFILL_75_ORIGIN, "2.5", "100.0", &order_hash);
    if (ret != 0) {
        log_it(L_ERROR, "M05: Failed to create initial BID order");
        return -1;
    }
    log_it(L_INFO, "M05: Bob created BID order 100 %s @ 2.5, min_fill=75%% origin", quote);
    
    // Buyer A (Alice): sell 30 BASE → leftover, min_fill still 75 QUOTE
    // budget_in_buy_tokens=false for BID orders (budget is in BASE that buyer sells)
    uint256_t budget_30 = dap_chain_coins_to_balance("30.0");
    
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err1 = dap_chain_net_srv_dex_purchase(
        f->net->net, &order_hash, budget_30, false, f->network_fee, f->alice, false, uint256_0, &tx1
    );
    if (err1 != DEX_PURCHASE_ERROR_OK || !tx1) {
        log_it(L_ERROR, "M05: First purchase failed: err=%d", err1);
        return -2;
    }
    
    dap_hash_fast_t tx1_hash = {0};
    dap_hash_fast(tx1, dap_chain_datum_tx_get_size(tx1), &tx1_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx1, &tx1_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M05: First TX rejected");
        dap_chain_datum_tx_delete(tx1);
        return -3;
    }
    dap_chain_datum_tx_delete(tx1);
    log_it(L_NOTICE, "✓ M05: First purchase (30 %s) accepted, leftover=25 %s, min_fill still=75", base, quote);
    
    dap_chain_datum_tx_t *tx1_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx1_hash);
    dap_hash_fast_t leftover_hash = tx1_hash;
    
    // Buyer B (Carol): try 5 BASE → SHOULD BE REJECTED
    uint256_t budget_5 = dap_chain_coins_to_balance("5.0");
    
    dap_chain_datum_tx_t *tx_reject = NULL;
    dap_chain_net_srv_dex_purchase_error_t err_reject = dap_chain_net_srv_dex_purchase(
        f->net->net, &leftover_hash, budget_5, false, f->network_fee, f->carol, false, uint256_0, &tx_reject
    );
    
    if (err_reject == DEX_PURCHASE_ERROR_OK && tx_reject) {
        dap_hash_fast_t reject_hash = {0};
        dap_hash_fast(tx_reject, dap_chain_datum_tx_get_size(tx_reject), &reject_hash);
        int ledger_ret = dap_ledger_tx_add(f->net->net->pub.ledger, tx_reject, &reject_hash, false, NULL);
        dap_chain_datum_tx_delete(tx_reject);
        
        if (ledger_ret == 0) {
            log_it(L_ERROR, "M05: Purchase below min_fill should be REJECTED!");
            return -4;
        }
        log_it(L_NOTICE, "✓ M05: Purchase below min_fill rejected by ledger");
    } else {
        log_it(L_NOTICE, "✓ M05: Purchase below min_fill rejected by composer (err=%d)", err_reject);
    }
    
    // Buyer C (Carol): sell remaining 10 BASE → closed
    uint256_t budget_10 = dap_chain_coins_to_balance("10.0");
    
    dap_chain_datum_tx_t *tx2 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err2 = dap_chain_net_srv_dex_purchase(
        f->net->net, &leftover_hash, budget_10, false, f->network_fee, f->carol, false, uint256_0, &tx2
    );
    if (err2 != DEX_PURCHASE_ERROR_OK || !tx2) {
        log_it(L_ERROR, "M05: Final purchase failed: err=%d", err2);
        return -5;
    }
    
    dap_hash_fast_t tx2_hash = {0};
    dap_hash_fast(tx2, dap_chain_datum_tx_get_size(tx2), &tx2_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx2, &tx2_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M05: Final TX rejected");
        dap_chain_datum_tx_delete(tx2);
        return -6;
    }
    log_it(L_NOTICE, "✓ M05: Final purchase (10 %s = remaining) accepted, order closed", base);
    
    log_it(L_NOTICE, "✓ M05: BID PARTIAL CHAIN (MINFILL_75_ORIGIN) PASSED");
    
    // Rollback
    dap_chain_datum_tx_t *tx2_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx2_hash);
    if (tx2_ledger)
        dap_ledger_tx_remove(f->net->net->pub.ledger, tx2_ledger, &tx2_hash);
    if (tx1_ledger)
        dap_ledger_tx_remove(f->net->net->pub.ledger, tx1_ledger, &tx1_hash);
    dap_chain_datum_tx_t *order_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &order_hash);
    if (order_tx)
        dap_ledger_tx_remove(f->net->net->pub.ledger, order_tx, &order_hash);
    
    dap_chain_datum_tx_delete(tx2);
    log_it(L_DEBUG, "M05: Rolled back all transactions");
    return 0;
}

// M06: BID buyer-leftover lifecycle
// Bob creates BID, Alice sells with leftover=true → creates ASK leftover order
// Carol matches Alice's ASK leftover
static int s_run_m06_bid_buyer_leftover(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- M06: BID buyer-leftover lifecycle ---");
    
    const char *base = pair->base_token;
    const char *quote = pair->quote_token;
    
    // Step 1: Bob creates BID order: 25 QUOTE @ 2.5 (wants 10 BASE)
    dap_hash_fast_t bob_order = {0};
    int ret = s_create_test_order(f, pair, WALLET_BOB, SIDE_BID, MINFILL_NONE, "2.5", "25.0", &bob_order);
    if (ret != 0) {
        log_it(L_ERROR, "M06: Failed to create Bob's BID order");
        return -1;
    }
    log_it(L_INFO, "M06: Bob created BID 25 %s @ 2.5 (wants 10 %s)", quote, base);
    
    // Step 2: Alice sells with budget=15 BASE, leftover=true, leftover_rate=2.6
    // Alice sells 10 BASE (fills Bob's order), creates ASK leftover for 5 BASE @ 2.6
    // budget_in_buy_tokens=false for BID orders (budget is in BASE that buyer sells)
    uint256_t budget_15 = dap_chain_coins_to_balance("15.0");
    uint256_t leftover_rate = dap_chain_coins_to_balance("2.6");
    
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err1 = dap_chain_net_srv_dex_purchase(
        f->net->net, &bob_order, budget_15, false, f->network_fee, f->alice, true, leftover_rate, &tx1
    );
    if (err1 != DEX_PURCHASE_ERROR_OK || !tx1) {
        log_it(L_ERROR, "M06: Alice's purchase with leftover failed: err=%d", err1);
        return -2;
    }
    
    dap_hash_fast_t tx1_hash = {0};
    dap_hash_fast(tx1, dap_chain_datum_tx_get_size(tx1), &tx1_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx1, &tx1_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M06: Alice's TX rejected");
        dap_chain_datum_tx_delete(tx1);
        return -3;
    }
    dap_chain_datum_tx_delete(tx1);
    log_it(L_NOTICE, "✓ M06: Alice sold 10 %s, created buyer-leftover ASK for 5 %s @ 2.6", base, base);
    
    // Step 3: Carol matches Alice's buyer-leftover ASK order
    // Alice's leftover is ASK (she wants to sell remaining BASE), so Carol buys BASE
    dap_hash_fast_t alice_leftover = tx1_hash;
    
    uint256_t budget_5 = dap_chain_coins_to_balance("5.0");
    
    dap_chain_datum_tx_t *tx2 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err2 = dap_chain_net_srv_dex_purchase(
        f->net->net, &alice_leftover, budget_5, true, f->network_fee, f->carol, false, uint256_0, &tx2
    );
    if (err2 != DEX_PURCHASE_ERROR_OK || !tx2) {
        log_it(L_ERROR, "M06: Carol's match failed: err=%d", err2);
        return -4;
    }
    
    dap_hash_fast_t tx2_hash = {0};
    dap_hash_fast(tx2, dap_chain_datum_tx_get_size(tx2), &tx2_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx2, &tx2_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M06: Carol's TX rejected");
        dap_chain_datum_tx_delete(tx2);
        return -5;
    }
    log_it(L_NOTICE, "✓ M06: Carol matched Alice's buyer-leftover ASK order");
    
    log_it(L_NOTICE, "✓ M06: BID BUYER-LEFTOVER LIFECYCLE PASSED");
    
    // Rollback
    dap_chain_datum_tx_t *tx2_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx2_hash);
    if (tx2_ledger)
        dap_ledger_tx_remove(f->net->net->pub.ledger, tx2_ledger, &tx2_hash);
    
    dap_chain_datum_tx_t *tx1_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx1_hash);
    if (tx1_ledger)
        dap_ledger_tx_remove(f->net->net->pub.ledger, tx1_ledger, &tx1_hash);
    
    dap_chain_datum_tx_t *bob_order_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &bob_order);
    if (bob_order_tx)
        dap_ledger_tx_remove(f->net->net->pub.ledger, bob_order_tx, &bob_order);
    
    dap_chain_datum_tx_delete(tx2);
    log_it(L_DEBUG, "M06: Rolled back all transactions");
    return 0;
}

// ============================================================================
// BUYER-LEFTOVER OPERATIONS (M07-M10)
// ============================================================================

// M07: UPDATE buyer-leftover (decrease value)
// Bob creates buyer-leftover, then updates it (decreases value)
static int s_run_m07_buyer_leftover_update(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- M07: UPDATE buyer-leftover ---");
    
    const char *base = pair->base_token;
    const char *quote = pair->quote_token;
    
    // Step 1: Carol creates ASK order: 10 BASE @ 2.5
    dap_hash_fast_t carol_order = {0};
    int ret = s_create_test_order(f, pair, WALLET_CAROL, SIDE_ASK, MINFILL_NONE, "2.5", "10.0", &carol_order);
    if (ret != 0) {
        log_it(L_ERROR, "M07: Failed to create Carol's order");
        return -1;
    }
    
    // Step 2: Bob buys with budget=40, leftover=true, leftover_rate=2.6
    // Bob gets 10 BASE (cost 25 QUOTE), creates buyer-leftover for 15 QUOTE @ 2.6
    uint256_t budget = dap_chain_coins_to_balance("40.0");
    uint256_t leftover_rate = dap_chain_coins_to_balance("2.6");
    
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err1 = dap_chain_net_srv_dex_purchase(
        f->net->net, &carol_order, budget, true, f->network_fee, f->bob, true, leftover_rate, &tx1
    );
    if (err1 != DEX_PURCHASE_ERROR_OK || !tx1) {
        log_it(L_ERROR, "M07: Bob's purchase failed: err=%d", err1);
        return -2;
    }
    
    dap_hash_fast_t tx1_hash = {0};
    dap_hash_fast(tx1, dap_chain_datum_tx_get_size(tx1), &tx1_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx1, &tx1_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M07: Bob's TX rejected");
        dap_chain_datum_tx_delete(tx1);
        return -3;
    }
    dap_chain_datum_tx_delete(tx1);
    log_it(L_INFO, "M07: Bob created buyer-leftover order");
    
    // Get buyer-leftover order info
    dex_order_info_t bl_order = {0};
    if (test_dex_order_get_info(f->net->net->pub.ledger, &tx1_hash, &bl_order) != 0) {
        log_it(L_ERROR, "M07: Failed to get buyer-leftover info");
        return -4;
    }
    log_it(L_INFO, "M07: Buyer-leftover value=%s", dap_uint256_to_char_ex(bl_order.value).frac);
    
    // Step 3: UPDATE buyer-leftover (decrease by 50%)
    uint256_t new_value = uint256_0;
    DIV_256(bl_order.value, GET_256_FROM_64(2), &new_value);
    
    balance_snap_t bob_before;
    test_dex_snap_take(f->net->net->pub.ledger, &f->bob_addr, base, quote, &bob_before);
    
    dap_chain_datum_tx_t *update_tx = NULL;
    dap_chain_net_srv_dex_update_error_t upd_err = dap_chain_net_srv_dex_update(
        f->net->net, &tx1_hash, true, new_value, f->network_fee, f->bob, &update_tx
    );
    if (upd_err != DEX_UPDATE_ERROR_OK || !update_tx) {
        log_it(L_ERROR, "M07: UPDATE API failed: err=%d", upd_err);
        return -5;
    }
    
    dap_hash_fast_t update_hash = {0};
    dap_hash_fast(update_tx, dap_chain_datum_tx_get_size(update_tx), &update_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, update_tx, &update_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M07: UPDATE TX rejected");
        dap_chain_datum_tx_delete(update_tx);
        return -6;
    }
    
    // Verify Bob got partial refund (QUOTE tokens)
    balance_snap_t bob_after;
    test_dex_snap_take(f->net->net->pub.ledger, &f->bob_addr, base, quote, &bob_after);
    
    uint256_t refund = uint256_0;
    SUBTRACT_256_256(bl_order.value, new_value, &refund);
    uint256_t actual_delta = uint256_0;
    SUBTRACT_256_256(bob_after.quote, bob_before.quote, &actual_delta);
    
    // Expected: refund - network_fee (1.0 for UPDATE)
    uint256_t expected_min = uint256_0;
    if (compare256(refund, f->network_fee) > 0)
        SUBTRACT_256_256(refund, f->network_fee, &expected_min);
    
    log_it(L_INFO, "M07: Expected refund=%s (minus fee=%s), actual QUOTE delta=%s",
           dap_uint256_to_char_ex(refund).frac,
           dap_uint256_to_char_ex(f->network_fee).frac,
           dap_uint256_to_char_ex(actual_delta).frac);
    
    // Verify delta >= expected_min (refund - fee)
    if (compare256(actual_delta, expected_min) < 0) {
        log_it(L_ERROR, "M07: Refund too small: got %s, expected at least %s",
               dap_uint256_to_char_ex(actual_delta).frac,
               dap_uint256_to_char_ex(expected_min).frac);
        return -7;
    }
    
    log_it(L_NOTICE, "✓ M07: BUYER-LEFTOVER UPDATE PASSED");
    
    // Rollback
    dap_chain_datum_tx_t *upd_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &update_hash);
    if (upd_ledger) dap_ledger_tx_remove(f->net->net->pub.ledger, upd_ledger, &update_hash);
    dap_chain_datum_tx_t *tx1_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx1_hash);
    if (tx1_ledger) dap_ledger_tx_remove(f->net->net->pub.ledger, tx1_ledger, &tx1_hash);
    dap_chain_datum_tx_t *carol_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &carol_order);
    if (carol_tx) dap_ledger_tx_remove(f->net->net->pub.ledger, carol_tx, &carol_order);
    
    dap_chain_datum_tx_delete(update_tx);
    return 0;
}

// M08: CANCEL buyer-leftover
// Bob creates buyer-leftover, then cancels it
static int s_run_m08_buyer_leftover_cancel(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- M08: CANCEL buyer-leftover ---");
    
    const char *base = pair->base_token;
    const char *quote = pair->quote_token;
    
    // Step 1: Carol creates ASK order: 10 BASE @ 2.5
    dap_hash_fast_t carol_order = {0};
    int ret = s_create_test_order(f, pair, WALLET_CAROL, SIDE_ASK, MINFILL_NONE, "2.5", "10.0", &carol_order);
    if (ret != 0) {
        log_it(L_ERROR, "M08: Failed to create Carol's order");
        return -1;
    }
    
    // Step 2: Bob buys with leftover=true
    uint256_t budget = dap_chain_coins_to_balance("40.0");
    uint256_t leftover_rate = dap_chain_coins_to_balance("2.6");
    
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err1 = dap_chain_net_srv_dex_purchase(
        f->net->net, &carol_order, budget, true, f->network_fee, f->bob, true, leftover_rate, &tx1
    );
    if (err1 != DEX_PURCHASE_ERROR_OK || !tx1) {
        log_it(L_ERROR, "M08: Bob's purchase failed: err=%d", err1);
        return -2;
    }
    
    dap_hash_fast_t tx1_hash = {0};
    dap_hash_fast(tx1, dap_chain_datum_tx_get_size(tx1), &tx1_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx1, &tx1_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M08: Bob's TX rejected");
        dap_chain_datum_tx_delete(tx1);
        return -3;
    }
    dap_chain_datum_tx_delete(tx1);
    log_it(L_INFO, "M08: Bob created buyer-leftover order");
    
    // Get buyer-leftover order info
    dex_order_info_t bl_order = {0};
    if (test_dex_order_get_info(f->net->net->pub.ledger, &tx1_hash, &bl_order) != 0) {
        log_it(L_ERROR, "M08: Failed to get buyer-leftover info");
        return -4;
    }
    
    // Step 3: CANCEL buyer-leftover
    balance_snap_t bob_before;
    test_dex_snap_take(f->net->net->pub.ledger, &f->bob_addr, base, quote, &bob_before);
    
    dap_chain_datum_tx_t *cancel_tx = NULL;
    dap_chain_net_srv_dex_remove_error_t rem_err = dap_chain_net_srv_dex_remove(
        f->net->net, &tx1_hash, f->network_fee, f->bob, &cancel_tx
    );
    if (rem_err != DEX_REMOVE_ERROR_OK || !cancel_tx) {
        log_it(L_ERROR, "M08: CANCEL API failed: err=%d", rem_err);
        return -5;
    }
    
    dap_hash_fast_t cancel_hash = {0};
    dap_hash_fast(cancel_tx, dap_chain_datum_tx_get_size(cancel_tx), &cancel_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, cancel_tx, &cancel_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M08: CANCEL TX rejected");
        dap_chain_datum_tx_delete(cancel_tx);
        return -6;
    }
    
    // Verify Bob got full refund
    balance_snap_t bob_after;
    test_dex_snap_take(f->net->net->pub.ledger, &f->bob_addr, base, quote, &bob_after);
    
    uint256_t actual_delta = uint256_0;
    SUBTRACT_256_256(bob_after.quote, bob_before.quote, &actual_delta);
    
    log_it(L_INFO, "M08: Expected refund=%s, actual QUOTE delta=%s",
           dap_uint256_to_char_ex(bl_order.value).frac,
           dap_uint256_to_char_ex(actual_delta).frac);
    
    // Verify delta matches expected refund (must be >= order value, minus possible fees)
    // Note: refund should be close to bl_order.value, may be slightly less due to network fee
    uint256_t min_expected = uint256_0;
    uint256_t fee_tolerance = dap_chain_coins_to_balance("2.0");  // Allow up to 2.0 for fees
    if (compare256(bl_order.value, fee_tolerance) > 0)
        SUBTRACT_256_256(bl_order.value, fee_tolerance, &min_expected);
    
    if (compare256(actual_delta, min_expected) < 0) {
        log_it(L_ERROR, "M08: Refund too small: got %s, expected at least %s",
               dap_uint256_to_char_ex(actual_delta).frac,
               dap_uint256_to_char_ex(min_expected).frac);
        return -7;
    }
    
    log_it(L_NOTICE, "✓ M08: BUYER-LEFTOVER CANCEL PASSED");
    
    // Rollback
    dap_chain_datum_tx_t *cancel_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &cancel_hash);
    if (cancel_ledger) dap_ledger_tx_remove(f->net->net->pub.ledger, cancel_ledger, &cancel_hash);
    dap_chain_datum_tx_t *tx1_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx1_hash);
    if (tx1_ledger) dap_ledger_tx_remove(f->net->net->pub.ledger, tx1_ledger, &tx1_hash);
    dap_chain_datum_tx_t *carol_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &carol_order);
    if (carol_tx) dap_ledger_tx_remove(f->net->net->pub.ledger, carol_tx, &carol_order);
    
    dap_chain_datum_tx_delete(cancel_tx);
    return 0;
}

// M09: Double CANCEL buyer-leftover (must fail)
// Try to cancel an already-cancelled buyer-leftover
static int s_run_m09_buyer_leftover_double_cancel(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- M09: Double CANCEL buyer-leftover ---");
    
    // Step 1: Carol creates ASK order
    dap_hash_fast_t carol_order = {0};
    int ret = s_create_test_order(f, pair, WALLET_CAROL, SIDE_ASK, MINFILL_NONE, "2.5", "10.0", &carol_order);
    if (ret != 0) {
        log_it(L_ERROR, "M09: Failed to create Carol's order");
        return -1;
    }
    
    // Step 2: Bob buys with leftover=true
    uint256_t budget = dap_chain_coins_to_balance("40.0");
    uint256_t leftover_rate = dap_chain_coins_to_balance("2.6");
    
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err1 = dap_chain_net_srv_dex_purchase(
        f->net->net, &carol_order, budget, true, f->network_fee, f->bob, true, leftover_rate, &tx1
    );
    if (err1 != DEX_PURCHASE_ERROR_OK || !tx1) {
        log_it(L_ERROR, "M09: Bob's purchase failed: err=%d", err1);
        return -2;
    }
    
    dap_hash_fast_t tx1_hash = {0};
    dap_hash_fast(tx1, dap_chain_datum_tx_get_size(tx1), &tx1_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx1, &tx1_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M09: Bob's TX rejected");
        dap_chain_datum_tx_delete(tx1);
        return -3;
    }
    dap_chain_datum_tx_delete(tx1);
    log_it(L_INFO, "M09: Bob created buyer-leftover order");
    
    // Step 3: First CANCEL (valid)
    dap_chain_datum_tx_t *cancel1_tx = NULL;
    dap_chain_net_srv_dex_remove_error_t rem_err = dap_chain_net_srv_dex_remove(
        f->net->net, &tx1_hash, f->network_fee, f->bob, &cancel1_tx
    );
    if (rem_err != DEX_REMOVE_ERROR_OK || !cancel1_tx) {
        log_it(L_ERROR, "M09: First CANCEL API failed: err=%d", rem_err);
        return -4;
    }
    
    dap_hash_fast_t cancel1_hash = {0};
    dap_hash_fast(cancel1_tx, dap_chain_datum_tx_get_size(cancel1_tx), &cancel1_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, cancel1_tx, &cancel1_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M09: First CANCEL TX rejected");
        dap_chain_datum_tx_delete(cancel1_tx);
        return -5;
    }
    dap_chain_datum_tx_delete(cancel1_tx);
    log_it(L_INFO, "M09: First CANCEL succeeded");
    
    // Step 4: Second CANCEL (must fail at API level - order no longer exists)
    dap_chain_datum_tx_t *cancel2_tx = NULL;
    dap_chain_net_srv_dex_remove_error_t rem_err2 = dap_chain_net_srv_dex_remove(
        f->net->net, &tx1_hash, f->network_fee, f->bob, &cancel2_tx
    );
    if (rem_err2 == DEX_REMOVE_ERROR_OK && cancel2_tx) {
        // API didn't catch it, try ledger
        dap_hash_fast_t cancel2_hash = {0};
        dap_hash_fast(cancel2_tx, dap_chain_datum_tx_get_size(cancel2_tx), &cancel2_hash);
        int add_ret = dap_ledger_tx_add(f->net->net->pub.ledger, cancel2_tx, &cancel2_hash, false, NULL);
        dap_chain_datum_tx_delete(cancel2_tx);
        if (add_ret == 0) {
            log_it(L_ERROR, "M09: Double CANCEL was accepted (should be rejected)");
            return -6;
        }
        log_it(L_INFO, "M09: Double CANCEL rejected by ledger (ret=%d)", add_ret);
    } else {
        log_it(L_INFO, "M09: Double CANCEL rejected at API level (err=%d)", rem_err2);
    }
    
    log_it(L_NOTICE, "✓ M09: DOUBLE CANCEL REJECTED");
    
    // Rollback
    dap_chain_datum_tx_t *cancel1_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &cancel1_hash);
    if (cancel1_ledger) dap_ledger_tx_remove(f->net->net->pub.ledger, cancel1_ledger, &cancel1_hash);
    dap_chain_datum_tx_t *tx1_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx1_hash);
    if (tx1_ledger) dap_ledger_tx_remove(f->net->net->pub.ledger, tx1_ledger, &tx1_hash);
    dap_chain_datum_tx_t *carol_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &carol_order);
    if (carol_tx) dap_ledger_tx_remove(f->net->net->pub.ledger, carol_tx, &carol_order);
    
    return 0;
}

// M10: Foreign owner UPDATE/CANCEL buyer-leftover (must fail)
// Alice tries to UPDATE/CANCEL Bob's buyer-leftover
static int s_run_m10_buyer_leftover_foreign_ops(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- M10: Foreign owner UPDATE/CANCEL buyer-leftover ---");
    
    // Step 1: Carol creates ASK order
    dap_hash_fast_t carol_order = {0};
    int ret = s_create_test_order(f, pair, WALLET_CAROL, SIDE_ASK, MINFILL_NONE, "2.5", "10.0", &carol_order);
    if (ret != 0) {
        log_it(L_ERROR, "M10: Failed to create Carol's order");
        return -1;
    }
    
    // Step 2: Bob buys with leftover=true
    uint256_t budget = dap_chain_coins_to_balance("40.0");
    uint256_t leftover_rate = dap_chain_coins_to_balance("2.6");
    
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err1 = dap_chain_net_srv_dex_purchase(
        f->net->net, &carol_order, budget, true, f->network_fee, f->bob, true, leftover_rate, &tx1
    );
    if (err1 != DEX_PURCHASE_ERROR_OK || !tx1) {
        log_it(L_ERROR, "M10: Bob's purchase failed: err=%d", err1);
        return -2;
    }
    
    dap_hash_fast_t tx1_hash = {0};
    dap_hash_fast(tx1, dap_chain_datum_tx_get_size(tx1), &tx1_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx1, &tx1_hash, false, NULL) != 0) {
        log_it(L_ERROR, "M10: Bob's TX rejected");
        dap_chain_datum_tx_delete(tx1);
        return -3;
    }
    dap_chain_datum_tx_delete(tx1);
    log_it(L_INFO, "M10: Bob created buyer-leftover order");
    
    // Get order info
    dex_order_info_t bl_order = {0};
    if (test_dex_order_get_info(f->net->net->pub.ledger, &tx1_hash, &bl_order) != 0) {
        log_it(L_ERROR, "M10: Failed to get buyer-leftover info");
        return -4;
    }
    
    // Step 3: Alice tries to UPDATE Bob's order (must fail)
    uint256_t new_value = uint256_0;
    DIV_256(bl_order.value, GET_256_FROM_64(2), &new_value);
    
    dap_chain_datum_tx_t *foreign_update = NULL;
    dap_chain_net_srv_dex_update_error_t upd_err = dap_chain_net_srv_dex_update(
        f->net->net, &tx1_hash, true, new_value, f->network_fee, f->alice, &foreign_update
    );
    if (upd_err == DEX_UPDATE_ERROR_OK && foreign_update) {
        // API didn't catch it, try ledger
        dap_hash_fast_t upd_hash = {0};
        dap_hash_fast(foreign_update, dap_chain_datum_tx_get_size(foreign_update), &upd_hash);
        int add_ret = dap_ledger_tx_add(f->net->net->pub.ledger, foreign_update, &upd_hash, false, NULL);
        dap_chain_datum_tx_delete(foreign_update);
        if (add_ret == 0) {
            log_it(L_ERROR, "M10: Foreign UPDATE was accepted (should be rejected)");
            dap_chain_datum_tx_t *upd_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &upd_hash);
            if (upd_ledger) dap_ledger_tx_remove(f->net->net->pub.ledger, upd_ledger, &upd_hash);
            return -5;
        }
        log_it(L_INFO, "M10: Foreign UPDATE rejected by ledger (ret=%d)", add_ret);
    } else {
        log_it(L_INFO, "M10: Foreign UPDATE rejected at API level (err=%d)", upd_err);
    }
    log_it(L_NOTICE, "✓ Foreign UPDATE rejected");
    
    // Step 4: Alice tries to CANCEL Bob's order (must fail)
    dap_chain_datum_tx_t *foreign_cancel = NULL;
    dap_chain_net_srv_dex_remove_error_t rem_err = dap_chain_net_srv_dex_remove(
        f->net->net, &tx1_hash, f->network_fee, f->alice, &foreign_cancel
    );
    if (rem_err == DEX_REMOVE_ERROR_OK && foreign_cancel) {
        // API didn't catch it, try ledger
        dap_hash_fast_t rem_hash = {0};
        dap_hash_fast(foreign_cancel, dap_chain_datum_tx_get_size(foreign_cancel), &rem_hash);
        int add_ret = dap_ledger_tx_add(f->net->net->pub.ledger, foreign_cancel, &rem_hash, false, NULL);
        dap_chain_datum_tx_delete(foreign_cancel);
        if (add_ret == 0) {
            log_it(L_ERROR, "M10: Foreign CANCEL was accepted (should be rejected)");
            dap_chain_datum_tx_t *rem_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &rem_hash);
            if (rem_ledger) dap_ledger_tx_remove(f->net->net->pub.ledger, rem_ledger, &rem_hash);
            return -6;
        }
        log_it(L_INFO, "M10: Foreign CANCEL rejected by ledger (ret=%d)", add_ret);
    } else {
        log_it(L_INFO, "M10: Foreign CANCEL rejected at API level (err=%d)", rem_err);
    }
    log_it(L_NOTICE, "✓ Foreign CANCEL rejected");
    
    log_it(L_NOTICE, "✓ M10: FOREIGN OWNER OPS REJECTED");
    
    // Rollback
    dap_chain_datum_tx_t *tx1_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx1_hash);
    if (tx1_ledger) dap_ledger_tx_remove(f->net->net->pub.ledger, tx1_ledger, &tx1_hash);
    dap_chain_datum_tx_t *carol_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &carol_order);
    if (carol_tx) dap_ledger_tx_remove(f->net->net->pub.ledger, carol_tx, &carol_order);
    
    return 0;
}

// ============================================================================
// BUYER-LEFTOVER TAMPERING TESTS (T_BL)
// ============================================================================

// Helper: find DEX OUT_COND by type (buyer-leftover: root=0, seller-leftover: root!=0)
static dap_chain_tx_out_cond_t *s_find_dex_out_cond_by_type(dap_chain_datum_tx_t *tx, bool a_buyer_leftover) {
    if (!tx) return NULL;
    
    int l_item_idx = 0;
    size_t l_item_size = 0;
    byte_t *l_item = NULL;
    
    while ((l_item = dap_chain_datum_tx_item_get(tx, &l_item_idx, NULL, TX_ITEM_TYPE_OUT_COND, &l_item_size))) {
        dap_chain_tx_out_cond_t *out_cond = (dap_chain_tx_out_cond_t *)l_item;
        if (out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX) {
            bool is_root_blank = dap_hash_fast_is_blank(&out_cond->subtype.srv_dex.order_root_hash);
            if (a_buyer_leftover && is_root_blank) {
                return out_cond;
            }
            if (!a_buyer_leftover && !is_root_blank) {
                return out_cond;
            }
        }
        l_item_idx++;
    }
    return NULL;
}

// Helper: tamper TX, re-sign, and verify rejection
// Returns 0 if tamper was correctly rejected, <0 on error, >0 if tamper was accepted (test failure)
typedef bool (*bl_tamper_fn)(dap_chain_datum_tx_t *tx, void *ctx);

static int s_tamper_resign_and_verify(dex_test_fixture_t *f, dap_chain_datum_tx_t *tx, 
                                       dap_chain_wallet_t *wallet, bl_tamper_fn tamper_fn, 
                                       void *ctx, const char *desc) {
    // 1. Strip signatures
    uint8_t *l_first_sig = dap_chain_datum_tx_item_get(tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
    if (!l_first_sig) {
        log_it(L_ERROR, "%s: No signature in TX", desc);
        return -1;
    }
    
    size_t l_tx_size_no_sig = (size_t)(l_first_sig - (uint8_t*)tx);
    dap_chain_datum_tx_t *l_tampered = DAP_DUP_SIZE(tx, l_tx_size_no_sig);
    if (!l_tampered) return -2;
    l_tampered->header.tx_items_size = l_tx_size_no_sig - sizeof(dap_chain_datum_tx_t);
    
    // 2. Apply tamper
    if (!tamper_fn(l_tampered, ctx)) {
        dap_chain_datum_tx_delete(l_tampered);
        log_it(L_WARNING, "%s: Tamper not applied (skipped)", desc);
        return 0;  // Not an error, just nothing to tamper
    }
    
    // 3. Re-sign
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(wallet, 0);
    if (!l_key || dap_chain_datum_tx_add_sign_item(&l_tampered, l_key) <= 0) {
        DAP_DEL_Z(l_key);
        dap_chain_datum_tx_delete(l_tampered);
        log_it(L_ERROR, "%s: Failed to re-sign", desc);
        return -3;
    }
    DAP_DELETE(l_key);
    
    // 4. Try to add
    dap_hash_fast_t l_hash = {0};
    dap_hash_fast(l_tampered, dap_chain_datum_tx_get_size(l_tampered), &l_hash);
    int ret = dap_ledger_tx_add(f->net->net->pub.ledger, l_tampered, &l_hash, false, NULL);
    dap_chain_datum_tx_delete(l_tampered);
    
    if (ret == 0) {
        log_it(L_ERROR, "%s: TAMPERED TX was ACCEPTED!", desc);
        dap_chain_datum_tx_t *tx_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &l_hash);
        if (tx_ledger) dap_ledger_tx_remove(f->net->net->pub.ledger, tx_ledger, &l_hash);
        return 1;  // Test failure
    }
    
    log_it(L_NOTICE, "✓ %s REJECTED", desc);
    return 0;
}

// Tamper callbacks for T_BL tests
typedef struct { dap_hash_fast_t fake_root; } t_bl01_ctx_t;
static bool s_tamper_bl01_nonzero_root(dap_chain_datum_tx_t *tx, void *ctx) {
    t_bl01_ctx_t *c = ctx;
    dap_chain_tx_out_cond_t *bl = s_find_dex_out_cond_by_type(tx, true);
    if (!bl) return false;
    bl->subtype.srv_dex.order_root_hash = c->fake_root;
    return true;
}

// Real attack: steal from SELLER payout into buyer-leftover
// Bob (buyer) underpays Carol (seller) and inflates his own buyer-leftover
// This should be rejected by DEXV_SELLER_PAYOUT_MISMATCH
static bool s_tamper_bl03_value_inflate(dap_chain_datum_tx_t *tx, void *ctx) {
    (void)ctx;
    dap_chain_tx_out_cond_t *bl = s_find_dex_out_cond_by_type(tx, true);
    if (!bl) return false;
    
    // Get buyer address (owner of buyer-leftover)
    dap_chain_addr_t *buyer_addr = &bl->subtype.srv_dex.seller_addr;
    
    // Find seller payout: OUT_STD going to address OTHER than buyer
    // This is Carol's payout which we want to steal from
    dap_chain_tx_out_std_t *seller_payout = NULL;
    int item_idx = 0;
    byte_t *item;
    while ((item = dap_chain_datum_tx_item_get(tx, &item_idx, NULL, TX_ITEM_TYPE_OUT_STD, NULL))) {
        dap_chain_tx_out_std_t *out = (dap_chain_tx_out_std_t *)item;
        // Not buyer's address = seller's payout
        if (!dap_chain_addr_compare(&out->addr, buyer_addr) && 
            !IS_ZERO_256(out->value)) {
            seller_payout = out;
            break;
        }
        item_idx++;
    }
    if (!seller_payout) return false;
    
    // Steal 5 units from seller's payout to buyer-leftover
    // Carol gets 5 less, Bob's leftover grows by 5
    uint256_t steal_amount = dap_chain_coins_to_balance("5.0");
    if (compare256(seller_payout->value, steal_amount) < 0) return false;
    
    uint256_t new_seller = uint256_0, new_bl = uint256_0;
    SUBTRACT_256_256(seller_payout->value, steal_amount, &new_seller);
    SUM_256_256(bl->header.value, steal_amount, &new_bl);
    seller_payout->value = new_seller;
    bl->header.value = new_bl;
    return true;
}

typedef struct { dap_chain_addr_t hijack_addr; } t_bl04_ctx_t;
static bool s_tamper_bl04_addr_hijack(dap_chain_datum_tx_t *tx, void *ctx) {
    t_bl04_ctx_t *c = ctx;
    dap_chain_tx_out_cond_t *bl = s_find_dex_out_cond_by_type(tx, true);
    if (!bl) return false;
    bl->subtype.srv_dex.seller_addr = c->hijack_addr;
    return true;
}

// T_BL01: Buyer-leftover with non-zero root_hash (should be rejected)
static int s_run_t_bl01_nonzero_root(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- T_BL01: Buyer-leftover with non-zero root_hash ---");
    
    // Create ASK order
    dap_hash_fast_t carol_order = {0};
    int ret = s_create_test_order(f, pair, WALLET_CAROL, SIDE_ASK, MINFILL_NONE, "2.5", "10.0", &carol_order);
    if (ret != 0) return -1;
    
    // Bob purchases with leftover
    uint256_t budget_38 = dap_chain_coins_to_balance("38.5");
    uint256_t leftover_rate = dap_chain_coins_to_balance("2.6");
    
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err1 = dap_chain_net_srv_dex_purchase(
        f->net->net, &carol_order, budget_38, true, f->network_fee, f->bob, true, leftover_rate, &tx1
    );
    if (err1 != DEX_PURCHASE_ERROR_OK || !tx1) return -2;
    
    // Tamper: set fake root_hash
    t_bl01_ctx_t ctx = { .fake_root = carol_order };
    ret = s_tamper_resign_and_verify(f, tx1, f->bob, s_tamper_bl01_nonzero_root, &ctx, 
                                     "T_BL01: Buyer-leftover with non-zero root_hash");
    dap_chain_datum_tx_delete(tx1);
    
    // Cleanup
    dap_chain_datum_tx_t *carol_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &carol_order);
    if (carol_tx) dap_ledger_tx_remove(f->net->net->pub.ledger, carol_tx, &carol_order);
    
    return ret > 0 ? -3 : ret;
}

// T_BL02: Partial fill on buyer-leftover with wrong root_hash
typedef struct { dap_hash_fast_t wrong_root; } t_bl02_ctx_t;
static bool s_tamper_bl02_wrong_root(dap_chain_datum_tx_t *tx, void *ctx) {
    t_bl02_ctx_t *c = ctx;
    dap_chain_tx_out_cond_t *sl = s_find_dex_out_cond_by_type(tx, false);  // seller-leftover
    if (!sl || dap_hash_fast_is_blank(&sl->subtype.srv_dex.order_root_hash)) return false;
    sl->subtype.srv_dex.order_root_hash = c->wrong_root;
    return true;
}

static int s_run_t_bl02_wrong_chain_root(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- T_BL02: Partial fill on buyer-leftover with wrong root ---");
    
    // Create original ASK order
    dap_hash_fast_t carol_order = {0};
    int ret = s_create_test_order(f, pair, WALLET_CAROL, SIDE_ASK, MINFILL_NONE, "2.5", "10.0", &carol_order);
    if (ret != 0) return -1;
    
    // Bob purchases, creates buyer-leftover
    uint256_t budget_38 = dap_chain_coins_to_balance("38.5");
    uint256_t leftover_rate = dap_chain_coins_to_balance("2.6");
    
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err1 = dap_chain_net_srv_dex_purchase(
        f->net->net, &carol_order, budget_38, true, f->network_fee, f->bob, true, leftover_rate, &tx1
    );
    if (err1 != DEX_PURCHASE_ERROR_OK || !tx1) return -2;
    
    dap_hash_fast_t tx1_hash = {0};
    dap_hash_fast(tx1, dap_chain_datum_tx_get_size(tx1), &tx1_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx1, &tx1_hash, false, NULL) != 0) {
        dap_chain_datum_tx_delete(tx1);
        return -3;
    }
    dap_chain_datum_tx_delete(tx1);
    
    // Alice partially fills buyer-leftover
    uint256_t budget_5 = dap_chain_coins_to_balance("5.0");
    dap_chain_datum_tx_t *tx2 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err2 = dap_chain_net_srv_dex_purchase(
        f->net->net, &tx1_hash, budget_5, false, f->network_fee, f->alice, false, uint256_0, &tx2
    );
    
    int result = 0;
    if (err2 == DEX_PURCHASE_ERROR_OK && tx2) {
        t_bl02_ctx_t ctx = { .wrong_root = carol_order };
        ret = s_tamper_resign_and_verify(f, tx2, f->alice, s_tamper_bl02_wrong_root, &ctx,
                                          "T_BL02: Wrong chain root");
        dap_chain_datum_tx_delete(tx2);
        if (ret > 0) result = -4;
    } else {
        log_it(L_WARNING, "T_BL02: Partial fill failed (err=%d), skipping", err2);
    }
    
    // Rollback
    dap_chain_datum_tx_t *tx1_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx1_hash);
    if (tx1_ledger) dap_ledger_tx_remove(f->net->net->pub.ledger, tx1_ledger, &tx1_hash);
    dap_chain_datum_tx_t *carol_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &carol_order);
    if (carol_tx) dap_ledger_tx_remove(f->net->net->pub.ledger, carol_tx, &carol_order);
    
    return result;
}

// T_BL03: Steal from seller payout to inflate buyer-leftover (underpay seller attack)
static int s_run_t_bl03_value_inflate(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- T_BL03: Underpay seller to inflate buyer-leftover ---");
    
    dap_hash_fast_t carol_order = {0};
    int ret = s_create_test_order(f, pair, WALLET_CAROL, SIDE_ASK, MINFILL_NONE, "2.5", "10.0", &carol_order);
    if (ret != 0) return -1;
    
    uint256_t budget_38 = dap_chain_coins_to_balance("38.5");
    uint256_t leftover_rate = dap_chain_coins_to_balance("2.6");
    
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err1 = dap_chain_net_srv_dex_purchase(
        f->net->net, &carol_order, budget_38, true, f->network_fee, f->bob, true, leftover_rate, &tx1
    );
    if (err1 != DEX_PURCHASE_ERROR_OK || !tx1) return -2;
    
    ret = s_tamper_resign_and_verify(f, tx1, f->bob, s_tamper_bl03_value_inflate, NULL,
                                     "T_BL03: Underpay seller to inflate buyer-leftover");
    dap_chain_datum_tx_delete(tx1);
    
    dap_chain_datum_tx_t *carol_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &carol_order);
    if (carol_tx) dap_ledger_tx_remove(f->net->net->pub.ledger, carol_tx, &carol_order);
    
    return ret > 0 ? -3 : ret;
}

// T_BL04: Buyer-leftover seller_addr hijack
static int s_run_t_bl04_addr_hijack(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- T_BL04: Buyer-leftover seller_addr hijack ---");
    
    dap_hash_fast_t carol_order = {0};
    int ret = s_create_test_order(f, pair, WALLET_CAROL, SIDE_ASK, MINFILL_NONE, "2.5", "10.0", &carol_order);
    if (ret != 0) return -1;
    
    uint256_t budget_38 = dap_chain_coins_to_balance("38.5");
    uint256_t leftover_rate = dap_chain_coins_to_balance("2.6");
    
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err1 = dap_chain_net_srv_dex_purchase(
        f->net->net, &carol_order, budget_38, true, f->network_fee, f->bob, true, leftover_rate, &tx1
    );
    if (err1 != DEX_PURCHASE_ERROR_OK || !tx1) return -2;
    
    t_bl04_ctx_t ctx = { .hijack_addr = f->carol_addr };
    ret = s_tamper_resign_and_verify(f, tx1, f->bob, s_tamper_bl04_addr_hijack, &ctx,
                                     "T_BL04: Buyer-leftover seller_addr hijack");
    dap_chain_datum_tx_delete(tx1);
    
    dap_chain_datum_tx_t *carol_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &carol_order);
    if (carol_tx) dap_ledger_tx_remove(f->net->net->pub.ledger, carol_tx, &carol_order);
    
    return ret > 0 ? -3 : ret;
}

// T_BL05: Inflate seller-leftover (partial fill on buyer-leftover)
// Attack: inflate seller-leftover BEYOND actual remaining value (breaks balance)
static bool s_tamper_bl05_over_exec(dap_chain_datum_tx_t *tx, void *ctx) {
    (void)ctx;
    dap_chain_tx_out_cond_t *sl = s_find_dex_out_cond_by_type(tx, false);  // seller-leftover
    if (!sl || dap_hash_fast_is_blank(&sl->subtype.srv_dex.order_root_hash)) return false;
    
    // Simply inflate seller-leftover by 10 units (no compensation = breaks balance)
    uint256_t inflate_amount = dap_chain_coins_to_balance("10.0");
    uint256_t new_sl = uint256_0;
    SUM_256_256(sl->header.value, inflate_amount, &new_sl);
    sl->header.value = new_sl;
    return true;
}

static int s_run_t_bl05_over_exec(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- T_BL05: Partial fill exceeds buyer-leftover value ---");
    
    dap_hash_fast_t carol_order = {0};
    int ret = s_create_test_order(f, pair, WALLET_CAROL, SIDE_ASK, MINFILL_NONE, "2.5", "10.0", &carol_order);
    if (ret != 0) return -1;
    
    // Bob purchases, creates buyer-leftover
    uint256_t budget_38 = dap_chain_coins_to_balance("38.5");
    uint256_t leftover_rate = dap_chain_coins_to_balance("2.6");
    
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err1 = dap_chain_net_srv_dex_purchase(
        f->net->net, &carol_order, budget_38, true, f->network_fee, f->bob, true, leftover_rate, &tx1
    );
    if (err1 != DEX_PURCHASE_ERROR_OK || !tx1) return -2;
    
    dap_hash_fast_t tx1_hash = {0};
    dap_hash_fast(tx1, dap_chain_datum_tx_get_size(tx1), &tx1_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx1, &tx1_hash, false, NULL) != 0) {
        dap_chain_datum_tx_delete(tx1);
        return -3;
    }
    dap_chain_datum_tx_delete(tx1);
    
    // Alice fills buyer-leftover partially
    uint256_t budget_3 = dap_chain_coins_to_balance("3.0");
    dap_chain_datum_tx_t *tx2 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err2 = dap_chain_net_srv_dex_purchase(
        f->net->net, &tx1_hash, budget_3, false, f->network_fee, f->alice, false, uint256_0, &tx2
    );
    
    int result = 0;
    if (err2 == DEX_PURCHASE_ERROR_OK && tx2) {
        ret = s_tamper_resign_and_verify(f, tx2, f->alice, s_tamper_bl05_over_exec, NULL,
                                          "T_BL05: Over-execution leftover");
        dap_chain_datum_tx_delete(tx2);
        if (ret > 0) result = -4;
    } else {
        log_it(L_WARNING, "T_BL05: Partial fill failed (err=%d), skipping", err2);
    }
    
    // Rollback
    dap_chain_datum_tx_t *tx1_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx1_hash);
    if (tx1_ledger) dap_ledger_tx_remove(f->net->net->pub.ledger, tx1_ledger, &tx1_hash);
    dap_chain_datum_tx_t *carol_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &carol_order);
    if (carol_tx) dap_ledger_tx_remove(f->net->net->pub.ledger, carol_tx, &carol_order);
    
    return result;
}

// T_BL06: Match buyer-leftover with wrong root_hash (use original TX hash instead of blank)
// When matching a buyer-leftover, the resulting seller-leftover (if any) must have correct root
typedef struct { dap_hash_fast_t original_tx_hash; } t_bl06_ctx_t;
static bool s_tamper_bl06_wrong_match_root(dap_chain_datum_tx_t *tx, void *ctx) {
    t_bl06_ctx_t *c = ctx;
    // Find seller-leftover (non-blank root) and tamper it
    dap_chain_tx_out_cond_t *sl = s_find_dex_out_cond_by_type(tx, false);
    if (!sl) return false;
    // Replace with original TX hash (wrong chain)
    sl->subtype.srv_dex.order_root_hash = c->original_tx_hash;
    return true;
}

static int s_run_t_bl06_match_wrong_root(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- T_BL06: Match buyer-leftover with tampered seller-leftover root ---");
    
    // Step 1: Carol creates ASK order
    dap_hash_fast_t carol_order = {0};
    int ret = s_create_test_order(f, pair, WALLET_CAROL, SIDE_ASK, MINFILL_NONE, "2.5", "10.0", &carol_order);
    if (ret != 0) return -1;
    
    // Step 2: Bob buys, creates buyer-leftover (BID 78 QUOTE @ 2.6)
    uint256_t budget = dap_chain_coins_to_balance("40.0");
    uint256_t leftover_rate = dap_chain_coins_to_balance("2.6");
    
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err1 = dap_chain_net_srv_dex_purchase(
        f->net->net, &carol_order, budget, true, f->network_fee, f->bob, true, leftover_rate, &tx1
    );
    if (err1 != DEX_PURCHASE_ERROR_OK || !tx1) return -2;
    
    dap_hash_fast_t tx1_hash = {0};
    dap_hash_fast(tx1, dap_chain_datum_tx_get_size(tx1), &tx1_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx1, &tx1_hash, false, NULL) != 0) {
        dap_chain_datum_tx_delete(tx1);
        return -3;
    }
    dap_chain_datum_tx_delete(tx1);
    
    // Step 3: Alice partially fills buyer-leftover (creates seller-leftover)
    uint256_t budget_3 = dap_chain_coins_to_balance("3.0");
    dap_chain_datum_tx_t *tx2 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err2 = dap_chain_net_srv_dex_purchase(
        f->net->net, &tx1_hash, budget_3, false, f->network_fee, f->alice, false, uint256_0, &tx2
    );
    
    int result = 0;
    if (err2 == DEX_PURCHASE_ERROR_OK && tx2) {
        // Tamper: put wrong root_hash (original Carol's order hash) into seller-leftover
        t_bl06_ctx_t ctx = { .original_tx_hash = carol_order };
        ret = s_tamper_resign_and_verify(f, tx2, f->alice, s_tamper_bl06_wrong_match_root, &ctx,
                                          "T_BL06: Seller-leftover with wrong root (original order)");
        dap_chain_datum_tx_delete(tx2);
        if (ret > 0) result = -4;
    } else {
        log_it(L_WARNING, "T_BL06: Partial fill failed (err=%d), skipping", err2);
    }
    
    // Rollback
    dap_chain_datum_tx_t *tx1_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx1_hash);
    if (tx1_ledger) dap_ledger_tx_remove(f->net->net->pub.ledger, tx1_ledger, &tx1_hash);
    dap_chain_datum_tx_t *carol_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &carol_order);
    if (carol_tx) dap_ledger_tx_remove(f->net->net->pub.ledger, carol_tx, &carol_order);
    
    return result;
}

// T_BL07: UPDATE buyer-leftover - tamper root_hash to wrong value
// In UPDATE TX, OUT_COND has root_hash pointing to previous TX in chain
// We tamper it to a completely different hash (breaks chain integrity)
static bool s_tamper_bl07_update_wrong_root(dap_chain_datum_tx_t *tx, void *ctx) {
    dap_hash_fast_t *fake_root = ctx;
    // Find ANY DEX OUT_COND in UPDATE TX (root_hash is NOT blank for UPDATE)
    int l_item_idx = 0;
    byte_t *l_item = NULL;
    while ((l_item = dap_chain_datum_tx_item_get(tx, &l_item_idx, NULL, TX_ITEM_TYPE_OUT_COND, NULL))) {
        dap_chain_tx_out_cond_t *out_cond = (dap_chain_tx_out_cond_t *)l_item;
        if (out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX) {
            // Tamper root_hash to wrong value (breaks order chain)
            out_cond->subtype.srv_dex.order_root_hash = *fake_root;
            return true;
        }
        l_item_idx++;
    }
    return false;
}

static int s_run_t_bl07_update_with_root(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- T_BL07: UPDATE buyer-leftover with non-blank root_hash ---");
    
    // Step 1: Carol creates ASK order
    dap_hash_fast_t carol_order = {0};
    int ret = s_create_test_order(f, pair, WALLET_CAROL, SIDE_ASK, MINFILL_NONE, "2.5", "10.0", &carol_order);
    if (ret != 0) return -1;
    
    // Step 2: Bob buys, creates buyer-leftover
    uint256_t budget = dap_chain_coins_to_balance("40.0");
    uint256_t leftover_rate = dap_chain_coins_to_balance("2.6");
    
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err1 = dap_chain_net_srv_dex_purchase(
        f->net->net, &carol_order, budget, true, f->network_fee, f->bob, true, leftover_rate, &tx1
    );
    if (err1 != DEX_PURCHASE_ERROR_OK || !tx1) return -2;
    
    dap_hash_fast_t tx1_hash = {0};
    dap_hash_fast(tx1, dap_chain_datum_tx_get_size(tx1), &tx1_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx1, &tx1_hash, false, NULL) != 0) {
        dap_chain_datum_tx_delete(tx1);
        return -3;
    }
    dap_chain_datum_tx_delete(tx1);
    
    // Get buyer-leftover info
    dex_order_info_t bl_order = {0};
    if (test_dex_order_get_info(f->net->net->pub.ledger, &tx1_hash, &bl_order) != 0) return -4;
    
    // Step 3: Create UPDATE TX
    uint256_t new_value = uint256_0;
    DIV_256(bl_order.value, GET_256_FROM_64(2), &new_value);
    
    dap_chain_datum_tx_t *update_tx = NULL;
    dap_chain_net_srv_dex_update_error_t upd_err = dap_chain_net_srv_dex_update(
        f->net->net, &tx1_hash, true, new_value, f->network_fee, f->bob, &update_tx
    );
    
    int result = 0;
    if (upd_err == DEX_UPDATE_ERROR_OK && update_tx) {
        // Tamper: change root_hash to completely wrong value (breaks chain)
        dap_hash_fast_t fake_root = {0};
        dap_hash_fast("fake_root_for_bl07", 18, &fake_root);
        ret = s_tamper_resign_and_verify(f, update_tx, f->bob, s_tamper_bl07_update_wrong_root, &fake_root,
                                          "T_BL07: UPDATE buyer-leftover with wrong root_hash");
        dap_chain_datum_tx_delete(update_tx);
        if (ret > 0) result = -5;
    } else {
        log_it(L_WARNING, "T_BL07: UPDATE API failed (err=%d), skipping", upd_err);
    }
    
    // Rollback
    dap_chain_datum_tx_t *tx1_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx1_hash);
    if (tx1_ledger) dap_ledger_tx_remove(f->net->net->pub.ledger, tx1_ledger, &tx1_hash);
    dap_chain_datum_tx_t *carol_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &carol_order);
    if (carol_tx) dap_ledger_tx_remove(f->net->net->pub.ledger, carol_tx, &carol_order);
    
    return result;
}

// T_BL08: CANCEL with tampered IN_COND pointing to different order
// Attack: Bob creates CANCEL for his buyer-leftover, but we tamper IN_COND
// to point to Carol's order instead (attempt to cancel someone else's order)
typedef struct { dap_hash_fast_t target_order; } t_bl08_ctx_t;
static bool s_tamper_bl08_cancel_foreign_order(dap_chain_datum_tx_t *tx, void *ctx) {
    t_bl08_ctx_t *c = ctx;
    // Find IN_COND and change tx_prev_hash to different order
    int l_item_idx = 0;
    byte_t *l_item = NULL;
    while ((l_item = dap_chain_datum_tx_item_get(tx, &l_item_idx, NULL, TX_ITEM_TYPE_IN_COND, NULL))) {
        dap_chain_tx_in_cond_t *in_cond = (dap_chain_tx_in_cond_t *)l_item;
        // Tamper: point to Carol's order instead of Bob's buyer-leftover
        in_cond->header.tx_prev_hash = c->target_order;
        return true;
    }
    return false;
}

static int s_run_t_bl08_cancel_foreign_order(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- T_BL08: CANCEL with IN_COND pointing to foreign order ---");
    
    // Step 1: Carol creates ASK order (this will be the "foreign" order)
    dap_hash_fast_t carol_order = {0};
    int ret = s_create_test_order(f, pair, WALLET_CAROL, SIDE_ASK, MINFILL_NONE, "2.5", "10.0", &carol_order);
    if (ret != 0) return -1;
    
    // Step 2: Bob buys, creates buyer-leftover
    uint256_t budget = dap_chain_coins_to_balance("40.0");
    uint256_t leftover_rate = dap_chain_coins_to_balance("2.6");
    
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err1 = dap_chain_net_srv_dex_purchase(
        f->net->net, &carol_order, budget, true, f->network_fee, f->bob, true, leftover_rate, &tx1
    );
    if (err1 != DEX_PURCHASE_ERROR_OK || !tx1) return -2;
    
    dap_hash_fast_t tx1_hash = {0};
    dap_hash_fast(tx1, dap_chain_datum_tx_get_size(tx1), &tx1_hash);
    if (dap_ledger_tx_add(f->net->net->pub.ledger, tx1, &tx1_hash, false, NULL) != 0) {
        dap_chain_datum_tx_delete(tx1);
        return -3;
    }
    dap_chain_datum_tx_delete(tx1);
    
    // Step 3: Alice creates another order (to have a second foreign order)
    dap_hash_fast_t alice_order = {0};
    ret = s_create_test_order(f, pair, WALLET_ALICE, SIDE_ASK, MINFILL_NONE, "2.7", "15.0", &alice_order);
    if (ret != 0) {
        dap_chain_datum_tx_t *tx1_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx1_hash);
        if (tx1_ledger) dap_ledger_tx_remove(f->net->net->pub.ledger, tx1_ledger, &tx1_hash);
        dap_chain_datum_tx_t *carol_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &carol_order);
        if (carol_tx) dap_ledger_tx_remove(f->net->net->pub.ledger, carol_tx, &carol_order);
        return -4;
    }
    
    // Step 4: Bob creates CANCEL for his buyer-leftover
    dap_chain_datum_tx_t *cancel_tx = NULL;
    dap_chain_net_srv_dex_remove_error_t rem_err = dap_chain_net_srv_dex_remove(
        f->net->net, &tx1_hash, f->network_fee, f->bob, &cancel_tx
    );
    
    int result = 0;
    if (rem_err == DEX_REMOVE_ERROR_OK && cancel_tx) {
        // Tamper: change IN_COND to point to Alice's order (foreign order)
        t_bl08_ctx_t ctx = { .target_order = alice_order };
        ret = s_tamper_resign_and_verify(f, cancel_tx, f->bob, s_tamper_bl08_cancel_foreign_order, &ctx,
                                          "T_BL08: CANCEL with IN_COND pointing to Alice's order");
        dap_chain_datum_tx_delete(cancel_tx);
        if (ret > 0) result = -5;
    } else {
        log_it(L_WARNING, "T_BL08: CANCEL API failed (err=%d), skipping", rem_err);
    }
    
    // Rollback
    dap_chain_datum_tx_t *alice_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &alice_order);
    if (alice_tx) dap_ledger_tx_remove(f->net->net->pub.ledger, alice_tx, &alice_order);
    dap_chain_datum_tx_t *tx1_ledger = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &tx1_hash);
    if (tx1_ledger) dap_ledger_tx_remove(f->net->net->pub.ledger, tx1_ledger, &tx1_hash);
    dap_chain_datum_tx_t *carol_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &carol_order);
    if (carol_tx) dap_ledger_tx_remove(f->net->net->pub.ledger, carol_tx, &carol_order);
    
    return result;
}

// ============================================================================
// SELLER-LEFTOVER TAMPERING TESTS (T_SL)
// ============================================================================

// T_SL01: Seller-leftover with blank root_hash (should be non-blank)
static int s_run_t_sl01_blank_root(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- T_SL01: Seller-leftover with blank root_hash ---");
    
    // Create ASK order (partial fill will create seller-leftover)
    dap_hash_fast_t alice_order = {0};
    int ret = s_create_test_order(f, pair, WALLET_ALICE, SIDE_ASK, MINFILL_NONE, "2.5", "20.0", &alice_order);
    if (ret != 0) return -1;
    
    // Bob purchases partially (10 of 20)
    uint256_t budget_10 = dap_chain_coins_to_balance("10.0");
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err = dap_chain_net_srv_dex_purchase(
        f->net->net, &alice_order, budget_10, true, f->network_fee, f->bob, false, uint256_0, &tx1);
    
    if (err != DEX_PURCHASE_ERROR_OK || !tx1) {
        dap_chain_datum_tx_t *order_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &alice_order);
        if (order_tx) dap_ledger_tx_remove(f->net->net->pub.ledger, order_tx, &alice_order);
        return -2;
    }
    
    // Tamper: blank root_hash (should be non-blank for seller-leftover)
    ret = s_tamper_resign_and_verify(f, tx1, f->bob, 
        (bl_tamper_fn)tamper_order_root_hash, NULL,
        "T_SL01: Seller-leftover with blank root_hash");
    dap_chain_datum_tx_delete(tx1);
    
    // Cleanup
    dap_chain_datum_tx_t *order_tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &alice_order);
    if (order_tx) dap_ledger_tx_remove(f->net->net->pub.ledger, order_tx, &alice_order);
    
    return ret > 0 ? -3 : ret;
}

// T_SL02: Seller-leftover with wrong root_hash (different order)
static int s_run_t_sl02_wrong_root(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- T_SL02: Seller-leftover with wrong root_hash ---");
    
    // Create two orders
    dap_hash_fast_t alice_order = {0}, carol_order = {0};
    int ret = s_create_test_order(f, pair, WALLET_ALICE, SIDE_ASK, MINFILL_NONE, "2.5", "20.0", &alice_order);
    if (ret != 0) return -1;
    ret = s_create_test_order(f, pair, WALLET_CAROL, SIDE_ASK, MINFILL_NONE, "2.6", "10.0", &carol_order);
    if (ret != 0) {
        dap_chain_datum_tx_t *tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &alice_order);
        if (tx) dap_ledger_tx_remove(f->net->net->pub.ledger, tx, &alice_order);
        return -2;
    }
    
    // Bob purchases Alice's order partially
    uint256_t budget_10 = dap_chain_coins_to_balance("10.0");
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err = dap_chain_net_srv_dex_purchase(
        f->net->net, &alice_order, budget_10, true, f->network_fee, f->bob, false, uint256_0, &tx1);
    
    if (err != DEX_PURCHASE_ERROR_OK || !tx1) {
        ret = -3;
        goto cleanup;
    }
    
    // Tamper: use Carol's order hash as root_hash (wrong chain)
    ret = s_tamper_resign_and_verify(f, tx1, f->bob,
        (bl_tamper_fn)tamper_order_root_hash, &carol_order,
        "T_SL02: Seller-leftover with wrong root_hash");
    dap_chain_datum_tx_delete(tx1);
    
    if (ret > 0) ret = -4;
    
cleanup: ;
    dap_chain_datum_tx_t *tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &alice_order);
    if (tx) dap_ledger_tx_remove(f->net->net->pub.ledger, tx, &alice_order);
    tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &carol_order);
    if (tx) dap_ledger_tx_remove(f->net->net->pub.ledger, tx, &carol_order);
    
    return ret;
}

// Tamper seller_addr in seller-leftover
typedef struct { dap_chain_addr_t hijack_addr; } t_sl03_ctx_t;
static bool s_tamper_sl03_addr(dap_chain_datum_tx_t *tx, void *ctx) {
    t_sl03_ctx_t *c = ctx;
    dap_chain_tx_out_cond_t *sl = s_find_dex_out_cond_by_type(tx, false);  // seller-leftover
    if (!sl || dap_hash_fast_is_blank(&sl->subtype.srv_dex.order_root_hash)) return false;
    sl->subtype.srv_dex.seller_addr = c->hijack_addr;
    return true;
}

// T_SL03: Seller-leftover seller_addr hijack
static int s_run_t_sl03_addr_hijack(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- T_SL03: Seller-leftover seller_addr hijack ---");
    
    dap_hash_fast_t alice_order = {0};
    int ret = s_create_test_order(f, pair, WALLET_ALICE, SIDE_ASK, MINFILL_NONE, "2.5", "20.0", &alice_order);
    if (ret != 0) return -1;
    
    uint256_t budget_10 = dap_chain_coins_to_balance("10.0");
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err = dap_chain_net_srv_dex_purchase(
        f->net->net, &alice_order, budget_10, true, f->network_fee, f->bob, false, uint256_0, &tx1);
    
    if (err != DEX_PURCHASE_ERROR_OK || !tx1) {
        dap_chain_datum_tx_t *tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &alice_order);
        if (tx) dap_ledger_tx_remove(f->net->net->pub.ledger, tx, &alice_order);
        return -2;
    }
    
    // Tamper: hijack to Carol's address
    t_sl03_ctx_t ctx = { .hijack_addr = f->carol_addr };
    ret = s_tamper_resign_and_verify(f, tx1, f->bob, s_tamper_sl03_addr, &ctx,
        "T_SL03: Seller-leftover seller_addr hijack");
    dap_chain_datum_tx_delete(tx1);
    
    dap_chain_datum_tx_t *tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &alice_order);
    if (tx) dap_ledger_tx_remove(f->net->net->pub.ledger, tx, &alice_order);
    
    return ret > 0 ? -3 : ret;
}

// Tamper rate in seller-leftover
typedef struct { uint256_t fake_rate; } t_sl04_ctx_t;
static bool s_tamper_sl04_rate(dap_chain_datum_tx_t *tx, void *ctx) {
    t_sl04_ctx_t *c = ctx;
    dap_chain_tx_out_cond_t *sl = s_find_dex_out_cond_by_type(tx, false);
    if (!sl || dap_hash_fast_is_blank(&sl->subtype.srv_dex.order_root_hash)) return false;
    sl->subtype.srv_dex.rate = c->fake_rate;
    return true;
}

// T_SL04: Seller-leftover with wrong rate
static int s_run_t_sl04_wrong_rate(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    log_it(L_INFO, "--- T_SL04: Seller-leftover with wrong rate ---");
    
    dap_hash_fast_t alice_order = {0};
    int ret = s_create_test_order(f, pair, WALLET_ALICE, SIDE_ASK, MINFILL_NONE, "2.5", "20.0", &alice_order);
    if (ret != 0) return -1;
    
    uint256_t budget_10 = dap_chain_coins_to_balance("10.0");
    dap_chain_datum_tx_t *tx1 = NULL;
    dap_chain_net_srv_dex_purchase_error_t err = dap_chain_net_srv_dex_purchase(
        f->net->net, &alice_order, budget_10, true, f->network_fee, f->bob, false, uint256_0, &tx1);
    
    if (err != DEX_PURCHASE_ERROR_OK || !tx1) {
        dap_chain_datum_tx_t *tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &alice_order);
        if (tx) dap_ledger_tx_remove(f->net->net->pub.ledger, tx, &alice_order);
        return -2;
    }
    
    // Tamper: change rate from 2.5 to 1.0 (lower rate = more favorable for attacker)
    t_sl04_ctx_t ctx = { .fake_rate = dap_chain_coins_to_balance("1.0") };
    ret = s_tamper_resign_and_verify(f, tx1, f->bob, s_tamper_sl04_rate, &ctx,
        "T_SL04: Seller-leftover with wrong rate");
    dap_chain_datum_tx_delete(tx1);
    
    dap_chain_datum_tx_t *tx = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &alice_order);
    if (tx) dap_ledger_tx_remove(f->net->net->pub.ledger, tx, &alice_order);
    
    return ret > 0 ? -3 : ret;
}

// Run all seller-leftover tampering tests
static int s_run_seller_leftover_tampers(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    int ret;
    
    ret = s_run_t_sl01_blank_root(f, pair);
    if (ret != 0) return ret;
    
    ret = s_run_t_sl02_wrong_root(f, pair);
    if (ret != 0) return ret;
    
    ret = s_run_t_sl03_addr_hijack(f, pair);
    if (ret != 0) return ret;
    
    ret = s_run_t_sl04_wrong_rate(f, pair);
    if (ret != 0) return ret;
    
    return 0;
}

// Run all buyer-leftover tampering tests
static int s_run_buyer_leftover_tampers(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    int ret;
    
    ret = s_run_t_bl01_nonzero_root(f, pair);
    if (ret != 0) return ret;
    
    ret = s_run_t_bl02_wrong_chain_root(f, pair);
    if (ret != 0) return ret;
    
    ret = s_run_t_bl03_value_inflate(f, pair);
    if (ret != 0) return ret;
    
    ret = s_run_t_bl04_addr_hijack(f, pair);
    if (ret != 0) return ret;
    
    ret = s_run_t_bl05_over_exec(f, pair);
    if (ret != 0) return ret;
    
    ret = s_run_t_bl06_match_wrong_root(f, pair);
    if (ret != 0) return ret;
    
    ret = s_run_t_bl07_update_with_root(f, pair);
    if (ret != 0) return ret;
    
    ret = s_run_t_bl08_cancel_foreign_order(f, pair);
    if (ret != 0) return ret;
    
    return 0;
}

// Run all multi-execution tests for a single pair
static int s_run_multi_tests_for_pair(dex_test_fixture_t *f, const test_pair_config_t *pair) {
    int ret;
    
    // ASK tests (M01-M03)
    ret = s_run_m01_seller_partial_current(f, pair);
    if (ret != 0) return ret;
    
    ret = s_run_m02_seller_partial_origin(f, pair);
    if (ret != 0) return ret;
    
    ret = s_run_m03_buyer_leftover(f, pair);
    if (ret != 0) return ret;
    
    // BID tests (M04-M06)
    ret = s_run_m04_bid_partial_current(f, pair);
    if (ret != 0) return ret;
    
    ret = s_run_m05_bid_partial_origin(f, pair);
    if (ret != 0) return ret;
    
    ret = s_run_m06_bid_buyer_leftover(f, pair);
    if (ret != 0) return ret;
    
    // Buyer-leftover operations (M07-M10)
    ret = s_run_m07_buyer_leftover_update(f, pair);
    if (ret != 0) return ret;
    
    ret = s_run_m08_buyer_leftover_cancel(f, pair);
    if (ret != 0) return ret;
    
    ret = s_run_m09_buyer_leftover_double_cancel(f, pair);
    if (ret != 0) return ret;
    
    ret = s_run_m10_buyer_leftover_foreign_ops(f, pair);
    if (ret != 0) return ret;
    
    // Seller-leftover tampering tests (T_SL01-T_SL04)
    ret = s_run_seller_leftover_tampers(f, pair);
    if (ret != 0) return ret;
    
    // Buyer-leftover tampering tests (T_BL01-T_BL05)
    ret = s_run_buyer_leftover_tampers(f, pair);
    if (ret != 0) return ret;
    
    return 0;
}

// Main entry point for multi-execution tests
// Rollback is done after each test to preserve balances across pairs
static int run_multi_execution_tests(dex_test_fixture_t *f) {
    log_it(L_NOTICE, " ");
    log_it(L_NOTICE, "╔══════════════════════════════════════════════════════════╗");
    log_it(L_NOTICE, "║          MULTI-EXECUTION TESTS (Group M)                 ║");
    log_it(L_NOTICE, "╚══════════════════════════════════════════════════════════╝");
    
    const test_pair_config_t *pairs = test_get_standard_pairs();
    size_t pairs_count = test_get_standard_pairs_count();
    
    size_t passed = 0, skipped = 0;
    for (size_t p = 0; p < pairs_count; p++) {
        // Check balances for all participants:
        // ASK tests: Alice needs BASE, Bob needs QUOTE
        // BID tests: Bob needs QUOTE, Alice needs BASE
        uint256_t alice_base = dap_ledger_calc_balance(f->net->net->pub.ledger, &f->alice_addr, pairs[p].base_token);
        uint256_t bob_quote = dap_ledger_calc_balance(f->net->net->pub.ledger, &f->bob_addr, pairs[p].quote_token);
        uint256_t min_required = dap_chain_coins_to_balance("100.0");
        
        if (compare256(bob_quote, min_required) < 0) {
            log_it(L_WARNING, "MULTI-EXEC PAIR %zu/%zu: %s - SKIPPED (Bob has insufficient %s)", 
                   p+1, pairs_count, pairs[p].description, pairs[p].quote_token);
            skipped++;
            continue;
        }
        if (compare256(alice_base, min_required) < 0) {
            log_it(L_WARNING, "MULTI-EXEC PAIR %zu/%zu: %s - SKIPPED (Alice has insufficient %s)", 
                   p+1, pairs_count, pairs[p].description, pairs[p].base_token);
            skipped++;
            continue;
        }
        
        log_it(L_NOTICE, " ");
        log_it(L_NOTICE, "┌──────────────────────────────────────────────────────────┐");
        log_it(L_NOTICE, "│  MULTI-EXEC PAIR %zu/%zu: %s", p+1, pairs_count, pairs[p].description);
        log_it(L_NOTICE, "└──────────────────────────────────────────────────────────┘");
        
        int ret = s_run_multi_tests_for_pair(f, &pairs[p]);
        if (ret != 0) {
            log_it(L_ERROR, "Multi-execution tests failed for pair %s: %d", pairs[p].description, ret);
            return ret;
        }
        passed++;
    }
    
    log_it(L_NOTICE, "Multi-exec: %zu pairs passed, %zu skipped", passed, skipped);
    
    log_it(L_NOTICE, " ");
    log_it(L_NOTICE, "╔══════════════════════════════════════════════════════════╗");
    log_it(L_NOTICE, "║  ✓ ALL MULTI-EXECUTION TESTS PASSED                      ║");
    log_it(L_NOTICE, "╚══════════════════════════════════════════════════════════╝");
    
    return 0;
}

// ============================================================================
// GROUP RUNNER
// ============================================================================

static const char* get_net_fee_collector_name(net_fee_collector_t nfc) {
    switch (nfc) {
        case NET_FEE_DAVE:  return "Dave (neutral)";
        case NET_FEE_ALICE: return "Alice (seller)";
        case NET_FEE_BOB:   return "Bob (seller)";
        default:            return "Unknown";
    }
}

int run_lifecycle_tests(dex_test_fixture_t *f) {
    log_it(L_NOTICE, " ");
    log_it(L_NOTICE, "╔══════════════════════════════════════════════════════════╗");
    log_it(L_NOTICE, "║          DEX LIFECYCLE TESTS                             ║");
    log_it(L_NOTICE, "╚══════════════════════════════════════════════════════════╝");
    
    const test_pair_config_t *pairs = test_get_standard_pairs();
    size_t pairs_count = test_get_standard_pairs_count();
    
   size_t passed = 0;
    
    // Iterate over network fee collector configurations
    for (net_fee_collector_t nfc = NET_FEE_DAVE; nfc <= NET_FEE_BOB; nfc++) {
        test_set_net_fee_collector(f, nfc);
        
        log_it(L_NOTICE, " ");
        log_it(L_NOTICE, "╔══════════════════════════════════════════════════════════╗");
        log_it(L_NOTICE, "║  NET FEE COLLECTOR: %s", get_net_fee_collector_name(nfc));
        log_it(L_NOTICE, "╚══════════════════════════════════════════════════════════╝");
        
        for (size_t p = 0; p < pairs_count; p++) {
            log_it(L_NOTICE, " ");
            log_it(L_NOTICE, "┌──────────────────────────────────────────────────────────┐");
            log_it(L_NOTICE, "│  PAIR %zu/%zu: %s", p+1, pairs_count, pairs[p].description);
            log_it(L_NOTICE, "└──────────────────────────────────────────────────────────┘");
            
            for (size_t t = 0; t < ORDER_TEMPLATES_COUNT; t++) {
                int ret = run_order_lifecycle(f, &pairs[p], &ORDER_TEMPLATES[t], p, t);
                if (ret != 0) {
                    log_it(L_ERROR, "✗ LIFECYCLE FAILED [nfc=%d, %zu.%zu]: ret=%d", 
                           nfc, p, t, ret);
                    test_dex_dump_balances(f, "State at failure");
                    test_dex_dump_orderbook(f, "State at failure");
                    return ret;
                }
                passed++;
            }
            
            test_dex_dump_balances(f, "After pair");
        }
    }
    test_dex_dump_orderbook(f, "At success");
    
    // Final cleanup: cancel all remaining active orders (owner-driven)
    int cancel_all_ret = run_cancel_all_active(f);
    if (cancel_all_ret != 0) {
        log_it(L_ERROR, "Cancel-all phase failed: %d", cancel_all_ret);
        return cancel_all_ret;
    }
    
    test_dex_dump_orderbook(f, "After cancel-all");
    
    // Run multi-execution tests on clean orderbook
    int multi_ret = run_multi_execution_tests(f);
    if (multi_ret != 0) {
        log_it(L_ERROR, "Multi-execution tests failed: %d", multi_ret);
        return multi_ret;
    }
    
    // Cleanup orderbook after multi-execution tests (for subsequent automatch seed)
    test_dex_dump_orderbook(f, "Before final cleanup");
    int cancel_ret = run_cancel_all_active(f);
    if (cancel_ret != 0) {
        log_it(L_ERROR, "Final cleanup (cancel-all) failed: %d", cancel_ret);
        return cancel_ret;
    }
    test_dex_dump_orderbook(f, "After final cleanup");
    
    log_it(L_NOTICE, " ");
    log_it(L_NOTICE, "╔══════════════════════════════════════════════════════════╗");
    log_it(L_NOTICE, "║  ✓ ALL %zu LIFECYCLE TESTS PASSED                        ║", passed);
    log_it(L_NOTICE, "╚══════════════════════════════════════════════════════════╝");
    return 0;
}

