/**
 * @file dex_lifecycle_tests.c
 * @brief Order lifecycle tests: create, full/partial buy, rollback, cancel
 */

#include "dex_test_scenarios.h"
#include "dap_chain_net_srv_dex.h"

// ============================================================================
// HELPERS
// ============================================================================

// Calculate percentage: result = value * pct / 100
static inline uint256_t calc_pct(uint256_t value, uint8_t pct) {
    uint256_t result = uint256_0;
    if (pct && !IS_ZERO_256(value)) {
        MULT_256_256(value, GET_256_FROM_64(pct), &result);
        DIV_256(result, GET_256_FROM_64(100), &result);
    }
    return result;
}

// Adjust buyer deltas when fee token == one of the traded tokens
// net_fee is always paid in NATIVE token (TestCoin), so:
// - if quote_is_native: affects buyer's QUOTE spending/receiving
// - if base_is_native: affects buyer's BASE receiving/spending
static inline void adjust_native_fee(
    uint8_t side, bool quote_is_native, bool base_is_native, bool buyer_is_net_collector,
    uint128_t net_fee,
    uint128_t *buyer_spending, uint128_t *buyer_receiving)
{
    // buyer_is_net_collector: net_fee goes back to buyer, but validator_fee is still paid
    uint128_t fee = buyer_is_net_collector ? net_fee : 2 * net_fee;
    if (fee == 0) return;
    
    // For ASK: buyer spends QUOTE, gets BASE
    // For BID: buyer spends BASE, gets QUOTE
    // When native == what buyer gets → subtract fee from receiving
    // When native == what buyer spends → add fee to spending
    
    if (side == SIDE_ASK) {
        if (quote_is_native)
            *buyer_spending += fee;
        else if (base_is_native)
            *buyer_receiving -= fee;
    } else {  // SIDE_BID
        if (base_is_native)
            *buyer_spending += fee;
        else if (quote_is_native)
            *buyer_receiving -= fee;
    }
}

// ============================================================================
// TAMPERING CALLBACKS
// ============================================================================

typedef struct {
    dap_chain_addr_t *target_addr;
    const char *token;
    uint256_t original_value;
    uint256_t tampered_value;
} tamper_output_data_t;

static bool tamper_inflate_output(dap_chain_datum_tx_t *tx, void *user_data) {
    tamper_output_data_t *data = (tamper_output_data_t*)user_data;
    byte_t *it; size_t sz;
    
    TX_ITEM_ITER_TX(it, sz, tx) {
        if (*it == TX_ITEM_TYPE_OUT_STD) {
            dap_chain_tx_out_std_t *out = (dap_chain_tx_out_std_t*)it;
            if (dap_chain_addr_compare(&out->addr, data->target_addr) &&
                !dap_strcmp(out->token, data->token)) {
                data->original_value = out->value;
                out->value = data->tampered_value;
                return true;
            }
        }
    }
    return false;
}

// Transfer tampering: move funds from source OUT to destination OUT
// Preserves total balance so TX passes ledger check but fails DEX verifier
typedef enum {
    TAMPER_OUT_SELLER_PAYOUT,   // OUT_STD to seller in buy_token
    TAMPER_OUT_BUYER_PAYOUT,    // OUT_STD to buyer in sell_token
    TAMPER_OUT_BUYER_CASHBACK,  // OUT_STD to buyer in buy_token
    TAMPER_OUT_NET_FEE,         // OUT_STD to net_addr in native
    TAMPER_OUT_SRV_FEE,         // OUT_STD to srv_addr in fee_token
    TAMPER_OUT_VALIDATOR_FEE    // OUT_COND subtype=FEE
} tamper_out_type_t;

typedef struct {
    tamper_out_type_t source;
    tamper_out_type_t destination;
    uint256_t transfer_amount;
    // Context for finding OUTs
    const dap_chain_addr_t *seller_addr;
    const dap_chain_addr_t *buyer_addr;
    const dap_chain_addr_t *net_addr;
    const dap_chain_addr_t *srv_addr;
    const char *native_ticker;
    const char *buy_ticker;
    const char *sell_ticker;
    const char *fee_ticker;  // Service fee token (quote for ASK, sell for BID)
} tamper_transfer_data_t;

// Find OUT by type and return pointer to its value
// skip_ptr: if not NULL, skip this OUT (to find a different one with same criteria)
static uint256_t *s_find_out_value_ex(dap_chain_datum_tx_t *tx, tamper_out_type_t type, 
                                       const tamper_transfer_data_t *ctx, uint256_t *skip_ptr) {
    byte_t *it; size_t sz;
    TX_ITEM_ITER_TX(it, sz, tx) {
        if (type == TAMPER_OUT_VALIDATOR_FEE) {
            if (*it == TX_ITEM_TYPE_OUT_COND) {
                dap_chain_tx_out_cond_t *out = (dap_chain_tx_out_cond_t*)it;
                if (out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE) {
                    if (&out->header.value != skip_ptr)
                        return &out->header.value;
                }
            }
        } else if (*it == TX_ITEM_TYPE_OUT_STD) {
            dap_chain_tx_out_std_t *out = (dap_chain_tx_out_std_t*)it;
            if (&out->value == skip_ptr)
                continue;
            switch (type) {
                case TAMPER_OUT_SELLER_PAYOUT:
                    if (dap_chain_addr_compare(&out->addr, ctx->seller_addr) &&
                        !dap_strcmp(out->token, ctx->buy_ticker))
                        return &out->value;
                    break;
                case TAMPER_OUT_BUYER_PAYOUT:
                    if (dap_chain_addr_compare(&out->addr, ctx->buyer_addr) &&
                        !dap_strcmp(out->token, ctx->sell_ticker))
                        return &out->value;
                    break;
                case TAMPER_OUT_BUYER_CASHBACK:
                    if (dap_chain_addr_compare(&out->addr, ctx->buyer_addr) &&
                        !dap_strcmp(out->token, ctx->buy_ticker))
                        return &out->value;
                    break;
                case TAMPER_OUT_NET_FEE:
                    if (dap_chain_addr_compare(&out->addr, ctx->net_addr) &&
                        !dap_strcmp(out->token, ctx->native_ticker))
                        return &out->value;
                    break;
                case TAMPER_OUT_SRV_FEE:
                    if (dap_chain_addr_compare(&out->addr, ctx->srv_addr) &&
                        !dap_strcmp(out->token, ctx->fee_ticker))
                        return &out->value;
                    break;
                default:
                    break;
            }
        }
    }
    return NULL;
}

static uint256_t *s_find_out_value(dap_chain_datum_tx_t *tx, tamper_out_type_t type,
                                    const tamper_transfer_data_t *ctx) {
    return s_find_out_value_ex(tx, type, ctx, NULL);
}

static bool tamper_transfer_funds(dap_chain_datum_tx_t *tx, void *user_data) {
    tamper_transfer_data_t *data = (tamper_transfer_data_t*)user_data;
    
    uint256_t *src_val = s_find_out_value(tx, data->source, data);
    if (!src_val)
        return false;
    
    // Find destination, but skip source OUT if they might be the same
    // (e.g., seller_payout and buyer_cashback when seller == buyer or same token)
    uint256_t *dst_val = s_find_out_value_ex(tx, data->destination, data, src_val);
    if (!dst_val)
        return false;
    
    // Double-check they're different OUTs
    if (src_val == dst_val)
        return false;
    
    // Check source has enough to transfer
    if (compare256(*src_val, data->transfer_amount) < 0)
        return false;
    
    // Transfer: src -= amount, dst += amount
    SUBTRACT_256_256(*src_val, data->transfer_amount, src_val);
    SUM_256_256(*dst_val, data->transfer_amount, dst_val);
    return true;
}

// ============================================================================
// OUT_COND SRV_DEX field tampering
// ============================================================================

// Find OUT_COND with subtype SRV_DEX
static dap_chain_tx_out_cond_t *s_find_dex_out_cond(dap_chain_datum_tx_t *tx) {
    byte_t *it; size_t sz;
    TX_ITEM_ITER_TX(it, sz, tx) {
        if (*it == TX_ITEM_TYPE_OUT_COND) {
            dap_chain_tx_out_cond_t *out = (dap_chain_tx_out_cond_t*)it;
            if (out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX)
                return out;
        }
    }
    return NULL;
}

// Tamper order_root_hash in OUT_COND SRV_DEX
// new_root_hash: NULL = set blank, otherwise set to this hash
static bool tamper_order_root_hash(dap_chain_datum_tx_t *tx, void *user_data) {
    dap_hash_fast_t *new_hash = (dap_hash_fast_t*)user_data;
    dap_chain_tx_out_cond_t *out = s_find_dex_out_cond(tx);
    if (!out)
        return false;
    
    if (new_hash)
        out->subtype.srv_dex.order_root_hash = *new_hash;
    else
        memset(&out->subtype.srv_dex.order_root_hash, 0, sizeof(dap_hash_fast_t));
    return true;
}

// Tamper tx_type in OUT_COND SRV_DEX
static bool tamper_tx_type(dap_chain_datum_tx_t *tx, void *user_data) {
    uint8_t new_type = *(uint8_t*)user_data;
    dap_chain_tx_out_cond_t *out = s_find_dex_out_cond(tx);
    if (!out)
        return false;
    
    out->subtype.srv_dex.tx_type = new_type;
    return true;
}

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
    if (sell_is_native)
        expected_seller_spent += seller_is_net_collector ? net_fee : 2 * net_fee;
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
        
        // Addresses needed for delta calculations
        const dap_chain_addr_t *buyer_addr = get_wallet_addr(f, sc->buyer);
        const dap_chain_addr_t *seller_addr = get_wallet_addr(f, ctx->tmpl->seller);
        const dap_chain_addr_t *net_fee_addr = test_get_net_fee_addr(f);
        bool buyer_is_net_collector = dap_chain_addr_compare(buyer_addr, net_fee_addr);
        bool seller_is_net_collector = dap_chain_addr_compare(seller_addr, net_fee_addr);
        
        // Expected deltas (ASK vs BID have different fee logic)
        const uint128_t POW18 = 1000000000000000000ULL;
        const uint128_t POW36 = POW18 * POW18;
        
        uint128_t order_val = dap_uint256_to_uint128(order->value);
        uint128_t rate = dap_uint256_to_uint128(order->price);
        uint128_t net_fee = dap_uint256_to_uint128(f->network_fee);
        uint128_t service_fee = 0;
        uint128_t buyer_gets_base, buyer_spends_quote, seller_gets_quote;
        uint8_t fee_cfg = ctx->pair->fee_config;
        
        bool seller_is_service = (ctx->tmpl->seller == WALLET_CAROL);
        
        if (ctx->tmpl->side == SIDE_ASK) {
            // ASK: seller sells BASE, buyer pays QUOTE + svc_fee
            seller_gets_quote = (order_val * rate) / POW18;
            if (!sc->expect_fee_waived && (fee_cfg & 0x80))
                service_fee = (seller_gets_quote * (fee_cfg & 0x7F)) / 100;
            buyer_gets_base = order_val;
            buyer_spends_quote = seller_gets_quote + service_fee;
            // When seller = Carol (service wallet), fee aggregates to seller payout
            if (seller_is_service)
                seller_gets_quote += service_fee;
            // When seller = net_fee_collector and QUOTE is native, seller also receives net_fee
            if (seller_is_net_collector && ctx->pair->quote_is_native)
                seller_gets_quote += net_fee;
        } else {
            // BID: seller sells QUOTE (order_val), gets BASE (exec_sell)
            // Rate is now canonical (QUOTE/BASE), no inversion needed
            // exec_sell = order_val / rate (QUOTE / (QUOTE/BASE) = BASE)
            uint128_t exec_sell = (order_val * POW18) / rate;
            seller_gets_quote = exec_sell;  // Actually seller gets BASE (exec_sell)
            if (!sc->expect_fee_waived && (fee_cfg & 0x80))
                service_fee = (order_val * (fee_cfg & 0x7F)) / 100;
            buyer_gets_base = order_val - service_fee;  // Buyer gets QUOTE minus fee
            buyer_spends_quote = exec_sell;  // Buyer spends BASE (exec_sell)
            // When seller = net_fee_collector and BASE is native (seller gets BASE), seller also receives net_fee
            if (seller_is_net_collector && ctx->pair->base_is_native)
                seller_gets_quote += net_fee;
        }
        
        adjust_native_fee(ctx->tmpl->side, ctx->pair->quote_is_native, ctx->pair->base_is_native, buyer_is_net_collector,
                          net_fee, &buyer_spends_quote, &buyer_gets_base);
        
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
            .target_addr = get_wallet_addr(f, ctx->tmpl->seller),
            .token = buy_token,
            .tampered_value = dap_chain_coins_to_balance("99999.0")
        };
        if (test_dex_tamper_and_verify_rejection(f, tx_template, buyer_wallet,
                tamper_inflate_output, &tamper_data, "Inflate seller payout") != 0) {
            dap_chain_datum_tx_delete(tx_template);
            return -2;
        }
        
        // Security tamper tests: transfer funds between OUTs (balance preserved, should fail DEX verifier)
        const char *svc_fee_token = (ctx->tmpl->side == SIDE_ASK) ? buy_token : sell_token;
        tamper_transfer_data_t transfer_ctx = {
            .seller_addr = seller_addr,
            .buyer_addr = buyer_addr,
            .net_addr = net_fee_addr,
            .srv_addr = &f->carol_addr,
            .native_ticker = "TestCoin",
            .buy_ticker = buy_token,
            .sell_ticker = sell_token,
            .fee_ticker = svc_fee_token,
            .transfer_amount = dap_chain_coins_to_balance("1.0")
        };
        
        // T1: Steal from seller payout to net_fee (skip if seller == net_collector)
        if (!seller_is_net_collector) {
            transfer_ctx.source = TAMPER_OUT_SELLER_PAYOUT;
            transfer_ctx.destination = TAMPER_OUT_NET_FEE;
            if (test_dex_tamper_and_verify_rejection(f, tx_template, buyer_wallet, tamper_transfer_funds, &transfer_ctx, "Steal seller→net_fee") != 0) {
                dap_chain_datum_tx_delete(tx_template);
                return -30;
            }
        }
        
        // T2: Steal from seller payout to service_fee (skip if seller == srv_addr)
        if (!seller_is_service) {
            transfer_ctx.source = TAMPER_OUT_SELLER_PAYOUT;
            transfer_ctx.destination = TAMPER_OUT_SRV_FEE;
            if (test_dex_tamper_and_verify_rejection(f, tx_template, buyer_wallet, tamper_transfer_funds, &transfer_ctx, "Steal seller→srv_fee") != 0) {
                dap_chain_datum_tx_delete(tx_template);
                return -31;
            }
        }
        
        // T3-T6: Seller ↔ Buyer transfers (self-purchase forbidden, so seller != buyer always)
        {
            // T3: Steal from seller payout to validator_fee
            transfer_ctx.source = TAMPER_OUT_SELLER_PAYOUT;
            transfer_ctx.destination = TAMPER_OUT_VALIDATOR_FEE;
            if (test_dex_tamper_and_verify_rejection(f, tx_template, buyer_wallet, tamper_transfer_funds, &transfer_ctx, "Steal seller→validator_fee") != 0) {
                dap_chain_datum_tx_delete(tx_template);
                return -32;
            }
            
            // T4: Steal from buyer payout to net_fee (skip if buyer == net_collector)
            if (!buyer_is_net_collector) {
                transfer_ctx.source = TAMPER_OUT_BUYER_PAYOUT;
                transfer_ctx.destination = TAMPER_OUT_NET_FEE;
                if (test_dex_tamper_and_verify_rejection(f, tx_template, buyer_wallet, tamper_transfer_funds, &transfer_ctx, "Steal buyer→net_fee") != 0) {
                    dap_chain_datum_tx_delete(tx_template);
                    return -33;
                }
            }
        
            // T5/T6: Seller↔Buyer transfer
            // T5: Steal from seller payout to buyer (buyer gets extra)
            transfer_ctx.source = TAMPER_OUT_SELLER_PAYOUT;
            transfer_ctx.destination = TAMPER_OUT_BUYER_CASHBACK;
            if (test_dex_tamper_and_verify_rejection(f, tx_template, buyer_wallet, tamper_transfer_funds, &transfer_ctx, "Steal seller→buyer") != 0) {
                dap_chain_datum_tx_delete(tx_template);
                return -34;
            }
            
            // T6: Steal from buyer payout to seller (seller gets extra)
            transfer_ctx.source = TAMPER_OUT_BUYER_PAYOUT;
            transfer_ctx.destination = TAMPER_OUT_SELLER_PAYOUT;
            if (test_dex_tamper_and_verify_rejection(f, tx_template, buyer_wallet, tamper_transfer_funds, &transfer_ctx, "Steal buyer→seller") != 0) {
                dap_chain_datum_tx_delete(tx_template);
                return -35;
            }
        }
        
        // Snapshot BEFORE
        uint256_t buyer_base_before = dap_ledger_calc_balance(f->net->net->pub.ledger, buyer_addr, sell_token);
        uint256_t buyer_quote_before = dap_ledger_calc_balance(f->net->net->pub.ledger, buyer_addr, buy_token);
        uint256_t seller_quote_before = dap_ledger_calc_balance(f->net->net->pub.ledger, seller_addr, buy_token);
        uint256_t net_collector_before = dap_ledger_calc_balance(f->net->net->pub.ledger, net_fee_addr, "TestCoin");
        uint256_t carol_svc_before = dap_ledger_calc_balance(f->net->net->pub.ledger, &f->carol_addr, svc_fee_token);
        
        // Add TX
        dap_hash_fast_t purchase_hash = {0};
        dap_hash_fast(tx_template, dap_chain_datum_tx_get_size(tx_template), &purchase_hash);
        if (dap_ledger_tx_add(f->net->net->pub.ledger, tx_template, &purchase_hash, false, NULL) != 0) {
            dap_chain_datum_tx_delete(tx_template);
            return -3;
        }
        
        // Snapshot AFTER
        uint256_t buyer_base_after = dap_ledger_calc_balance(f->net->net->pub.ledger, buyer_addr, sell_token);
        uint256_t buyer_quote_after = dap_ledger_calc_balance(f->net->net->pub.ledger, buyer_addr, buy_token);
        uint256_t seller_quote_after = dap_ledger_calc_balance(f->net->net->pub.ledger, seller_addr, buy_token);
        uint256_t net_collector_after = dap_ledger_calc_balance(f->net->net->pub.ledger, net_fee_addr, "TestCoin");
        uint256_t carol_svc_after = dap_ledger_calc_balance(f->net->net->pub.ledger, &f->carol_addr, svc_fee_token);
        
        // Verify deltas
        if (test_dex_verify_delta("Buyer BASE", buyer_base_before, buyer_base_after, buyer_gets_base, false) != 0)
            return -20;
        if (test_dex_verify_delta("Buyer QUOTE", buyer_quote_before, buyer_quote_after, buyer_spends_quote, true) != 0)
            return -21;
        if (test_dex_verify_delta("Seller QUOTE", seller_quote_before, seller_quote_after, seller_gets_quote, false) != 0)
            return -22;
        
        // Verify net fee collector received network_fee (unless buyer is net collector)
        if (!buyer_is_net_collector && !seller_is_net_collector) {
            if (test_dex_verify_delta("Net collector fee", net_collector_before, net_collector_after, net_fee, false) != 0)
                return -23;
        }
        // Verify Carol received service_fee (unless seller is Carol - then it's aggregated)
        if (service_fee > 0 && !seller_is_service) {
            if (test_dex_verify_delta("Carol service_fee", carol_svc_before, carol_svc_after, service_fee, false) != 0)
                return -24;
        }
        
        log_it(L_NOTICE, "✓ Valid purchase accepted");
        
        // Rollback
        if (sc->do_rollback) {
            dap_chain_datum_tx_t *tx_for_remove = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &purchase_hash);
            if (dap_ledger_tx_remove(f->net->net->pub.ledger, tx_for_remove, &purchase_hash) != 0)
                return -4;
            
            uint256_t buyer_base_restored = dap_ledger_calc_balance(f->net->net->pub.ledger, buyer_addr, sell_token);
            uint256_t buyer_quote_restored = dap_ledger_calc_balance(f->net->net->pub.ledger, buyer_addr, buy_token);
            
            if (test_dex_verify_delta("Buyer BASE rollback", buyer_base_before, buyer_base_restored, 0, false) != 0)
                return -25;
            if (test_dex_verify_delta("Buyer QUOTE rollback", buyer_quote_before, buyer_quote_restored, 0, false) != 0)
                return -26;
            
            log_it(L_NOTICE, "✓ Rollback successful");
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
        
        const char *sell_token, *buy_token;
        get_order_tokens(ctx->pair, ctx->tmpl->side, &sell_token, &buy_token);
        const dap_chain_addr_t *buyer_addr = get_wallet_addr(f, buyer_id);
        const dap_chain_addr_t *seller_addr = get_wallet_addr(f, ctx->tmpl->seller);
        
        // Expected deltas (ASK vs BID have different fee logic)
        const uint128_t POW18 = 1000000000000000000ULL;
        const uint128_t POW36 = POW18 * POW18;
        
        uint128_t order_val = dap_uint256_to_uint128(order->value);
        uint128_t rate = dap_uint256_to_uint128(order->price);
        uint128_t net_fee = dap_uint256_to_uint128(f->network_fee);
        uint128_t service_fee = 0;
        uint128_t buyer_gets_base, buyer_spends_quote, seller_gets_quote;
        
        // Determine net_fee collector before calculating deltas
        const dap_chain_addr_t *net_fee_addr = test_get_net_fee_addr(f);
        bool buyer_is_net_collector = dap_chain_addr_compare(buyer_addr, net_fee_addr);
        bool seller_is_net_collector = dap_chain_addr_compare(seller_addr, net_fee_addr);
        
        if (ctx->tmpl->side == SIDE_ASK) {
            // ASK: seller sells BASE, buyer pays QUOTE + svc_fee
            seller_gets_quote = (order_val * rate) / POW18;
            if (ctx->pair->fee_config & 0x80)
                service_fee = (seller_gets_quote * (ctx->pair->fee_config & 0x7F)) / 100;
            buyer_gets_base = order_val;
            buyer_spends_quote = seller_gets_quote + service_fee;
            // When seller = net_fee_collector and QUOTE is native, seller also receives net_fee
            if (seller_is_net_collector && ctx->pair->quote_is_native)
                seller_gets_quote += net_fee;
        } else {
            // BID: rate is now canonical (QUOTE/BASE), no inversion needed
            uint128_t exec_sell = (order_val * POW18) / rate;
            seller_gets_quote = exec_sell;
            if (ctx->pair->fee_config & 0x80)
                service_fee = (order_val * (ctx->pair->fee_config & 0x7F)) / 100;
            buyer_gets_base = order_val - service_fee;
            buyer_spends_quote = exec_sell;
            // When seller = net_fee_collector and BASE is native, seller also receives net_fee
            if (seller_is_net_collector && ctx->pair->base_is_native)
                seller_gets_quote += net_fee;
        }
        
        adjust_native_fee(ctx->tmpl->side, ctx->pair->quote_is_native, ctx->pair->base_is_native, buyer_is_net_collector,
                          net_fee, &buyer_spends_quote, &buyer_gets_base);
        
        // Snapshots
        balance_snap_t buyer_before, buyer_after, seller_before, seller_after, net_coll_before, net_coll_after;
        test_dex_snap_take_pair(f->net->net->pub.ledger, buyer_addr, ctx->pair, &buyer_before);
        test_dex_snap_take_pair(f->net->net->pub.ledger, seller_addr, ctx->pair, &seller_before);
        test_dex_snap_take_pair(f->net->net->pub.ledger, net_fee_addr, ctx->pair, &net_coll_before);
        
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
        
        // Verify balances
        test_dex_snap_take_pair(f->net->net->pub.ledger, buyer_addr, ctx->pair, &buyer_after);
        test_dex_snap_take_pair(f->net->net->pub.ledger, seller_addr, ctx->pair, &seller_after);
        test_dex_snap_take_pair(f->net->net->pub.ledger, net_fee_addr, ctx->pair, &net_coll_after);
        
        // ASK: buyer gets BASE, spends QUOTE; BID: buyer spends BASE, gets QUOTE
        uint128_t buyer_base_delta, buyer_quote_delta, seller_base_delta, seller_quote_delta;
        bool buyer_base_dec, buyer_quote_dec;
        if (ctx->tmpl->side == SIDE_ASK) {
            buyer_base_delta = buyer_gets_base;  buyer_base_dec = false;
            buyer_quote_delta = buyer_spends_quote;  buyer_quote_dec = true;
            seller_base_delta = (seller_is_net_collector && ctx->pair->base_is_native) ? net_fee : 0;
            seller_quote_delta = seller_gets_quote;
        } else {
            buyer_base_delta = buyer_spends_quote;  buyer_base_dec = true;
            buyer_quote_delta = buyer_gets_base;  buyer_quote_dec = false;
            seller_base_delta = seller_gets_quote;
            seller_quote_delta = (seller_is_net_collector && ctx->pair->quote_is_native) ? net_fee : 0;
        }
        if (test_dex_snap_verify("AON Buyer", &buyer_before, &buyer_after, buyer_base_delta, buyer_base_dec, buyer_quote_delta, buyer_quote_dec) != 0)
            return -60;
        if (test_dex_snap_verify("AON Seller", &seller_before, &seller_after, seller_base_delta, false, seller_quote_delta, false) != 0)
            return -61;
        // Net fee: skip if buyer == net_collector (same address, fees already in buyer's costs)
        if (!buyer_is_net_collector && !seller_is_net_collector) {
            if (test_dex_snap_verify_fee("AON Net", &net_coll_before, &net_coll_after, net_fee, false) != 0)
                return -62;
        }
        log_it(L_NOTICE, "✓ AON full buy accepted (balances verified)");
        
        // Rollback
        dap_chain_datum_tx_t *tx_for_remove = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &full_hash);
        if (dap_ledger_tx_remove(f->net->net->pub.ledger, tx_for_remove, &full_hash) != 0) {
            log_it(L_ERROR, "AON full buy rollback failed");
            return -7;
        }
        
        // Verify rollback
        test_dex_snap_take_pair(f->net->net->pub.ledger, buyer_addr, ctx->pair, &buyer_after);
        if (test_dex_snap_verify("AON rollback", &buyer_before, &buyer_after, 0, false, 0, false) != 0)
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
    
    // Step 3: Valid partial at min_fill boundary
    uint8_t valid_pct = pct + 5;  // e.g. 50% min_fill → try 55%
    uint256_t valid_base, valid_quote;
    if (ctx->tmpl->side == SIDE_ASK) {
        valid_base = calc_pct(exec_sell_full, valid_pct);  // exec_sell_full computed above
        MULT_256_COIN(valid_base, order->price, &valid_quote);
    } else {
        valid_base = calc_pct(exec_sell_full, valid_pct);
        valid_quote = calc_pct(order->value, valid_pct);
    }
    
    // Expected deltas (ASK vs BID have different fee logic)
    const uint128_t POW18 = 1000000000000000000ULL;
    const uint128_t POW36 = POW18 * POW18;
    bool seller_is_service = (ctx->tmpl->seller == WALLET_CAROL);
    
    // Determine net_fee collector before calculating deltas
    const dap_chain_addr_t *net_fee_addr = test_get_net_fee_addr(f);
    bool buyer_is_net_collector = dap_chain_addr_compare(buyer_addr, net_fee_addr);
    bool seller_is_net_collector = dap_chain_addr_compare(seller_addr, net_fee_addr);
    
    // For expected delta calculations:
    // Step 3a uses is_budget_buy=true: budget in token buyer WANTS
    //   ASK: buyer wants BASE → partial_val = valid_base
    //   BID: buyer wants QUOTE → partial_val = valid_quote
    uint128_t partial_val = (ctx->tmpl->side == SIDE_ASK)
        ? dap_uint256_to_uint128(valid_base)
        : dap_uint256_to_uint128(valid_quote);
    uint128_t rate = dap_uint256_to_uint128(order->price);
    uint128_t net_fee = dap_uint256_to_uint128(f->network_fee);
    uint128_t service_fee = 0;
    // Variable naming is historical: for BID these represent different tokens
    // ASK: buyer_gets_base=BASE, buyer_spends_quote=QUOTE, seller_gets_quote=QUOTE
    // BID: buyer_gets_base→QUOTE, buyer_spends_quote→BASE, seller_gets_quote→BASE
    uint128_t buyer_gets_base, buyer_spends_quote, seller_gets_quote;
    
    if (ctx->tmpl->side == SIDE_ASK) {
        seller_gets_quote = (partial_val * rate) / POW18;
        if (ctx->pair->fee_config & 0x80)
            service_fee = (seller_gets_quote * (ctx->pair->fee_config & 0x7F)) / 100;
        buyer_gets_base = partial_val;
        buyer_spends_quote = seller_gets_quote + service_fee;
        if (seller_is_service)
            seller_gets_quote += service_fee;
        if (seller_is_net_collector && ctx->pair->quote_is_native)
            seller_gets_quote += net_fee;
    } else {
        // BID with QUOTE budget (is_budget_buy=true): exec_quote = budget (exact), exec_sell = budget / rate
        // Matcher stores exact exec_quote, no round-trip needed
        uint128_t exec_quote = partial_val;  // QUOTE budget directly (exact!)
        uint128_t exec_sell = (exec_quote * POW18) / rate;  // BASE = QUOTE / rate
        seller_gets_quote = exec_sell;  // Seller gets BASE (named _quote for historical reasons)
        if (ctx->pair->fee_config & 0x80)
            service_fee = (exec_quote * (ctx->pair->fee_config & 0x7F)) / 100;
        buyer_gets_base = exec_quote - service_fee;  // Buyer gets QUOTE minus fee
        buyer_spends_quote = exec_sell;  // Buyer spends BASE
        if (seller_is_net_collector && ctx->pair->base_is_native)
            seller_gets_quote += net_fee;
    }
    
    adjust_native_fee(ctx->tmpl->side, ctx->pair->quote_is_native, ctx->pair->base_is_native, buyer_is_net_collector,
                      net_fee, &buyer_spends_quote, &buyer_gets_base);
    
    // API: is_budget_buy=true means token buyer wants (ASK: BASE, BID: QUOTE)
    uint256_t budget_buy_valid = (ctx->tmpl->side == SIDE_ASK) ? valid_base : valid_quote;
    
    // Snapshots
    balance_snap_t buyer_before, buyer_after, seller_before, seller_after, net_coll_before, net_coll_after;
    
    // Step 3a: Valid partial in BUY token
    log_it(L_INFO, "--- Valid partial %d%% in BUY token ---", valid_pct);
    test_dex_snap_take_pair(f->net->net->pub.ledger, buyer_addr, ctx->pair, &buyer_before);
    test_dex_snap_take_pair(f->net->net->pub.ledger, seller_addr, ctx->pair, &seller_before);
    test_dex_snap_take_pair(f->net->net->pub.ledger, net_fee_addr, ctx->pair, &net_coll_before);
    
    err = dap_chain_net_srv_dex_purchase(f->net->net, &order->tail, budget_buy_valid, true,
                                          f->network_fee, buyer_wallet, false, uint256_0, &tx);
    if (err != DEX_PURCHASE_ERROR_OK || !tx) {
        log_it(L_ERROR, "Valid partial (BASE) failed: err=%d", err);
        return -5;
    }
    
    // Security tamper tests for OUT_COND SRV_DEX fields
    // T7: Set blank order_root_hash (should have head hash) → reject
    if (test_dex_tamper_and_verify_rejection(f, tx, buyer_wallet,
            tamper_order_root_hash, NULL, "Blank order_root_hash in partial") != 0) {
        dap_chain_datum_tx_delete(tx);
        return -70;
    }
    
    // T8: Set wrong order_root_hash (random) → reject
    {
        dap_hash_fast_t fake_hash;
        memset(&fake_hash, 0xCD, sizeof(fake_hash));  // Non-matching fake hash
        if (test_dex_tamper_and_verify_rejection(f, tx, buyer_wallet,
                tamper_order_root_hash, &fake_hash, "Wrong order_root_hash in partial") != 0) {
            dap_chain_datum_tx_delete(tx);
            return -71;
        }
    }
    
    // T9: Change tx_type from EXCHANGE to ORDER → reject
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
    
    // Verify balances (use pair tokens for consistent base=KEL, quote=USDT)
    test_dex_snap_take_pair(f->net->net->pub.ledger, buyer_addr, ctx->pair, &buyer_after);
    test_dex_snap_take_pair(f->net->net->pub.ledger, seller_addr, ctx->pair, &seller_after);
    test_dex_snap_take_pair(f->net->net->pub.ledger, net_fee_addr, ctx->pair, &net_coll_after);
    
    // ASK: buyer gets BASE, spends QUOTE; BID: buyer gets QUOTE, spends BASE
    uint128_t buyer_base_delta, buyer_quote_delta, seller_base_delta, seller_quote_delta;
    bool buyer_base_dec, buyer_quote_dec;
    if (ctx->tmpl->side == SIDE_ASK) {
        buyer_base_delta = buyer_gets_base;  buyer_base_dec = false;
        buyer_quote_delta = buyer_spends_quote;  buyer_quote_dec = true;
        seller_base_delta = (seller_is_net_collector && ctx->pair->base_is_native) ? net_fee : 0;
        seller_quote_delta = seller_gets_quote;  // already includes service_fee if seller_is_service
    } else {
        // BID: buyer spends BASE (KEL), gets QUOTE (USDT)
        buyer_base_delta = buyer_spends_quote;  buyer_base_dec = true;   // KEL spent
        buyer_quote_delta = buyer_gets_base;  buyer_quote_dec = false;   // USDT received
        seller_base_delta = seller_gets_quote;  // KEL received
        uint128_t extra_quote = (seller_is_net_collector && ctx->pair->quote_is_native) ? net_fee : 0;
        seller_quote_delta = (seller_is_service ? service_fee : 0) + extra_quote;
    }
    if (test_dex_snap_verify("Partial Buyer", &buyer_before, &buyer_after, buyer_base_delta, buyer_base_dec, buyer_quote_delta, buyer_quote_dec) != 0)
        return -50;
    if (test_dex_snap_verify("Partial Seller", &seller_before, &seller_after, seller_base_delta, false, seller_quote_delta, false) != 0)
        return -51;
    // Net fee: skip if buyer == net_collector (same address, fees already in buyer's costs)
    if (!buyer_is_net_collector && !seller_is_net_collector) {
        if (test_dex_snap_verify_fee("Partial Net", &net_coll_before, &net_coll_after, net_fee, false) != 0)
            return -52;
    }
    log_it(L_NOTICE, "✓ Valid partial (BASE) accepted (balances verified)");
    
    // Rollback
    dap_chain_datum_tx_t *tx_for_remove = dap_ledger_tx_find_by_hash(f->net->net->pub.ledger, &partial_hash);
    if (dap_ledger_tx_remove(f->net->net->pub.ledger, tx_for_remove, &partial_hash) != 0) {
        log_it(L_ERROR, "Rollback failed");
        return -7;
    }
    
    test_dex_snap_take_pair(f->net->net->pub.ledger, buyer_addr, ctx->pair, &buyer_after);
    if (test_dex_snap_verify("Partial rollback", &buyer_before, &buyer_after, 0, false, 0, false) != 0)
        return -55;
    log_it(L_NOTICE, "✓ Rolled back for QUOTE test");
    
    // Step 3b: Valid partial in SELL token (is_budget_buy=false: budget in token buyer SELLS)
    // ASK: buyer sells QUOTE → valid_quote
    // BID: buyer sells BASE → valid_base (needs canonical correction!)
    uint256_t budget_sell_valid = (ctx->tmpl->side == SIDE_ASK) ? valid_quote : valid_base;
    
    // Recalculate deltas for SELL token budget (different from BUY token budget in Step 3a)
    if (ctx->tmpl->side == SIDE_BID) {
        // BID with BASE budget: apply canonical correction (same as composer)
        // budget = valid_base (BASE), exec_quote = budget * rate, exec_sell_canonical = exec_quote / rate
        uint128_t budget_base = dap_uint256_to_uint128(valid_base);
        uint128_t exec_quote = (budget_base * rate) / POW18;  // round-trip step 1
        uint128_t exec_sell_canonical = (exec_quote * POW18) / rate;  // round-trip step 2 (canonical)
        seller_gets_quote = exec_sell_canonical;
        service_fee = 0;
        if (ctx->pair->fee_config & 0x80)
            service_fee = (exec_quote * (ctx->pair->fee_config & 0x7F)) / 100;
        buyer_gets_base = exec_quote - service_fee;
        buyer_spends_quote = exec_sell_canonical;
        if (seller_is_net_collector && ctx->pair->base_is_native)
            seller_gets_quote += net_fee;
        // Recalculate deltas for BID with QUOTE budget
        buyer_base_delta = buyer_spends_quote;  buyer_base_dec = true;
        buyer_quote_delta = buyer_gets_base;  buyer_quote_dec = false;
        seller_base_delta = seller_gets_quote;
        uint128_t extra_quote_3b = (seller_is_net_collector && ctx->pair->quote_is_native) ? net_fee : 0;
        seller_quote_delta = (seller_is_service ? service_fee : 0) + extra_quote_3b;
        adjust_native_fee(ctx->tmpl->side, ctx->pair->quote_is_native, ctx->pair->base_is_native, buyer_is_net_collector,
                          net_fee, &buyer_spends_quote, &buyer_gets_base);
        // Update buyer deltas after fee adjustment
        buyer_base_delta = buyer_spends_quote;
        buyer_quote_delta = buyer_gets_base;
    }
    // ASK with QUOTE budget: same calculation as Step 3a (no correction needed)
    
    log_it(L_INFO, "--- Valid partial %d%% in SELL token ---", valid_pct);
    test_dex_snap_take_pair(f->net->net->pub.ledger, buyer_addr, ctx->pair, &buyer_before);
    test_dex_snap_take_pair(f->net->net->pub.ledger, seller_addr, ctx->pair, &seller_before);
    test_dex_snap_take_pair(f->net->net->pub.ledger, net_fee_addr, ctx->pair, &net_coll_before);
    
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
    
    // Verify balances (use pair tokens)
    test_dex_snap_take_pair(f->net->net->pub.ledger, buyer_addr, ctx->pair, &buyer_after);
    test_dex_snap_take_pair(f->net->net->pub.ledger, seller_addr, ctx->pair, &seller_after);
    test_dex_snap_take_pair(f->net->net->pub.ledger, net_fee_addr, ctx->pair, &net_coll_after);
    
    if (test_dex_snap_verify("PartialQ Buyer", &buyer_before, &buyer_after, buyer_base_delta, buyer_base_dec, buyer_quote_delta, buyer_quote_dec) != 0)
        return -56;
    if (test_dex_snap_verify("PartialQ Seller", &seller_before, &seller_after, seller_base_delta, false, seller_quote_delta, false) != 0)
        return -57;
    // Net fee: skip if buyer == net_collector (same address)
    if (!buyer_is_net_collector && !seller_is_net_collector) {
        if (test_dex_snap_verify_fee("PartialQ Net", &net_coll_before, &net_coll_after, net_fee, false) != 0)
            return -58;
    }
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
    
    // Expected deltas for Step 1 (ASK vs BID have different fee logic)
    const uint128_t POW18 = 1000000000000000000ULL;
    const uint128_t POW36 = POW18 * POW18;
    
    // Determine net_fee collector before calculating deltas
    const dap_chain_addr_t *net_fee_addr = test_get_net_fee_addr(f);
    bool buyer_is_net_collector = dap_chain_addr_compare(buyer_addr, net_fee_addr);
    bool seller_is_net_collector = dap_chain_addr_compare(seller_addr, net_fee_addr);
    
    uint128_t partial_val = dap_uint256_to_uint128(partial_amount);
    uint128_t rate = dap_uint256_to_uint128(order->price);
    uint128_t net_fee = dap_uint256_to_uint128(f->network_fee);
    uint128_t service_fee = 0;
    uint128_t buyer_gets_base, buyer_spends_quote, seller_gets_quote;
    
    if (ctx->tmpl->side == SIDE_ASK) {
        seller_gets_quote = (partial_val * rate) / POW18;
        if (ctx->pair->fee_config & 0x80)
            service_fee = (seller_gets_quote * (ctx->pair->fee_config & 0x7F)) / 100;
        buyer_gets_base = partial_val;
        buyer_spends_quote = seller_gets_quote + service_fee;
        if (seller_is_net_collector && ctx->pair->quote_is_native)
            seller_gets_quote += net_fee;
    } else {
        // BID PARTIAL: rate is now canonical (QUOTE/BASE), no inversion needed
        uint128_t exec_sell = (partial_val * POW18) / rate;  // BASE = QUOTE / rate
        uint128_t exec_quote = (exec_sell * rate) / POW18;   // QUOTE = BASE * rate
        seller_gets_quote = exec_sell;
        if (ctx->pair->fee_config & 0x80)
            service_fee = (exec_quote * (ctx->pair->fee_config & 0x7F)) / 100;
        buyer_gets_base = exec_quote - service_fee;
        buyer_spends_quote = exec_sell;
        if (seller_is_net_collector && ctx->pair->base_is_native)
            seller_gets_quote += net_fee;
    }
    
    adjust_native_fee(ctx->tmpl->side, ctx->pair->quote_is_native, ctx->pair->base_is_native, buyer_is_net_collector,
                      net_fee, &buyer_spends_quote, &buyer_gets_base);
    
    // -------------------------------------------------------------------------
    // Step 1: Partial buy to create sub-minfill leftover
    // -------------------------------------------------------------------------
    log_it(L_INFO, "--- Step 1: Partial %d%% (%s) → leftover %d%% ---",
           partial_pct, dap_uint256_to_char_ex(partial_amount).frac, leftover_pct);
    
    balance_snap_t buyer_before, buyer_after, seller_before, seller_after, net_coll_before, net_coll_after;
    test_dex_snap_take_pair(f->net->net->pub.ledger, buyer_addr, ctx->pair, &buyer_before);
    test_dex_snap_take_pair(f->net->net->pub.ledger, seller_addr, ctx->pair, &seller_before);
    test_dex_snap_take_pair(f->net->net->pub.ledger, net_fee_addr, ctx->pair, &net_coll_before);
    
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
    
    // Verify balances
    test_dex_snap_take_pair(f->net->net->pub.ledger, buyer_addr, ctx->pair, &buyer_after);
    test_dex_snap_take_pair(f->net->net->pub.ledger, seller_addr, ctx->pair, &seller_after);
    test_dex_snap_take_pair(f->net->net->pub.ledger, net_fee_addr, ctx->pair, &net_coll_after);
    
    // ASK: buyer gets BASE, spends QUOTE; BID: buyer spends BASE, gets QUOTE
    uint128_t buyer_base_delta, buyer_quote_delta, seller_base_delta, seller_quote_delta;
    bool buyer_base_dec, buyer_quote_dec;
    if (ctx->tmpl->side == SIDE_ASK) {
        buyer_base_delta = buyer_gets_base;  buyer_base_dec = false;
        buyer_quote_delta = buyer_spends_quote;  buyer_quote_dec = true;
        seller_base_delta = (seller_is_net_collector && ctx->pair->base_is_native) ? net_fee : 0;
        seller_quote_delta = seller_gets_quote;
    } else {
        buyer_base_delta = buyer_spends_quote;  buyer_base_dec = true;
        buyer_quote_delta = buyer_gets_base;  buyer_quote_dec = false;
        seller_base_delta = seller_gets_quote;
        seller_quote_delta = (seller_is_net_collector && ctx->pair->quote_is_native) ? net_fee : 0;
    }
    if (test_dex_snap_verify("SubMF Buyer", &buyer_before, &buyer_after, buyer_base_delta, buyer_base_dec, buyer_quote_delta, buyer_quote_dec) != 0)
        return -20;
    if (test_dex_snap_verify("SubMF Seller", &seller_before, &seller_after, seller_base_delta, false, seller_quote_delta, false) != 0)
        return -21;
    // Net fee: skip if buyer == net_collector (same address)
    if (!buyer_is_net_collector && !seller_is_net_collector) {
        if (test_dex_snap_verify_fee("SubMF Net", &net_coll_before, &net_coll_after, net_fee, false) != 0)
            return -22;
    }
    
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
    
    // Expected deltas for full buy of leftover (ASK vs BID)
    uint128_t left_val = dap_uint256_to_uint128(leftover_value);
    uint128_t left_svc_fee = 0;
    uint128_t left_buyer_gets, left_buyer_spends, left_seller_gets;
    
    if (ctx->tmpl->side == SIDE_ASK) {
        left_seller_gets = (left_val * rate) / POW18;
        if (ctx->pair->fee_config & 0x80)
            left_svc_fee = (left_seller_gets * (ctx->pair->fee_config & 0x7F)) / 100;
        left_buyer_gets = left_val;
        left_buyer_spends = left_seller_gets + left_svc_fee;
        if (seller_is_net_collector && ctx->pair->quote_is_native)
            left_seller_gets += net_fee;
    } else {
        // BID: rate is now canonical (QUOTE/BASE), no inversion needed
        uint128_t exec_sell = (left_val * POW18) / rate;  // BASE = QUOTE / rate
        left_seller_gets = exec_sell;
        if (ctx->pair->fee_config & 0x80)
            left_svc_fee = (left_val * (ctx->pair->fee_config & 0x7F)) / 100;
        left_buyer_gets = left_val - left_svc_fee;
        left_buyer_spends = exec_sell;
        if (seller_is_net_collector && ctx->pair->base_is_native)
            left_seller_gets += net_fee;
    }
    
    adjust_native_fee(ctx->tmpl->side, ctx->pair->quote_is_native, ctx->pair->base_is_native, buyer_is_net_collector,
                      net_fee, &left_buyer_spends, &left_buyer_gets);
    
    test_dex_snap_take_pair(f->net->net->pub.ledger, buyer_addr, ctx->pair, &buyer_before);
    test_dex_snap_take_pair(f->net->net->pub.ledger, seller_addr, ctx->pair, &seller_before);
    test_dex_snap_take_pair(f->net->net->pub.ledger, net_fee_addr, ctx->pair, &net_coll_before);
    
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
    
    // Verify balances
    test_dex_snap_take_pair(f->net->net->pub.ledger, buyer_addr, ctx->pair, &buyer_after);
    test_dex_snap_take_pair(f->net->net->pub.ledger, seller_addr, ctx->pair, &seller_after);
    test_dex_snap_take_pair(f->net->net->pub.ledger, net_fee_addr, ctx->pair, &net_coll_after);
    
    // ASK: buyer gets BASE, spends QUOTE; BID: buyer spends BASE, gets QUOTE
    uint128_t b_base_delta, b_quote_delta, s_base_delta, s_quote_delta;
    bool b_base_dec, b_quote_dec;
    if (ctx->tmpl->side == SIDE_ASK) {
        b_base_delta = left_buyer_gets;  b_base_dec = false;
        b_quote_delta = left_buyer_spends;  b_quote_dec = true;
        s_base_delta = (seller_is_net_collector && ctx->pair->base_is_native) ? net_fee : 0;
        s_quote_delta = left_seller_gets;
    } else {
        b_base_delta = left_buyer_spends;  b_base_dec = true;
        b_quote_delta = left_buyer_gets;  b_quote_dec = false;
        s_base_delta = left_seller_gets;
        s_quote_delta = (seller_is_net_collector && ctx->pair->quote_is_native) ? net_fee : 0;
    }
    if (test_dex_snap_verify("SubMF Full Buyer", &buyer_before, &buyer_after, b_base_delta, b_base_dec, b_quote_delta, b_quote_dec) != 0)
        return -90;
    if (test_dex_snap_verify("SubMF Full Seller", &seller_before, &seller_after, s_base_delta, false, s_quote_delta, false) != 0)
        return -91;
    // Net fee: skip if buyer == net_collector (same address)
    if (!buyer_is_net_collector && !seller_is_net_collector) {
        if (test_dex_snap_verify_fee("SubMF Full Net", &net_coll_before, &net_coll_after, net_fee, false) != 0)
            return -92;
    }
    
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
    
    log_it(L_NOTICE, "✓ All UPDATE tampering tests passed");
    
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
    uint128_t effective_fee = seller_is_net_collector ? net_fee : (2 * net_fee);
    
    // BASE: delta + effective_fee if sell=native, else just delta
    uint128_t expected_base = sell_is_native ? (delta_128 + effective_fee) : delta_128;
    // QUOTE: effective_fee if buy=native, else 0
    uint128_t expected_quote = buy_is_native ? effective_fee : 0;
    bool quote_decrease = buy_is_native;
    
    if (test_dex_snap_verify("Update Untouched", &seller_before, &seller_after,
                             expected_base, true, expected_quote, quote_decrease) != 0) {
        log_it(L_ERROR, "UPDATE balance verification failed");
        return -3;
    }
    
    // Update context for next phases
    ctx->order_hash = update_hash;
    ctx->order.value = new_value;
    
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
    uint128_t effective_fee = seller_is_net_collector ? net_fee : (2 * net_fee);
    
    // BASE: refund - effective_fee if sell=native, else full refund
    uint128_t base_fee = sell_is_native ? effective_fee : 0;
    uint128_t expected_base = (decrease_128 > base_fee) ? (decrease_128 - base_fee) : 0;
    // QUOTE: effective_fee if buy=native, else 0
    uint128_t expected_quote = buy_is_native ? effective_fee : 0;
    bool quote_decrease = buy_is_native;
    
    if (expected_base > 0 || expected_quote > 0) {
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
    uint128_t effective_fee = seller_is_net_collector ? net_fee : (2 * net_fee);
    
    // BASE: refund - effective_fee if sell=native, else full refund
    uint128_t base_fee = sell_is_native ? effective_fee : 0;
    uint128_t expected_base = (value_128 > base_fee) ? (value_128 - base_fee) : 0;
    // QUOTE: effective_fee if buy=native, else 0
    uint128_t expected_quote = buy_is_native ? effective_fee : 0;
    bool quote_decrease = buy_is_native;
    
    if (expected_base > 0 || expected_quote > 0) {
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
    uint128_t effective_fee = seller_is_net_collector ? net_fee : (2 * net_fee);
    
    // BASE: refund - effective_fee if sell=native, else full refund
    uint128_t base_fee = sell_is_native ? effective_fee : 0;
    uint128_t expected_base = (value_128 > base_fee) ? (value_128 - base_fee) : 0;
    // QUOTE: effective_fee if buy=native, else 0
    uint128_t expected_quote = buy_is_native ? effective_fee : 0;
    bool quote_decrease = buy_is_native;
    
    if (expected_base > 0 || expected_quote > 0) {
        if (test_dex_snap_verify("Cancel Untouched", &seller_before, &seller_after,
                                 expected_base, false, expected_quote, quote_decrease) != 0) {
            log_it(L_ERROR, "CANCEL untouched balance verification failed");
            return -3;
        }
    }
    
    // Order is now cancelled - clear context
    memset(&ctx->order, 0, sizeof(ctx->order));
    memset(&ctx->order_hash, 0, sizeof(ctx->order_hash));
    
    log_it(L_NOTICE, "✓ CANCEL UNTOUCHED COMPLETE");
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
        .order = {0},
        .pair_idx = pair_idx,
        .tmpl_idx = tmpl_idx
    };
    
    log_it(L_NOTICE, "");
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
    log_it(L_NOTICE, "");
    log_it(L_NOTICE, "╔══════════════════════════════════════════════════════════╗");
    log_it(L_NOTICE, "║          DEX LIFECYCLE TESTS                             ║");
    log_it(L_NOTICE, "╚══════════════════════════════════════════════════════════╝");
    
    const test_pair_config_t *pairs = test_get_standard_pairs();
    size_t pairs_count = test_get_standard_pairs_count();
    
    size_t passed = 0;
    
    // Iterate over network fee collector configurations
    for (net_fee_collector_t nfc = NET_FEE_DAVE; nfc <= NET_FEE_BOB; nfc++) {
        test_set_net_fee_collector(f, nfc);
        
        log_it(L_NOTICE, "");
        log_it(L_NOTICE, "╔══════════════════════════════════════════════════════════╗");
        log_it(L_NOTICE, "║  NET FEE COLLECTOR: %s", get_net_fee_collector_name(nfc));
        log_it(L_NOTICE, "╚══════════════════════════════════════════════════════════╝");
        
        for (size_t p = 0; p < pairs_count; p++) {
            log_it(L_NOTICE, "");
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
    log_it(L_NOTICE, "");
    log_it(L_NOTICE, "╔══════════════════════════════════════════════════════════╗");
    log_it(L_NOTICE, "║  ✓ ALL %zu LIFECYCLE TESTS PASSED                        ║", passed);
    log_it(L_NOTICE, "╚══════════════════════════════════════════════════════════╝");
    return 0;
}

