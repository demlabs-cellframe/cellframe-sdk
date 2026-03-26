/**
 * @file dex_test_helpers.c
 * @brief Implementation of shared DEX test helpers
 */

#include "dex_test_helpers.h"
#include "dap_chain_wallet_internal.h"

// ============================================================================
// TX MANIPULATION
// ============================================================================

bool dex_test_tamper_ts_created(dap_chain_datum_tx_t *tx, void *user_data) {
    if (!tx || !user_data)
        return false;
    dap_time_t new_ts = *(dap_time_t*)user_data;
    tx->header.ts_created = new_ts;
    return true;
}

int dex_test_resign_tx(dap_chain_datum_tx_t **a_tx, dap_chain_wallet_t *wallet) {
    dap_return_val_if_fail(a_tx && *a_tx && wallet, -1);
    
    uint8_t *l_first_sig = dap_chain_datum_tx_item_get(*a_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
    size_t l_tx_size_without_sigs = l_first_sig
        ? (size_t)(l_first_sig - (uint8_t*)*a_tx)
        : dap_chain_datum_tx_get_size(*a_tx);
    
    dap_chain_datum_tx_t *l_new_tx = DAP_DUP_SIZE(*a_tx, l_tx_size_without_sigs);
    dap_return_val_if_fail(l_new_tx, -2);
    l_new_tx->header.tx_items_size = l_tx_size_without_sigs - sizeof(dap_chain_datum_tx_t);
    
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(wallet, 0);
    dap_return_val_if_fail(l_key, -3);
    if (dap_chain_datum_tx_add_sign_item(&l_new_tx, l_key) <= 0) {
        DAP_DELETE(l_key);
        dap_chain_datum_tx_delete(l_new_tx);
        return -4;
    }
    DAP_DELETE(l_key);
    dap_chain_datum_tx_delete(*a_tx);
    *a_tx = l_new_tx;
    return 0;
}

bool dex_test_tamper_inflate_output(dap_chain_datum_tx_t *tx, void *user_data) {
    dex_tamper_output_data_t *data = (dex_tamper_output_data_t*)user_data;
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

uint256_t *dex_test_find_out_value_ex(dap_chain_datum_tx_t *tx, dex_tamper_out_type_t type,
                                       const dex_tamper_transfer_data_t *ctx, uint256_t *skip_ptr) {
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

bool dex_test_tamper_transfer_funds(dap_chain_datum_tx_t *tx, void *user_data) {
    dex_tamper_transfer_data_t *data = (dex_tamper_transfer_data_t*)user_data;
    
    uint256_t *src_val = dex_test_find_out_value(tx, data->source, data);
    if (!src_val)
        return false;
    
    uint256_t *dst_val = dex_test_find_out_value_ex(tx, data->destination, data, src_val);
    if (!dst_val || src_val == dst_val)
        return false;
    
    if (compare256(*src_val, data->transfer_amount) < 0)
        return false;
    
    SUBTRACT_256_256(*src_val, data->transfer_amount, src_val);
    SUM_256_256(*dst_val, data->transfer_amount, dst_val);
    return true;
}

dap_chain_tx_out_cond_t *dex_test_find_dex_out_cond(dap_chain_datum_tx_t *tx) {
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

bool dex_test_tamper_order_root_hash(dap_chain_datum_tx_t *tx, void *user_data) {
    dap_hash_fast_t *new_hash = (dap_hash_fast_t*)user_data;
    dap_chain_tx_out_cond_t *out = dex_test_find_dex_out_cond(tx);
    if (!out)
        return false;
    
    if (new_hash)
        out->subtype.srv_dex.order_root_hash = *new_hash;
    else
        memset(&out->subtype.srv_dex.order_root_hash, 0, sizeof(dap_hash_fast_t));
    return true;
}

bool dex_test_tamper_tx_type(dap_chain_datum_tx_t *tx, void *user_data) {
    uint8_t *new_type = (uint8_t*)user_data;
    dap_chain_tx_out_cond_t *out = dex_test_find_dex_out_cond(tx);
    if (!out || !new_type)
        return false;
    
    out->subtype.srv_dex.tx_type = *new_type;
    return true;
}

bool dex_test_tamper_rate(dap_chain_datum_tx_t *tx, void *user_data) {
    uint256_t *new_rate = (uint256_t*)user_data;
    dap_chain_tx_out_cond_t *out = dex_test_find_dex_out_cond(tx);
    if (!out || !new_rate)
        return false;
    
    out->subtype.srv_dex.rate = *new_rate;
    return true;
}

bool dex_test_tamper_buy_token(dap_chain_datum_tx_t *tx, void *user_data) {
    const char *new_token = (const char*)user_data;
    dap_chain_tx_out_cond_t *out = dex_test_find_dex_out_cond(tx);
    if (!out || !new_token)
        return false;
    
    dap_strncpy(out->subtype.srv_dex.buy_token, new_token, sizeof(out->subtype.srv_dex.buy_token) - 1);
    return true;
}

bool dex_test_tamper_min_fill(dap_chain_datum_tx_t *tx, void *user_data) {
    uint8_t *new_min_fill = (uint8_t*)user_data;
    dap_chain_tx_out_cond_t *out = dex_test_find_dex_out_cond(tx);
    if (!out || !new_min_fill)
        return false;
    
    out->subtype.srv_dex.min_fill = *new_min_fill;
    return true;
}

// ============================================================================
// TX ANALYSIS HELPERS
// ============================================================================

int dex_test_count_in_cond(dap_chain_datum_tx_t *tx) {
    if (!tx) return 0;
    
    int count = 0;
    byte_t *it; size_t sz;
    TX_ITEM_ITER_TX(it, sz, tx) {
        if (*it == TX_ITEM_TYPE_IN_COND)
            count++;
    }
    return count;
}

int dex_test_get_sellers_from_tx(dap_chain_datum_tx_t *tx, dap_ledger_t *ledger,
                                  dex_test_seller_info_t *sellers, int max_count) {
    if (!tx || !ledger || !sellers || max_count <= 0)
        return -1;
    
    int count = 0;
    byte_t *it; size_t sz;
    TX_ITEM_ITER_TX(it, sz, tx) {
        if (*it != TX_ITEM_TYPE_IN_COND || count >= max_count)
            continue;
        
        dap_chain_tx_in_cond_t *in_cond = (dap_chain_tx_in_cond_t *)it;
        dap_chain_datum_tx_t *prev_tx = dap_ledger_tx_find_by_hash(ledger, &in_cond->header.tx_prev_hash);
        if (!prev_tx)
            continue;
        
        // Find DEX OUT_COND in prev_tx at specified index
        uint32_t out_idx = 0;
        byte_t *pit; size_t psz;
        TX_ITEM_ITER_TX(pit, psz, prev_tx) {
            if (*pit == TX_ITEM_TYPE_OUT_COND) {
                dap_chain_tx_out_cond_t *out = (dap_chain_tx_out_cond_t *)pit;
                if (out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX &&
                    out_idx == in_cond->header.tx_out_prev_idx) {
                    sellers[count].addr = out->subtype.srv_dex.seller_addr;
                    sellers[count].order_hash = in_cond->header.tx_prev_hash;
                    sellers[count].value = out->header.value;
                    count++;
                    break;
                }
                out_idx++;
            }
        }
    }
    return count;
}

uint256_t *dex_test_find_seller_payout(dap_chain_datum_tx_t *tx,
                                        const dap_chain_addr_t *seller_addr,
                                        const char *buy_token) {
    if (!tx || !seller_addr || !buy_token)
        return NULL;
    
    byte_t *it; size_t sz;
    TX_ITEM_ITER_TX(it, sz, tx) {
        if (*it == TX_ITEM_TYPE_OUT_STD) {
            dap_chain_tx_out_std_t *out = (dap_chain_tx_out_std_t *)it;
            if (dap_chain_addr_compare(&out->addr, seller_addr) &&
                !dap_strcmp(out->token, buy_token))
                return &out->value;
        }
    }
    return NULL;
}

// ============================================================================
// WALLET UTILITIES
// ============================================================================

dap_chain_wallet_t *dex_test_wallet_by_addr(dex_test_fixture_t *f, const dap_chain_addr_t *addr) {
    if (dap_chain_addr_compare(addr, &f->alice_addr))
        return f->alice;
    if (dap_chain_addr_compare(addr, &f->bob_addr))
        return f->bob;
    if (dap_chain_addr_compare(addr, &f->carol_addr))
        return f->carol;
    if (dap_chain_addr_compare(addr, &f->dave_addr))
        return f->dave;
    return NULL;
}



