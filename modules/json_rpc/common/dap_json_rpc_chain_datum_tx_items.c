#include <stdint.h>
#include <string.h>

#include "dap_common.h"
#include "dap_enc_key.h"
#include "dap_chain_common.h"
#include "dap_sign.h"
#include "dap_hash.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_in.h"
#include "dap_chain_datum_tx_out.h"
#include "dap_chain_datum_tx_in_cond.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_enc_base58.h"

#include "dap_json_rpc_chain_datum_tx_items.h"
#include "dap_json_rpc_chain_common.h"
#include "dap_json_rpc_sign.h"
#include "json.h"

#define LOG_TAG "dap_json_rpc_chain_datum_tx_items"

json_object *dap_chain_datum_tx_item_out_cond_srv_pay_to_json(dap_chain_tx_out_cond_t *item) {
        char *l_coins_str,
             *l_value_str = dap_uint256_to_char(((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.unit_price_max_datoshi, &l_coins_str);
        char *l_hash_str = dap_enc_base58_encode_hash_to_str_static(&((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.pkey_hash);
        json_object *l_obj = json_object_new_object();
        char unit_str[32];
        snprintf(unit_str, 32, "0x%08x", ((dap_chain_tx_out_cond_t*)item)->subtype.srv_pay.unit.uint32);
        json_object_object_add(l_obj, "unit", json_object_new_string(unit_str));
        json_object_object_add(l_obj, "pkey", json_object_new_string(l_hash_str));
        json_object_object_add(l_obj, "max_price", json_object_new_string(l_coins_str));
        json_object_object_add(l_obj, "max_price_datoshi", json_object_new_string(l_value_str));
        return l_obj;
}

json_object* dap_chain_datum_tx_item_out_cond_srv_xchange_to_json(dap_chain_tx_out_cond_t* a_srv_xchange) {
    if (a_srv_xchange->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE){
        json_object *l_object = json_object_new_object();
        json_object_object_add(l_object, "value", json_object_new_string(dap_uint256_to_char(a_srv_xchange->header.value, NULL)));
        json_object_object_add(l_object, "rate", ( { 
            char *l_rate; dap_uint256_to_char(a_srv_xchange->subtype.srv_xchange.rate, &l_rate);
            json_object_new_string(l_rate); } ));
        json_object_object_add(l_object, "srv_uid", json_object_new_uint64(a_srv_xchange->header.srv_uid.uint64));
        json_object_object_add(l_object, "buy_net_id", dap_chain_net_id_to_json(a_srv_xchange->subtype.srv_xchange.buy_net_id));
        json_object_object_add(l_object, "sell_net_id", dap_chain_net_id_to_json(a_srv_xchange->subtype.srv_xchange.sell_net_id));
        json_object_object_add(l_object, "buy_token", json_object_new_string(a_srv_xchange->subtype.srv_xchange.buy_token));
        json_object_object_add(l_object, "seller_addr", dap_chain_addr_to_json(&a_srv_xchange->subtype.srv_xchange.seller_addr));
        //TODO: Parse TSD
        return l_object;
    }
    return NULL;
}

json_object *dap_chain_datum_tx_item_out_cond_srv_stake_to_json(dap_chain_tx_out_cond_t* a_srv_stake) {
    if (a_srv_stake->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE) {
        json_object *l_object = json_object_new_object();
        json_object *l_obj_value = json_object_new_string(dap_uint256_to_char(a_srv_stake->header.value, NULL));
        json_object *l_obj_srv_uid = json_object_new_uint64(a_srv_stake->header.srv_uid.uint64);
        json_object *l_obj_signing_addr = dap_chain_addr_to_json(&a_srv_stake->subtype.srv_stake_pos_delegate.signing_addr);
        char *l_signer_node_addr = dap_strdup_printf(
                NODE_ADDR_FP_STR,
                NODE_ADDR_FP_ARGS_S(a_srv_stake->subtype.srv_stake_pos_delegate.signer_node_addr));
        json_object *l_obj_signer_node_addr = json_object_new_string(l_signer_node_addr);
        DAP_DELETE(l_signer_node_addr);
        json_object_object_add(l_object, "value", l_obj_value);
        json_object_object_add(l_object, "srv_uid", l_obj_srv_uid);
        json_object_object_add(l_object, "signind_addr", l_obj_signing_addr);
        json_object_object_add(l_object, "signer_node_addr", l_obj_signer_node_addr);
        return l_object;
    }
    return NULL;
}


json_object *dap_chain_net_srv_stake_lock_cond_out_to_json(dap_chain_tx_out_cond_t *a_stake_lock)
{
    if (a_stake_lock->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK) {
        json_object *l_object = json_object_new_object();
        json_object_object_add(l_object, "value", json_object_new_string(dap_uint256_to_char(a_stake_lock->header.value, NULL)));
        json_object_object_add(l_object, "srv_uid", json_object_new_uint64(a_stake_lock->header.srv_uid.uint64));
        json_object_object_add(l_object, "reinvest_percent",
            json_object_new_string(dap_uint256_to_char(a_stake_lock->subtype.srv_stake_lock.reinvest_percent, NULL)));
        json_object_object_add(l_object, "time_unlock", json_object_new_uint64(a_stake_lock->subtype.srv_stake_lock.time_unlock));
        json_object_object_add(l_object, "flags", json_object_new_uint64(a_stake_lock->subtype.srv_stake_lock.flags));
        return l_object;
    }
    return NULL;
}


json_object* dap_chain_datum_tx_item_out_to_json(const dap_chain_tx_out_t *a_out) {
    json_object *l_object = json_object_new_object();
    char *l_val_coins, *l_val_datoshi = dap_uint256_to_char(a_out->header.value, &l_val_coins);
    json_object_object_add(l_object, "value", json_object_new_string(l_val_coins));
    json_object_object_add(l_object, "value_datoshi", json_object_new_string(l_val_datoshi));
    json_object_object_add(l_object, "address", dap_chain_addr_to_json(&a_out->addr));
    return l_object;
}


json_object* dap_chain_datum_tx_item_out_ext_to_json(const dap_chain_tx_out_ext_t *a_out_ext) {
    json_object *l_obj = json_object_new_object();
    json_object_object_add(l_obj, "value", json_object_new_string(dap_uint256_to_char(a_out_ext->header.value, NULL)));
    json_object_object_add(l_obj, "addr", dap_chain_addr_to_json(&a_out_ext->addr));
    json_object_object_add(l_obj, "token", json_object_new_string(a_out_ext->token));
    return l_obj;
}

json_object* dap_chain_datum_tx_item_in_cond_to_json(dap_chain_tx_in_cond_t *a_in_cond){
    json_object *l_obj = json_object_new_object();
    if (!l_obj) {
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_receipt_idx = json_object_new_uint64(a_in_cond->header.receipt_idx);
    if (!l_obj_receipt_idx) {
        json_object_put(l_obj);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_out_prev_idx = json_object_new_uint64(a_in_cond->header.tx_out_prev_idx);
    if (!l_obj_out_prev_idx) {
        json_object_put(l_obj_receipt_idx);
        json_object_put(l_obj);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_prev_hash = NULL;
    if (dap_hash_fast_is_blank(&a_in_cond->header.tx_prev_hash)){
        l_obj_prev_hash = json_object_new_null();
    } else {
        char *l_prev_hash = dap_hash_fast_to_str_new(&a_in_cond->header.tx_prev_hash);
        if(!l_prev_hash) {
            json_object_put(l_obj_out_prev_idx);
            json_object_put(l_obj_receipt_idx);
            json_object_put(l_obj);
            dap_json_rpc_allocation_error;
            return NULL;
        }
        l_obj_prev_hash = json_object_new_string(dap_strdup(l_prev_hash));
        if (!l_obj_prev_hash) {
            json_object_put(l_obj_out_prev_idx);
            json_object_put(l_obj_receipt_idx);
            json_object_put(l_obj);
            DAP_DELETE(l_prev_hash);
            dap_json_rpc_allocation_error;
            return NULL;
        }
        DAP_DELETE(l_prev_hash);
    }
    json_object_object_add(l_obj, "receipt_idx", l_obj_receipt_idx);
    json_object_object_add(l_obj, "out_prev_idx", l_obj_out_prev_idx);
    json_object_object_add(l_obj, "tx_prev_hash", l_obj_prev_hash);
    return l_obj;
}

json_object* dap_chain_datum_tx_item_in_to_json(dap_chain_tx_in_t *a_in){
    json_object *l_obj_in = json_object_new_object();
    if (!l_obj_in) {
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_prev_idx = json_object_new_uint64(a_in->header.tx_out_prev_idx);
    if (!l_obj_prev_idx) {
        json_object_put(l_obj_in);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    char l_hash[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&a_in->header.tx_prev_hash, l_hash, sizeof(l_hash));
    json_object *l_obj_hash = json_object_new_string(l_hash);
    if (!l_obj_hash) {
        json_object_put(l_obj_in);
        json_object_put(l_obj_prev_idx);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object_object_add(l_obj_in, "prev_idx", l_obj_prev_idx);
    json_object_object_add(l_obj_in, "prev_hash", l_obj_hash);
    return l_obj_in;
}

json_object* dap_chain_datum_tx_item_in_reward_to_json(dap_chain_tx_in_reward_t *a_in_reward){
    json_object *l_jobj_ret = json_object_new_object();
    char *l_hash_block = dap_hash_fast_to_str_new(&a_in_reward->block_hash);
    if (!l_jobj_ret && !l_hash_block) {
        json_object_put(l_jobj_ret);
        DAP_DEL_Z(l_hash_block);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_jobj_block_hash = json_object_new_string(l_hash_block);
    DAP_DEL_Z(l_hash_block);
    if (!l_jobj_block_hash) {
        return NULL;
    }
    json_object_object_add(l_jobj_ret, "block_hash", l_jobj_block_hash);
    return l_jobj_ret;
}

json_object* dap_chain_datum_tx_item_tsd_to_json(dap_chain_tx_tsd_t *a_tsd){
    json_object *l_object = json_object_new_object();
    if (!l_object) {
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_tsd_type = json_object_new_int(a_tsd->header.type);
    if(!l_obj_tsd_type) {
        json_object_put(l_object);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_tsd_size = json_object_new_uint64(a_tsd->header.size);
    if (!l_obj_tsd_size) {
        json_object_put(l_obj_tsd_type);
        json_object_put(l_object);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_data = json_object_new_string_len((char *)a_tsd->tsd, a_tsd->header.size);
    if (!l_obj_data) {
        json_object_put(l_obj_tsd_size);
        json_object_put(l_obj_tsd_type);
        json_object_put(l_object);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object_object_add(l_object, "type", l_obj_tsd_type);
    json_object_object_add(l_object, "size", l_obj_tsd_size);
    json_object_object_add(l_object, "data", l_obj_data);
    return l_object;
}

json_object *dap_chain_datum_tx_item_in_ems_to_json(const dap_chain_tx_in_ems_t *a_in_ems)
{
    json_object *l_object = json_object_new_object();
    if (!l_object) {
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_ticker = json_object_new_string(a_in_ems->header.ticker);
    if (!l_obj_ticker){
        json_object_put(l_object);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_chain_id = json_object_new_uint64(a_in_ems->header.token_emission_chain_id.uint64);
    if (!l_obj_chain_id) {
        json_object_put(l_object);
        json_object_put(l_obj_ticker);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    char l_ehf[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&a_in_ems->header.token_emission_hash, l_ehf, sizeof(l_ehf));
    json_object *l_obj_ehf = json_object_new_string(l_ehf);
    if (!l_obj_ehf) {
        json_object_put(l_object);
        json_object_put(l_obj_chain_id);
        json_object_put(l_obj_ticker);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object_object_add(l_object, "ticker", l_obj_ticker);
    json_object_object_add(l_object, "chain_id", l_obj_chain_id);
    json_object_object_add(l_object, "emission_hash", l_obj_ehf);
    return l_object;
}

json_object *dap_chain_datum_tx_item_out_cond_fee_to_json(dap_chain_tx_out_cond_t *a_fee) {
    return a_fee->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE
        ? ( {
                json_object *l_obj = json_object_new_object();
                json_object_object_add(l_obj, "balance", json_object_new_string(dap_uint256_to_char(a_fee->header.value, NULL)));
                l_obj;
            } )
        : NULL;
}

json_object* dap_chain_datum_tx_item_sig_to_json(const dap_chain_tx_sig_t *a_sig){
    json_object *l_object = json_object_new_object();
    if (!l_object) {
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_sign_size = json_object_new_uint64(a_sig->header.sig_size);
    if (!l_sign_size) {
        json_object_put(l_object);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_sign = dap_sign_to_json((dap_sign_t*)a_sig->sig);
    if (!l_sign) {
        json_object_put(l_object);
        json_object_put(l_sign_size);
        dap_json_rpc_error_add(DAP_JSON_RPC_ERR_CODE_SERIALIZATION_SIGN_TO_JSON,
                               "Error serializing signature to JSON.");
        return NULL;
    }
    json_object_object_add(l_object, "sign_size", l_sign_size);
    json_object_object_add(l_object, "sign", l_sign);
    return l_object;
}
