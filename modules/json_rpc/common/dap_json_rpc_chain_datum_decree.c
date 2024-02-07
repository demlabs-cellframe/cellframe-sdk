
#include "dap_json_rpc_chain_datum_decree.h"
#include "json.h"


#define LOG_TAG "dap_json_rpc_chain_datum_decree"

json_object *s_dap_chain_datum_decree_certs_dump_json(byte_t * a_signs, size_t a_certs_size){
    json_object *l_jobj_signatures = json_object_new_array();
    if (!l_jobj_signatures) {
        dap_json_rpc_allocation_error;
        return NULL;
    }
    size_t l_offset = 0;
    for (int i = 1; l_offset < (a_certs_size); i++) {
        json_object *l_jobj_signature = json_object_new_object();
        if (!l_jobj_signature) {
            json_object_put(l_jobj_signatures);
            dap_json_rpc_allocation_error;
            return NULL;
        }
        dap_sign_t *l_sign = (dap_sign_t *) (a_signs + l_offset);
        l_offset += dap_sign_get_size(l_sign);
        if (l_sign->header.sign_size == 0) {
            json_object *l_wrn_text = json_object_new_string("<CORRUPTED - 0 size signature>");
            if(!l_wrn_text) {
                json_object_put(l_jobj_signature);
                json_object_put(l_jobj_signatures);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object_object_add(l_jobj_signature, "warning", l_wrn_text);
            continue;
        }

        dap_chain_hash_fast_t l_pkey_hash = {0};
        if (dap_sign_get_pkey_hash(l_sign, &l_pkey_hash) == false) {
            json_object *l_wrn_text = json_object_new_string("<CORRUPTED - can't calc hash>");
            if (!l_wrn_text){
                json_object_put(l_jobj_signature);
                json_object_put(l_jobj_signatures);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object_object_add(l_jobj_signature, "warning", l_wrn_text);
            continue;
        }
        json_object *l_jobj_hash_str = json_object_new_string(dap_chain_hash_fast_to_str_static(&l_pkey_hash));
        if (!l_jobj_hash_str) {
            json_object_put(l_jobj_signature);
            json_object_put(l_jobj_signatures);
            dap_json_rpc_allocation_error;
            return NULL;
        }
        json_object *l_jobj_type_str = json_object_new_string(dap_sign_type_to_str(l_sign->header.type));
        if (!l_jobj_type_str) {
            json_object_put(l_jobj_hash_str);
            json_object_put(l_jobj_signature);
            json_object_put(l_jobj_signatures);
            dap_json_rpc_allocation_error;
            return NULL;
        }
        json_object *l_jobj_sign_size = json_object_new_uint64(l_sign->header.sign_size);
        if (!l_jobj_sign_size) {
            json_object_put(l_jobj_hash_str);
            json_object_put(l_jobj_type_str);
            json_object_put(l_jobj_signature);
            json_object_put(l_jobj_signatures);
            dap_json_rpc_allocation_error;
            return NULL;
        }
        json_object_object_add(l_jobj_signature, "hash", l_jobj_hash_str);
        json_object_object_add(l_jobj_signature, "type", l_jobj_type_str);
        json_object_object_add(l_jobj_signature, "size", l_jobj_sign_size);
        json_object_array_add(l_jobj_signatures, l_jobj_signature);
    }
    return l_jobj_signatures;
}

json_object *dap_chain_datum_decree_to_json(dap_chain_datum_decree_t *a_decree){
    json_object *l_jobj_decree = json_object_new_object();
    if (!l_jobj_decree) {
        dap_json_rpc_allocation_error;
        return NULL;
    }
    char *l_type_str = "";
    switch(a_decree->header.type)
    {
        case DAP_CHAIN_DATUM_DECREE_TYPE_COMMON:
            l_type_str = "DECREE_TYPE_COMMON";
            break;
        case DAP_CHAIN_DATUM_DECREE_TYPE_SERVICE:
            l_type_str = "DECREE_TYPE_SERVICE";
            break;
        default:
            l_type_str = "DECREE_TYPE_UNKNOWN";
    }
    json_object *l_jobj_type = json_object_new_string(l_type_str);
    if (!l_jobj_type) {
        json_object_put(l_jobj_decree);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    const char *l_subtype_str = dap_chain_datum_decree_subtype_to_str(a_decree->header.sub_type);
    json_object *l_json_subtype = json_object_new_string(l_subtype_str);
    if (!l_json_subtype) {
        json_object_put(l_jobj_type);
        json_object_put(l_jobj_decree);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_json_tsd_array = json_object_new_array();
    if (!l_json_tsd_array){
        json_object_put(l_json_subtype);
        json_object_put(l_jobj_type);
        json_object_put(l_jobj_decree);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    for (size_t l_offset = 0; l_offset < a_decree->header.data_size;) {
        dap_tsd_t *l_tsd = (dap_tsd_t *)((byte_t*)a_decree->data_n_signs + l_offset);
        l_offset += dap_tsd_size(l_tsd);
        json_object *l_jobj_tsd = json_object_new_object();
        if (!l_jobj_tsd) {
            json_object_put(l_json_tsd_array);
            json_object_put(l_json_subtype);
            json_object_put(l_jobj_type);
            json_object_put(l_jobj_decree);
            dap_json_rpc_allocation_error;
            return NULL;
        }
        switch(l_tsd->type) {
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGN: {
                json_object *l_obj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGN");
                if (!l_obj_tsd_type) {
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_obj_tsd_type);
            } break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE: {
                json_object *l_obj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE");
                if (!l_obj_tsd_type) {
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_obj_tsd_type);
                if (l_tsd->size > sizeof(uint256_t)) {
                    json_object *l_text_wgn = json_object_new_string("Fee: <WRONG SIZE>");
                    if (!l_text_wgn) {
                        json_object_put(l_json_tsd_array);
                        json_object_put(l_json_subtype);
                        json_object_put(l_jobj_type);
                        json_object_put(l_jobj_decree);
                        json_object_put(l_jobj_tsd);
                        dap_json_rpc_allocation_error;
                        return NULL;
                    }
                    json_object_object_add(l_jobj_tsd, "warning", l_text_wgn);
                    break;
                }
                uint256_t l_fee_value = uint256_0;
                json_object *l_jobj_fee = json_object_new_string(dap_chain_balance_print(l_fee_value));
                if (!l_jobj_fee) {
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "value", l_jobj_fee);
            } break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER: {
                json_object *l_obj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER");
                if (!l_obj_tsd_type){
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_obj_tsd_type);
                if (l_tsd->size < sizeof(dap_pkey_t)) {
                    json_object *l_text_wgn = json_object_new_string("Owner fingerprint: <WRONG SIZE>");
                    if (!l_text_wgn){
                        json_object_put(l_json_tsd_array);
                        json_object_put(l_json_subtype);
                        json_object_put(l_jobj_type);
                        json_object_put(l_jobj_decree);
                        json_object_put(l_jobj_tsd);
                        dap_json_rpc_allocation_error;
                        return NULL;
                    }
                    json_object_object_add(l_jobj_tsd, "warning", l_text_wgn);
                    break;
                }
                dap_pkey_t *l_owner_pkey = DAP_NEW_Z_SIZE(dap_pkey_t, l_tsd->size);
                if(!l_owner_pkey) {
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                memcpy(l_owner_pkey, l_tsd->data, l_tsd->size);
                dap_hash_fast_t l_owner_pkey_hash = {0};
                dap_hash_fast(l_owner_pkey->pkey, l_owner_pkey->header.size, &l_owner_pkey_hash);
                char l_owner_pkey_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_chain_hash_fast_to_str(&l_owner_pkey_hash, l_owner_pkey_str, sizeof(l_owner_pkey_str));
                json_object *l_jobj_owner_pkey = json_object_new_string(l_owner_pkey_str);
                if (!l_jobj_owner_pkey) {
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "owner_fingerprint", l_jobj_owner_pkey);
                DAP_DELETE(l_owner_pkey);
            } break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER: {
                json_object *l_obj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER");
                if (!l_obj_tsd_type){
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_obj_tsd_type);
                if (l_tsd->size > sizeof(uint256_t)){
                    json_object *l_text_wgn = json_object_new_string("Owner min: <WRONG SIZE>");
                    if (!l_text_wgn) {
                        json_object_put(l_json_tsd_array);
                        json_object_put(l_json_subtype);
                        json_object_put(l_jobj_type);
                        json_object_put(l_jobj_decree);
                        json_object_put(l_jobj_tsd);
                        dap_json_rpc_allocation_error;
                        return NULL;
                    }
                    json_object_object_add(l_jobj_tsd, "warning", l_text_wgn);
                    break;
                }
                uint256_t l_owner_min = {0};
                _dap_tsd_get_scalar(l_tsd, &l_owner_min);
                json_object *l_jobj_owner_min = json_object_new_string(dap_chain_balance_print(l_owner_min));
                if (!l_jobj_owner_min) {
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "owner_min", l_jobj_owner_min);
            } break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE_WALLET: {
                json_object *l_obj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE_WALLET");
                if (!l_obj_tsd_type) {
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_obj_tsd_type);
                if (l_tsd->size > sizeof(dap_chain_addr_t)) {
                    json_object *l_text_wgn = json_object_new_string("Wallet for fee: <WRONG SIZE>");
                    if (!l_text_wgn) {
                        json_object_put(l_json_tsd_array);
                        json_object_put(l_json_subtype);
                        json_object_put(l_jobj_type);
                        json_object_put(l_jobj_decree);
                        json_object_put(l_jobj_tsd);
                        dap_json_rpc_allocation_error;
                        return NULL;
                    }
                    json_object_object_add(l_jobj_tsd, "warning", l_text_wgn);
                    break;
                }
                dap_chain_addr_t l_addr_fee_wallet = { };
                _dap_tsd_get_scalar(l_tsd, &l_addr_fee_wallet);
                json_object *l_jobj_addr_fee_wallet = json_object_new_string(dap_chain_addr_to_str(&l_addr_fee_wallet));
                if (!l_jobj_addr_fee_wallet) {
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "addr", l_jobj_addr_fee_wallet);
            } break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_TX_HASH: {
                json_object *l_obj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_TX_HASH");
                json_object_object_add(l_jobj_tsd, "type", l_obj_tsd_type);
                if (l_tsd->size > sizeof(dap_hash_fast_t)) {
                    json_object *l_text_wgn = json_object_new_string("Stake tx: <WRONG SIZE>");
                    json_object_object_add(l_jobj_tsd, "warning", l_text_wgn);
                    break;
                }
                dap_hash_fast_t l_stake_tx = {0};
                _dap_tsd_get_scalar(l_tsd, &l_stake_tx);
                char *l_stake_tx_hash = dap_chain_hash_fast_to_str_new(&l_stake_tx);
                if (!l_stake_tx_hash) {
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object *l_jobj_tx_hash = json_object_new_string(l_stake_tx_hash);
                DAP_DELETE(l_stake_tx_hash);
                if (!l_jobj_tx_hash) {
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "hash", l_jobj_tx_hash);
//                char *l_stake_tx_hash = dap_strcmp(a_hash_out_type, "hex")
//                                        ? dap_enc_base58_encode_hash_to_str(&l_stake_tx)
//                                        : dap_chain_hash_fast_to_str_new(&l_stake_tx);
//                dap_string_append_printf(a_str_out, "\tStake tx: %s\n", l_stake_tx_hash);
            } break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_VALUE: {
                json_object *l_obj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_VALUE");
                if (!l_obj_tsd_type){
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_obj_tsd_type);
                if (l_tsd->size > sizeof(uint256_t)) {
                    json_object *l_text_wgn = json_object_new_string("Stake value: <WRONG SIZE>");
                    if (!l_text_wgn){
                        json_object_put(l_json_tsd_array);
                        json_object_put(l_json_subtype);
                        json_object_put(l_jobj_type);
                        json_object_put(l_jobj_decree);
                        json_object_put(l_jobj_tsd);
                        dap_json_rpc_allocation_error;
                        return NULL;
                    }
                    json_object_object_add(l_jobj_tsd, "warning", l_text_wgn);
                    break;
                }
                uint256_t l_stake_value = uint256_0;
                _dap_tsd_get_scalar(l_tsd, &l_stake_value);
                json_object *l_jobj_stake_value = json_object_new_string(dap_chain_balance_print(l_stake_value));
                if (!l_jobj_stake_value){
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "value", l_jobj_stake_value);
            } break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNING_ADDR: {
                json_object *l_obj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNING_ADDR");
                json_object_object_add(l_jobj_tsd, "type", l_obj_tsd_type);
                if (l_tsd->size > sizeof(dap_chain_addr_t)) {
                    json_object *l_text_wgn = json_object_new_string("Signing addr: <WRONG SIZE>");
                    json_object_object_add(l_jobj_tsd, "warning", l_text_wgn);
                    break;
                }
                dap_chain_addr_t l_stake_addr_signing = { };
                _dap_tsd_get_scalar(l_tsd, &l_stake_addr_signing);

                json_object *l_jobj_stake_addr_signing = json_object_new_string(dap_chain_addr_to_str(&l_stake_addr_signing));
                if (!l_jobj_stake_addr_signing) {
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                dap_chain_hash_fast_t l_pkey_signing = l_stake_addr_signing.data.hash_fast;
                json_object *l_jobj_pkey_signing = json_object_new_string(dap_chain_hash_fast_to_str_static(&l_pkey_signing));
                if (!l_jobj_pkey_signing) {
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "addr", l_jobj_stake_addr_signing);
                json_object_object_add(l_jobj_tsd, "pkey", l_jobj_pkey_signing);
//                char *l_pkey_signing_str = dap_strcmp(a_hash_out_type, "hex")
//                                           ? dap_enc_base58_encode_hash_to_str(l_pkey_signing)
//                                           : dap_chain_hash_fast_to_str_new(l_pkey_signing);
//                dap_string_append_printf(a_str_out, "\tSigning pkey fingerprint: %s\n", l_pkey_signing_str);
            } break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNER_NODE_ADDR: {
                json_object *l_obj_tsd_type = json_object_new_string(
                        "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNER_NODE_ADDR");
                if (!l_obj_tsd_type) {
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_obj_tsd_type);
                if(l_tsd->size > sizeof(dap_chain_node_addr_t)){
                    json_object *l_text_wgn = json_object_new_string("Node addr: <WRONG SIZE>");
                    if (!l_text_wgn){
                        json_object_put(l_json_tsd_array);
                        json_object_put(l_json_subtype);
                        json_object_put(l_jobj_type);
                        json_object_put(l_jobj_decree);
                        json_object_put(l_jobj_tsd);
                        dap_json_rpc_allocation_error;
                        return NULL;
                    }
                    json_object_object_add(l_jobj_tsd, "warning", l_text_wgn);
                    break;
                }
                dap_chain_node_addr_t l_node_addr = {0};
                _dap_tsd_get_scalar(l_tsd, &l_node_addr);
                char *l_node_addr_str = dap_strdup_printf(NODE_ADDR_FP_STR,NODE_ADDR_FP_ARGS_S(l_node_addr));
                if (!l_node_addr_str) {
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object *l_jobj_node_addr = json_object_new_string(l_node_addr_str);
                DAP_DELETE(l_node_addr_str);
                if (!l_jobj_node_addr){
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "node", l_jobj_node_addr);
            } break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_VALUE: {
                json_object *l_obj_tsd_type = json_object_new_string(
                        "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_VALUE");
                json_object_object_add(l_jobj_tsd, "type", l_obj_tsd_type);
                if (l_tsd->size > sizeof(uint256_t)) {
                    json_object *l_text_wgn = json_object_new_string("Min value: <WRONG SIZE>");
                    json_object_object_add(l_jobj_tsd, "warning", l_text_wgn);
                    break;
                }
                uint256_t l_min_value = uint256_0;
                _dap_tsd_get_scalar(l_tsd, &l_min_value);
                json_object *l_jobj_min_value = json_object_new_string(dap_chain_balance_print(l_min_value));
                json_object_object_add(l_jobj_tsd, "value", l_jobj_min_value);
            } break;
            case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_SIGNERS_COUNT: {
                json_object *l_obj_tsd_type = json_object_new_string(
                        "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_SIGNERS_COUNT");
                if (!l_obj_tsd_type) {
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_obj_tsd_type);
                if (l_tsd->size > sizeof(uint256_t)) {
                    json_object *l_text_wgn = json_object_new_string("Min signers count: <WRONG SIZE>");
                    if(!l_text_wgn){
                        json_object_put(l_json_tsd_array);
                        json_object_put(l_json_subtype);
                        json_object_put(l_jobj_type);
                        json_object_put(l_jobj_decree);
                        json_object_put(l_jobj_tsd);
                        dap_json_rpc_allocation_error;
                        return NULL;
                    }
                    json_object_object_add(l_jobj_tsd, "warning", l_text_wgn);
                    break;
                }
                uint256_t l_min_signers_count = uint256_0;
                _dap_tsd_get_scalar(l_tsd, &l_min_signers_count);
                json_object *l_jobj_min_signers_count = json_object_new_string(dap_chain_balance_print(l_min_signers_count));
                if (!l_jobj_min_signers_count) {
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "count", l_jobj_min_signers_count);
            } break;
            default: {
                json_object *l_obj_tsd_type = json_object_new_string(
                        "<UNKNOWN_TYPE_TSD_SECTION>");
                if (!l_obj_tsd_type){
                    json_object_put(l_json_tsd_array);
                    json_object_put(l_json_subtype);
                    json_object_put(l_jobj_type);
                    json_object_put(l_jobj_decree);
                    json_object_put(l_jobj_tsd);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_obj_tsd_type);
            } break;
        }
        json_object_array_add(l_json_tsd_array, l_jobj_tsd);
    }
    json_object *l_jobj_signs = s_dap_chain_datum_decree_certs_dump_json(a_decree->data_n_signs + a_decree->header.data_size,
                                                                         a_decree->header.signs_size);
    if (!l_jobj_signs){
        json_object_put(l_json_tsd_array);
        json_object_put(l_json_subtype);
        json_object_put(l_jobj_type);
        json_object_put(l_jobj_decree);
        dap_json_rpc_error_add(DAP_JSON_RPC_ERR_CODE_SERIALIZATION_SIGN_TO_JSON, "Can't serialize the decree signature in JSON.");
        return NULL;
    }
    json_object_object_add(l_jobj_decree, "type", l_jobj_type);
    json_object_object_add(l_jobj_decree, "subtype", l_json_subtype);
    json_object_object_add(l_jobj_decree, "TSD", l_json_tsd_array);
    json_object_object_add(l_jobj_decree, "signs", l_jobj_signs);
    return l_jobj_decree;
}
