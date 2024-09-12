
#include "dap_common.h"
#include "dap_time.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_datum_anchor.h"
#include "dap_chain_datum_hashtree_roots.h"
#include "dap_enc_base58.h"

#include "dap_json_rpc_chain_datum.h"
#include "dap_json_rpc_chain_datum_tx.h"
#include "dap_json_rpc_chain_datum_token.h"
#include "dap_json_rpc_chain_datum_anchor.h"
#include "dap_json_rpc_chain_datum_decree.h"
#include "json.h"

#define LOG_TAG "dap_json_rpc_chain_datum"

json_object *s_dap_chain_datum_token_tsd_to_json(dap_chain_datum_token_t *a_token, size_t a_token_size) {
    dap_tsd_t *l_tsd = dap_chain_datum_token_tsd_get(a_token, a_token_size);
    if (l_tsd == NULL) {
        json_object *l_tsd_wgn = json_object_new_object();
        if (!l_tsd_wgn){
            dap_json_rpc_allocation_error;
            return NULL;
        }
        json_object *l_tsd_wgn_warning = json_object_new_string("<CORRUPTED TSD SECTION>");
        if (!l_tsd_wgn_warning) {
            json_object_put(l_tsd_wgn);
            dap_json_rpc_allocation_error;
            return NULL;
        }
        json_object_object_add(l_tsd_wgn, "warning", l_tsd_wgn_warning);
        return l_tsd_wgn;
    }
    json_object *l_tsd_array = json_object_new_array();
    if (!l_tsd_array) {
        dap_json_rpc_allocation_error;
        return NULL;
    }
    size_t l_tsd_total_size = 0;
    switch (a_token->type) {
        case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL:
            switch (a_token->subtype) {
                case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
                    l_tsd_total_size = a_token->header_private_decl.tsd_total_size; break;
                case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
                    l_tsd_total_size = a_token->header_native_decl.tsd_total_size; break;
                default: break;
            } break;
        case DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE:
            switch (a_token->subtype) {
                case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE:
                    l_tsd_total_size = a_token->header_private_update.tsd_total_size; break;
                case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE:
                    l_tsd_total_size = a_token->header_native_update.tsd_total_size; break;
                default: break;
            } break;
        default: break;
    }
    size_t l_tsd_size = 0;
    for (size_t l_offset = 0; l_offset < l_tsd_total_size; l_offset += l_tsd_size) {
        json_object *l_jobj_tsd = json_object_new_object();
        l_tsd = (dap_tsd_t *) (((byte_t*)l_tsd) + l_tsd_size);
        l_tsd_size = l_tsd ? dap_tsd_size(l_tsd) : 0;
        if (l_tsd_size == 0) {
            json_object *l_wgn_text = json_object_new_string("Wrong zero TSD size, exiting s_datum_token_dump_tsd()");
            if (!l_wgn_text) {
                json_object_put(l_tsd_array);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object *l_wgn = json_object_new_object();
            if (!l_wgn) {
                json_object_put(l_wgn_text);
                json_object_put(l_tsd_array);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object_object_add(l_wgn, "error", l_wgn_text);
            json_object_array_add(l_tsd_array, l_wgn);
            break;
        } else if (l_tsd_size+l_offset > l_tsd_total_size) {
            char *l_wgn_str = dap_strdup_printf("<CORRUPTED TSD> too big size %u when left maximum %zu",
                                           l_tsd->size, l_tsd_total_size - l_offset);
            if (!l_wgn_str) {
                json_object_put(l_tsd_array);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object *l_wgn_text = json_object_new_string(l_wgn_str);
            DAP_DELETE(l_wgn_str);
            if (!l_wgn_text) {
                json_object_put(l_tsd_array);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object *l_wgn = json_object_new_object();
            if (!l_wgn) {
                json_object_put(l_wgn_text);
                json_object_put(l_tsd_array);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object_object_add(l_wgn, "error", l_wgn_text);
            json_object_array_add(l_tsd_array, l_wgn);
            break;
        }
        switch( l_tsd->type){
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_SET_FLAGS: {
                json_object *l_jobj_tsd = json_object_new_object();
                if (!l_jobj_tsd) {
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_SET_FLAGS");
                if (!l_jobj_tsd_type) {
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                uint16_t l_flags = 0;
                _dap_tsd_get_scalar(l_tsd, &l_flags);
                json_object *l_jobj_tsd_flag = dap_chain_datum_token_flags_to_json(l_flags);
                if (!l_jobj_tsd_flag) {
                    json_object_put(l_jobj_tsd_type);
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                json_object_object_add(l_jobj_tsd, "flags", l_jobj_tsd_flag);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            } continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS: {
                json_object *l_jobj_tsd = json_object_new_object();
                if (!l_jobj_tsd) {
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS");
                if (!l_jobj_tsd_type) {
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                uint16_t l_flags = 0;
                _dap_tsd_get_scalar(l_tsd, &l_flags);
                json_object *l_jobj_tsd_flag = dap_chain_datum_token_flags_to_json(l_flags);
                if (!l_jobj_tsd_flag) {
                    json_object_put(l_jobj_tsd_type);
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                json_object_object_add(l_jobj_tsd, "flags", l_jobj_tsd_flag);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            } continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY: { // 256
                json_object *l_jobj_tsd = json_object_new_object();
                if (!l_jobj_tsd) {
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY");
                if (!l_jobj_tsd_type) {
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                uint256_t l_balance_native = uint256_0;
                _dap_tsd_get_scalar(l_tsd, &l_balance_native);
                char *l_balance = dap_chain_balance_print(l_balance_native);
                if (!l_balance) {
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_jobj_tsd_type);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object *l_jobj_tsd_value = json_object_new_string(l_balance);
                DAP_DELETE(l_balance);
                if (!l_jobj_tsd_value) {
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_jobj_tsd_type);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                json_object_object_add(l_jobj_tsd, "value", l_jobj_tsd_value);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            } continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY_OLD: {// 128
                json_object *l_jobj_tsd = json_object_new_object();
                if (!l_jobj_tsd) {
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY_OLD");
                if (!l_jobj_tsd_type) {
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                uint128_t l_balance_native_old = uint128_0;
                _dap_tsd_get_scalar(l_tsd, &l_balance_native_old);
                char *l_balance = dap_chain_balance_print(GET_256_FROM_128(l_balance_native_old));
                if (!l_balance) {
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_jobj_tsd_type);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object *l_jobj_tsd_value = json_object_new_string(l_balance);
                DAP_DELETE(l_balance);
                if (!l_jobj_tsd_value) {
                    json_object_put(l_jobj_tsd_type);
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                json_object_object_add(l_jobj_tsd, "value", l_jobj_tsd_value);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            } continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID: {
                json_object *l_jobj_tsd = json_object_new_object();
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID");
                uint16_t l_flags = 0;
                _dap_tsd_get_scalar(l_tsd, &l_flags);
                json_object *l_jobj_value = json_object_new_uint64(l_flags);
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                json_object_object_add(l_jobj_tsd, "total_signs_valid", l_jobj_value);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            } continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_ADD: {
                json_object *l_jobj_tsd = json_object_new_object();
                if (!l_jobj_tsd) {
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_ADD");
                if (!l_jobj_tsd_type) {
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                if (l_tsd->size >= sizeof(dap_pkey_t)) {
                    dap_pkey_t *l_pkey = (dap_pkey_t *) l_tsd->data;
                    dap_hash_fast_t l_hf = {0};
                    if (!dap_pkey_get_hash(l_pkey, &l_hf)) {
                        json_object *l_wgn_text = json_object_new_string("total_pkeys_add: <WRONG CALCULATION FINGERPRINT>");
                        if (!l_wgn_text) {
                            json_object_put(l_jobj_tsd);
                            json_object_put(l_tsd_array);
                            dap_json_rpc_allocation_error;
                            return NULL;
                        }
                        json_object_object_add(l_jobj_tsd, "warning", l_wgn_text);
                    } else {
                        char *l_hash_str = dap_chain_hash_fast_to_str_new(&l_hf);
                        if (!l_hash_str) {
                            json_object_put(l_jobj_tsd);
                            json_object_put(l_tsd_array);
                            dap_json_rpc_allocation_error;
                            return NULL;
                        }
                        json_object *l_jobj_hash = json_object_new_string(l_hash_str);
                        DAP_DELETE(l_hash_str);
                        if (l_jobj_hash) {
                            json_object_put(l_jobj_tsd);
                            json_object_put(l_tsd_array);
                            dap_json_rpc_allocation_error;
                            return NULL;
                        }
                        json_object_object_add(l_jobj_tsd, "pkey", l_jobj_hash);
                    }
                } else {
                    char *l_wgn_text = dap_strdup_printf("total_pkeys_add: <WRONG SIZE %u>\n", l_tsd->size);
                    if (!l_wgn_text) {
                        json_object_put(l_jobj_tsd);
                        json_object_put(l_tsd_array);
                        dap_json_rpc_allocation_error;
                        return NULL;
                    }
                    json_object *l_jobj_wgn_text = json_object_new_string(l_wgn_text);
                    DAP_DELETE(l_wgn_text);
                    if (!l_jobj_wgn_text) {
                        json_object_put(l_jobj_tsd);
                        json_object_put(l_tsd_array);
                        dap_json_rpc_allocation_error;
                        return NULL;
                    }
                    json_object_object_add(l_jobj_tsd, "warning", l_jobj_wgn_text);
                }
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            } continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_REMOVE: {
                json_object *l_jobj_tsd = json_object_new_object();
                if (!l_jobj_tsd){
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_REMOVE");
                if (!l_jobj_tsd_type) {
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                if (l_tsd->size == sizeof(dap_chain_hash_fast_t)) {
                    char *l_hash_str = dap_chain_hash_fast_to_str_new((dap_chain_hash_fast_t *) l_tsd->data);
                    if (!l_hash_str) {
                        json_object_put(l_jobj_tsd);
                        json_object_put(l_tsd_array);
                        dap_json_rpc_allocation_error;
                        return NULL;
                    }
                    json_object *l_jobj_hash = json_object_new_string(l_hash_str);
                    DAP_DELETE(l_hash_str);
                    if (!l_jobj_hash) {
                        json_object_put(l_jobj_tsd);
                        json_object_put(l_tsd_array);
                        dap_json_rpc_allocation_error;
                        return NULL;
                    }
                    json_object_object_add(l_jobj_tsd, "pkey", l_jobj_hash);
                } else {
                    char *l_wgn_text = dap_strdup_printf("total_pkeys_remove: <WRONG SIZE %u>\n", l_tsd->size);
                    if (!l_wgn_text) {
                        json_object_put(l_jobj_tsd);
                        json_object_put(l_tsd_array);
                        dap_json_rpc_allocation_error;
                        return NULL;
                    }
                    json_object *l_jobj_wgn_text = json_object_new_string(l_wgn_text);
                    DAP_DELETE(l_wgn_text);
                    if (!l_jobj_wgn_text) {
                        json_object_put(l_jobj_tsd);
                        json_object_put(l_tsd_array);
                        dap_json_rpc_allocation_error;
                        return NULL;
                    }
                    json_object_object_add(l_jobj_tsd, "warning", l_jobj_wgn_text);
                }
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            } continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK: {
                json_object *l_jobj_tsd = json_object_new_object();
                if (!l_jobj_tsd) {
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK");
                if (!l_jobj_tsd_type) {
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                dap_chain_datum_token_tsd_delegate_from_stake_lock_t *l_tsd_section = _dap_tsd_get_object(l_tsd, dap_chain_datum_token_tsd_delegate_from_stake_lock_t);
                json_object *l_jobj_ticker_token_from = json_object_new_string((char*)l_tsd_section->ticker_token_from);
                char *balance = dap_chain_balance_to_coins(l_tsd_section->emission_rate);
                if (!l_jobj_ticker_token_from || !balance) {
                    json_object_put(l_jobj_ticker_token_from);
                    DAP_DEL_Z(balance);
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "ticker_token_from", l_jobj_ticker_token_from);
                json_object *l_jobj_emission_rate = json_object_new_string(balance);
                DAP_DEL_Z(balance);
                if (!l_jobj_emission_rate) {
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "emission_rate", l_jobj_emission_rate);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            } continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD: {
                json_object *l_jobj_tsd = json_object_new_object();
                if (!l_jobj_tsd) {
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD");
                if (!l_jobj_tsd_type) {
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                json_object *l_jobj_datum_type_allowed_add = json_object_new_string(dap_tsd_get_string_const(l_tsd));
                if (!l_jobj_datum_type_allowed_add) {
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "datum_type_allowed_add", l_jobj_datum_type_allowed_add);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            }continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_REMOVE: {
                json_object *l_jobj_tsd = json_object_new_object();
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_REMOVE");
                json_object *l_jobj_datum_type_allowed_remove = json_object_new_string(dap_tsd_get_string_const(l_tsd));
                if (!l_jobj_tsd || !l_jobj_tsd_type || !l_jobj_datum_type_allowed_remove) {
                    json_object_put(l_jobj_datum_type_allowed_remove);
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                json_object_object_add(l_jobj_tsd, "datum_type_allowed_remove", l_jobj_datum_type_allowed_remove);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            }continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_ADD: {
                json_object *l_jobj_tsd = json_object_new_object();
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_ADD");
                json_object *l_jobj_datum_type_blocked_add = json_object_new_string(dap_tsd_get_string_const(l_tsd));
                if (!l_jobj_tsd || !l_jobj_tsd_type || !l_jobj_datum_type_blocked_add) {
                    json_object_put(l_jobj_datum_type_blocked_add);
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                json_object_object_add(l_jobj_tsd, "datum_type_blocked_add", l_jobj_datum_type_blocked_add);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            } continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_REMOVE: {
                json_object *l_jobj_tsd = json_object_new_object();
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_REMOVE");
                json_object *l_jobj_datum_type_blocked_remove = json_object_new_string(dap_tsd_get_string_const(l_tsd));
                if (!l_jobj_tsd || !l_jobj_tsd_type || !l_jobj_datum_type_blocked_remove) {
                    json_object_put(l_jobj_datum_type_blocked_remove);
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                json_object_object_add(l_jobj_tsd, "datum_type_blocked_remove", l_jobj_datum_type_blocked_remove);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            } continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD: {
                json_object *l_jobj_tsd = json_object_new_object();
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD");
                json_object *l_jobj_tx_sender_allowed_add = json_object_new_string(dap_tsd_get_string_const(l_tsd));
                if (!l_jobj_tsd || !l_jobj_tsd_type || !l_jobj_tx_sender_allowed_add) {
                    json_object_put(l_jobj_tx_sender_allowed_add);
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                json_object_object_add(l_jobj_tsd, "tx_sender_allowed_add",l_jobj_tx_sender_allowed_add);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            } continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_REMOVE: {
                json_object *l_jobj_tsd = json_object_new_object();
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_REMOVE");
                json_object *l_jobj_tx_sender_allowed_remove = json_object_new_string(dap_tsd_get_string_const(l_tsd));
                if (!l_jobj_tsd || !l_jobj_tsd_type || !l_jobj_tx_sender_allowed_remove) {
                    json_object_put(l_jobj_tx_sender_allowed_remove);
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                json_object_object_add(l_jobj_tsd, "tx_sender_allowed_remove",l_jobj_tx_sender_allowed_remove);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            }continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD: {
                json_object *l_jobj_tsd = json_object_new_object();
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD");
                json_object *l_jobj_tx_sender_blocked_add = json_object_new_string(dap_tsd_get_string_const(l_tsd));
                if (!l_jobj_tsd || !l_jobj_tsd_type || !l_jobj_tx_sender_blocked_add) {
                    json_object_put(l_jobj_tx_sender_blocked_add);
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                json_object_object_add(l_jobj_tsd, "tx_sender_blocked_add", l_jobj_tx_sender_blocked_add);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            } continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_REMOVE: {
                json_object *l_jobj_tsd = json_object_new_object();
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_REMOVE");
                json_object *l_jobj_tx_sender_blocked_remove = json_object_new_string(dap_tsd_get_string_const(l_tsd));
                if (!l_jobj_tsd || !l_jobj_tsd_type || !l_jobj_tx_sender_blocked_remove) {
                    json_object_put(l_jobj_tx_sender_blocked_remove);
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                json_object_object_add(l_jobj_tsd, "tx_sender_blocked_remove", l_jobj_tx_sender_blocked_remove);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            } continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD: {
                json_object *l_jobj_tsd = json_object_new_object();
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD");
                json_object *l_tx_receiver_allowed_add = json_object_new_string(dap_tsd_get_string_const(l_tsd));
                if (!l_jobj_tsd || !l_jobj_tsd_type || !l_tx_receiver_allowed_add) {
                    json_object_put(l_tx_receiver_allowed_add);
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                json_object_object_add(l_jobj_tsd, "tx_receiver_allowed_add", l_tx_receiver_allowed_add);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            } continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_REMOVE: {
                json_object *l_jobj_tsd = json_object_new_object();
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_REMOVE");
                json_object *l_jobj_tx_receiver_allowed_remove = json_object_new_string(dap_tsd_get_string_const(l_tsd));
                if (!l_jobj_tsd || !l_jobj_tsd_type || !l_jobj_tx_receiver_allowed_remove){
                    json_object_put(l_jobj_tx_receiver_allowed_remove);
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                json_object_object_add(l_jobj_tsd, "tx_receiver_allowed_remove", l_jobj_tx_receiver_allowed_remove);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            } continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD: {
                json_object *l_jobj_tsd = json_object_new_object();
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD");
                json_object *l_jobj_tx_receiver_blocked_add = json_object_new_string(dap_tsd_get_string_const(l_tsd));
                if (!l_jobj_tsd || !l_jobj_tsd_type || !l_jobj_tx_receiver_blocked_add){
                    json_object_put(l_jobj_tx_receiver_blocked_add);
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                json_object_object_add(l_jobj_tsd, "tx_receiver_blocked_add", l_jobj_tx_receiver_blocked_add);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            } continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_REMOVE: {
                json_object *l_jobj_tsd = json_object_new_object();
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_REMOVE");
                json_object *l_jobj_tx_receiver_blocked_remove = json_object_new_string(dap_tsd_get_string_const(l_tsd));
                if (!l_jobj_tsd || !l_jobj_tsd_type || !l_jobj_tx_receiver_blocked_remove) {
                    json_object_put(l_jobj_tx_receiver_blocked_remove);
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                json_object_object_add(l_jobj_tsd, "tx_receiver_blocked_remove", l_jobj_tx_receiver_blocked_remove);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            } continue;
            case DAP_CHAIN_DATUM_TOKEN_TSD_TOKEN_DESCRIPTION: {
                json_object *l_jobj_tsd = json_object_new_object();
                json_object *l_jobj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TSD_TOKEN_DESCRIPTION");
                json_object *l_jobj_description = json_object_new_string(dap_tsd_get_string_const(l_tsd));
                if (!l_jobj_tsd || !l_jobj_tsd_type || !l_jobj_description) {
                    json_object_put(l_jobj_description);
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "type", l_jobj_tsd_type);
                json_object_object_add(l_jobj_tsd, "description", l_jobj_description);
                json_object_array_add(l_tsd_array, l_jobj_tsd);
            } continue;
            default: {
                char *l_wgn_text = dap_strdup_printf("<0x%04hX>: <size %u>\n", l_tsd->type, l_tsd->size);
                if (!l_wgn_text){
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object *l_jobj_wgn_text = json_object_new_string(l_wgn_text);
                DAP_DELETE(l_wgn_text);
                json_object *l_jobj_warning = json_object_new_object();
                if (!l_jobj_wgn_text || !l_jobj_warning) {
                    json_object_put(l_jobj_wgn_text);
                    json_object_put(l_jobj_warning);
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_tsd_array);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_warning, "warning", l_jobj_wgn_text);
                json_object_array_add(l_tsd_array, l_jobj_warning);
            }
        }
    }
    return l_tsd_array;
}

typedef enum dap_chain_datum_to_json_err_list {
    CHAIN_DATUM_TO_JSON_ERR_CAN_NOT_SERIALIZATION_TX_TO_JSON = DAP_JSON_RPC_ERR_CODE_METHOD_ERR_START,
    CHAIN_DATUM_TO_JSON_ERR_CAN_NOT_SERIALIZATION_DECL_TO_JSON,
    CHAIN_DATUM_TO_JSON_ERR_CAN_NOT_READ_DECL,
    CHAIN_DATUM_TO_JSON_ERR_CAN_NOT_SERIALIZATION_TSD_SECTION_DECL_TO_JSON,
    CHAIN_DATUM_TO_JSON_ERR_CAN_NOT_SERIALIZATION_EMISSION_TO_JSON,
    CHAIN_DATUM_TO_JSON_ERR_CAN_NOT_READ_EMISSION,
    CHAIN_DATUM_TO_JSON_ERR_CAN_NOT_SERIALIZATION_ANCHOR_TO_JSON,
    CHAIN_DATUM_TO_JSON_ERR_CAN_NOT_SERIALIZATION_DECREE_TO_JSON
}dap_chain_datum_to_json_err_list_t;

json_object * dap_chain_datum_to_json(dap_chain_datum_t* a_datum){
    json_object *l_object = json_object_new_object();
    if (!l_object){
        dap_json_rpc_allocation_error;
        return NULL;
    }
    char *l_hash_data_str;
    dap_get_data_hash_str_static(a_datum->data, a_datum->header.data_size, l_hash_data_str);
    json_object *l_obj_data_hash = json_object_new_string(l_hash_data_str);
    if (!l_obj_data_hash) {
        json_object_put(l_object);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_version = json_object_new_int(a_datum->header.version_id);
    if (!l_obj_version) {
        json_object_put(l_object);
        json_object_put(l_obj_data_hash);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_size = json_object_new_int(a_datum->header.data_size);
    if (!l_obj_size) {
        json_object_put(l_object);
        json_object_put(l_obj_data_hash);
        json_object_put(l_obj_version);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_type = json_object_new_string(dap_chain_datum_type_id_to_str(a_datum->header.type_id));
    if (!l_obj_type) {
        json_object_put(l_object);
        json_object_put(l_obj_data_hash);
        json_object_put(l_obj_version);
        json_object_put(l_obj_size);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_data = dap_chain_datum_data_to_json(a_datum);

    json_object_object_add(l_object, "hash", l_obj_data_hash);
    json_object_object_add(l_object, "data_size", l_obj_size);
    json_object_object_add(l_object, "version", l_obj_version);

    char l_time_str[32];
    if (a_datum->header.ts_create) {
        uint64_t l_ts = a_datum->header.ts_create;
        dap_ctime_r(&l_ts, l_time_str);                             /* Convert ts to  "Sat May 17 01:17:08 2014\n" */
        l_time_str[strlen(l_time_str)-1] = '\0';                    /* Remove "\n"*/
    }
    json_object *l_obj_ts_created = json_object_new_string(l_time_str);
    json_object_object_add(l_object, "ts_create", l_obj_ts_created);
    json_object_object_add(l_object, "type", l_obj_type);
    if (a_datum->header.type_id == DAP_CHAIN_DATUM_TX) {
        json_object_object_add(l_object, "items", l_obj_data);
    } else {
        json_object_object_add(l_object, "data", l_obj_data);
    }
    return l_object;
}

json_object * dap_chain_datum_data_to_json(dap_chain_datum_t *a_datum) {
    if (!a_datum)
        return json_object_new_null();
    json_object *l_obj_data;

    switch (a_datum->header.type_id) {
        case DAP_CHAIN_DATUM_TX:
        l_obj_data = dap_chain_datum_tx_to_json((dap_chain_datum_tx_t*)a_datum->data,NULL);
            if (!l_obj_data) {
                dap_json_rpc_error_add(CHAIN_DATUM_TO_JSON_ERR_CAN_NOT_SERIALIZATION_TX_TO_JSON,
                                       "Can't convert DAP_CHAIN_DATUM_TX to JSON");
                return NULL;
            }
            break;
        case DAP_CHAIN_DATUM_DECREE:
            l_obj_data = dap_chain_datum_decree_to_json((dap_chain_datum_decree_t*)a_datum->data);
            if (!l_obj_data) {
                dap_json_rpc_error_add(CHAIN_DATUM_TO_JSON_ERR_CAN_NOT_SERIALIZATION_DECREE_TO_JSON,
                                       "Can't convert DAP_CHAIN_DATUM_DECREE to JSON");
                return NULL;
            }
            break;
        case DAP_CHAIN_DATUM_ANCHOR:
            l_obj_data = dap_chain_datum_anchor_to_json((dap_chain_datum_anchor_t*)a_datum->data);
            if (!l_obj_data) {
                dap_json_rpc_error_add(CHAIN_DATUM_TO_JSON_ERR_CAN_NOT_SERIALIZATION_ANCHOR_TO_JSON,
                                       "Can't convert DAP_CHAIN_DATUM_ANCHOR to JSON");
                return NULL;
            }
            break;
        case DAP_CHAIN_DATUM_TOKEN_DECL: {
            size_t l_token_size = a_datum->header.data_size;
            dap_chain_datum_token_t *l_token = dap_chain_datum_token_read(a_datum->data, &l_token_size);
            if (!l_token) {
                dap_json_rpc_error_add(CHAIN_DATUM_TO_JSON_ERR_CAN_NOT_READ_DECL,
                                       "The contents of the token delcaration could not be read.");
                return NULL;
            }
            l_obj_data = dap_chain_datum_token_to_json(l_token, l_token_size);
            if (!l_obj_data) {
                dap_json_rpc_error_add(CHAIN_DATUM_TO_JSON_ERR_CAN_NOT_SERIALIZATION_DECL_TO_JSON,
                                       "Can't convert DAP_CHAIN_DATUM_TOKEN_DECL to JSON");
                DAP_DELETE(l_token);
                return NULL;
            }
            json_object *l_obj_tsd_data = s_dap_chain_datum_token_tsd_to_json(l_token, l_token_size);
            if (!l_obj_tsd_data) {
                json_object_put(l_obj_data);
                DAP_DELETE(l_token);
                log_it(L_ERROR, "It was not possible to read the contents of the TSD sections of the token delcaration.");
                dap_json_rpc_error_add(CHAIN_DATUM_TO_JSON_ERR_CAN_NOT_SERIALIZATION_TSD_SECTION_DECL_TO_JSON,
                                       "It was not possible to read the contents of the TSD sections of the token delcaration.");
                return NULL;
            }
            json_object_object_add(l_obj_data, "TSD", l_obj_tsd_data);
            DAP_DELETE(l_token);
        } break;
        case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
            size_t l_emission_size = a_datum->header.data_size;
            dap_chain_datum_token_emission_t *l_emission = dap_chain_datum_emission_read(a_datum->data, &l_emission_size);
            if (l_emission_size == 0 || !l_emission) {
                log_it(L_ERROR, "Failed to read emission");
                dap_json_rpc_error_add(CHAIN_DATUM_TO_JSON_ERR_CAN_NOT_READ_EMISSION,
                                       "Failed to read emission.");
                return NULL;
            } else {
                l_obj_data = dap_chain_datum_emission_to_json(l_emission, l_emission_size);
                DAP_DELETE(l_emission);
                if (!l_obj_data) {
                    dap_json_rpc_error_add(CHAIN_DATUM_TO_JSON_ERR_CAN_NOT_SERIALIZATION_EMISSION_TO_JSON,
                                           "Can't convert DAP_CHAIN_DATUM_TOKEN_DECL to JSON");
                    return NULL;
                }
            }
        } break;
        default:
            l_obj_data = json_object_new_null();
            break;
    }
    return l_obj_data;
}
