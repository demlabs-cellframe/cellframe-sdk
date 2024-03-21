

#include "dap_json_rpc_chain_datum_token.h"
#include "dap_json_rpc_chain_common.h"
#include "dap_json_rpc_sign.h"
#include "json.h"

#define LOG_TAG "dap_json_rpc_chain_datum_token"

json_object *dap_chain_datum_token_flags_to_json(uint16_t a_flags){
    if (!a_flags) {
        return json_object_new_null();
    }
    json_object *l_jobj_flags = json_object_new_array();
    for (uint16_t i = 0; BIT(i) <= DAP_CHAIN_DATUM_TOKEN_FLAG_MAX; i++){
        if(a_flags & (1 << i)){
            json_object *l_jobj_flag_txt = json_object_new_string(c_dap_chain_datum_token_flag_str[BIT(i)]);
            json_object_array_add(l_jobj_flags, l_jobj_flag_txt);
        }
    }
    return l_jobj_flags;
}


json_object *dap_chain_datum_token_to_json(dap_chain_datum_token_t * a_token, size_t a_token_size){
    json_object *l_jobj_token = json_object_new_object();
    if (!l_jobj_token){
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_jobj_type;
    json_object *l_jobj_version = json_object_new_uint64(a_token->version);
    if (!l_jobj_version) {
        json_object_put(l_jobj_token);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    switch (a_token->type) {
        case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL:
            l_jobj_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TYPE_DECL");
            break;
        case DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE:
            l_jobj_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE");
            break;
        default:
            l_jobj_type = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_TYPE_UNKNOWN");
            break;
    }
    if (!l_jobj_type) {
        json_object_put(l_jobj_version);
        json_object_put(l_jobj_token);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object_object_add(l_jobj_token, "version", l_jobj_version);
    json_object_object_add(l_jobj_token, "type", l_jobj_type);
    json_object *l_jobj_subtype = NULL;
    json_object *l_jobj_header = json_object_new_object();
    if (!l_jobj_header){
        json_object_put(l_jobj_token);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    size_t l_tsd_total_size = 0;
    switch (a_token->subtype) {
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE: {
            json_object *l_jobj_decimals  = json_object_new_uint64(a_token->header_simple.decimals);
            if (!l_jobj_decimals){
                json_object_put(l_jobj_header);
                json_object_put(l_jobj_token);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object_object_add(l_jobj_header, "decimals", l_jobj_decimals);
            l_jobj_subtype = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE");
        }break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE: {
            json_object *l_jobj_flags = NULL;
            json_object *l_jobj_decimals  = NULL;
            if (a_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_DECL) {
                l_jobj_flags = json_object_new_string(s_flag_str_from_code(a_token->header_private_decl.flags));
                if (!l_jobj_flags){
                    json_object_put(l_jobj_header);
                    json_object_put(l_jobj_token);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                l_jobj_decimals = json_object_new_uint64(a_token->header_private_decl.decimals);
                if (!l_jobj_decimals) {
                    json_object_put(l_jobj_flags);
                    json_object_put(l_jobj_header);
                    json_object_put(l_jobj_token);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                l_tsd_total_size = a_token->header_private_decl.tsd_total_size;
            } else {
                l_jobj_flags = json_object_new_string(s_flag_str_from_code(a_token->header_private_update.flags));
                if (!l_jobj_flags) {
                    json_object_put(l_jobj_header);
                    json_object_put(l_jobj_token);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                l_jobj_decimals = json_object_new_uint64(a_token->header_private_update.decimals);
                if (!l_jobj_decimals) {
                    json_object_put(l_jobj_flags);
                    json_object_put(l_jobj_header);
                    json_object_put(l_jobj_token);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                l_tsd_total_size = a_token->header_private_update.tsd_total_size;
            }
            json_object_object_add(l_jobj_header, "flags", l_jobj_flags);
            json_object_object_add(l_jobj_header, "decimals", l_jobj_decimals);
            l_jobj_subtype = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE");
        } break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE: {
            json_object *l_jobj_flags = NULL;
            json_object *l_jobj_decimals  = NULL;
            if (a_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_DECL) {
                l_jobj_flags = json_object_new_string(s_flag_str_from_code(a_token->header_native_decl.flags));
                if (!l_jobj_flags) {
                    json_object_put(l_jobj_header);
                    json_object_put(l_jobj_token);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                l_jobj_decimals = json_object_new_uint64(a_token->header_native_decl.decimals);
                if (!l_jobj_decimals){
                    json_object_put(l_jobj_flags);
                    json_object_put(l_jobj_header);
                    json_object_put(l_jobj_token);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                l_tsd_total_size = a_token->header_native_decl.tsd_total_size;
            } else {
                l_jobj_flags = json_object_new_string(s_flag_str_from_code(a_token->header_native_update.flags));
                if (!l_jobj_flags) {
                    json_object_put(l_jobj_header);
                    json_object_put(l_jobj_token);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                l_jobj_decimals = json_object_new_uint64(a_token->header_native_update.decimals);
                if (!l_jobj_decimals) {
                    json_object_put(l_jobj_flags);
                    json_object_put(l_jobj_header);
                    json_object_put(l_jobj_token);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                l_tsd_total_size = a_token->header_native_update.tsd_total_size;
            }
            json_object_object_add(l_jobj_header, "flags", l_jobj_flags);
            json_object_object_add(l_jobj_header, "decimals", l_jobj_decimals);
            l_jobj_subtype = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE");
        } break;
        case DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC: {
            json_object *l_jobj_flags = json_object_new_string(s_flag_str_from_code(a_token->header_public.flags));
            if (!l_jobj_flags){
                json_object_put(l_jobj_header);
                json_object_put(l_jobj_token);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object *l_jobj_premine_supply = json_object_new_string(dap_uint256_to_char(a_token->header_public.premine_supply, NULL));
            if (!l_jobj_premine_supply) {
                json_object_put(l_jobj_flags);
                json_object_put(l_jobj_header);
                json_object_put(l_jobj_token);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object *l_jobj_premine_address = dap_chain_addr_to_json(&a_token->header_public.premine_address);
            if (!l_jobj_premine_address) {
                json_object_put(l_jobj_flags);
                json_object_put(l_jobj_premine_supply);
                json_object_put(l_jobj_header);
                json_object_put(l_jobj_token);
                dap_json_rpc_error_add(DAP_JSON_RPC_ERR_CODE_SERIALIZATION_ADDR_TO_JSON,
                                       "Failed to convert address to JSON.");
                return NULL;
            }
            json_object_object_add(l_jobj_header, "flags", l_jobj_flags);
            json_object_object_add(l_jobj_header, "premine_supply", l_jobj_premine_supply);
            json_object_object_add(l_jobj_header, "premine_address", l_jobj_premine_address);
            l_jobj_subtype = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC");
        } break;
        default: {
            l_jobj_subtype = json_object_new_string("DAP_CHAIN_DATUM_TOKEN_SUBTYPE_UNKNOWN");
        } break;
    }
    if (!l_jobj_subtype) {
        json_object_put(l_jobj_header);
        json_object_put(l_jobj_token);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object_object_add(l_jobj_token, "subtype", l_jobj_subtype);
    json_object_object_add(l_jobj_token, "header", l_jobj_header);
    json_object *l_jobj_ticker = json_object_new_string(a_token->ticker);
    if (!l_jobj_ticker) {
        json_object_put(l_jobj_token);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object_object_add(l_jobj_token, "ticker", l_jobj_ticker);
    json_object *l_jobj_signs_valid = json_object_new_uint64(a_token->signs_valid);
    if (!l_jobj_signs_valid) {
        json_object_put(l_jobj_token);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object_object_add(l_jobj_token, "signs_valid", l_jobj_signs_valid);
    json_object *l_jobj_signs_total = json_object_new_uint64(a_token->signs_total);
    if (!l_jobj_signs_total) {
        json_object_put(l_jobj_token);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object_object_add(l_jobj_token, "signs_total", l_jobj_signs_total);
    json_object *l_obj_signs = json_object_new_array();
    if (!l_obj_signs) {
        json_object_put(l_jobj_token);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    size_t l_offset = 0;
    size_t l_certs_field_size = a_token_size - sizeof(*a_token);
    while (l_offset < l_certs_field_size) {
        dap_sign_t *l_sign = (dap_sign_t *) ((byte_t*)a_token->data_n_tsd + l_tsd_total_size + l_offset);
        l_offset += dap_sign_get_size(l_sign);
        json_object *l_obj_sign = dap_sign_to_json(l_sign);
        if (!l_obj_sign) {
            json_object_put(l_obj_signs);
            json_object_put(l_jobj_token);
            dap_json_rpc_error_add(DAP_JSON_RPC_ERR_CODE_SERIALIZATION_SIGN_TO_JSON, "Failed to convert signature to JSON.");
            return NULL;
        }
        json_object_array_add(l_obj_signs, l_obj_sign);
    }
    json_object_object_add(l_jobj_token, "signs", l_obj_signs);
    return l_jobj_token;
}


json_object *dap_chain_datum_emission_to_json(dap_chain_datum_token_emission_t *a_emission, size_t a_emission_size){
    json_object *l_emi_obj = json_object_new_object();
    json_object *l_emi_version = json_object_new_uint64(a_emission->hdr.version);
    json_object *l_emi_type = json_object_new_string(c_dap_chain_datum_token_emission_type_str[a_emission->hdr.type]);
    json_object *l_emi_address = dap_chain_addr_to_json(&a_emission->hdr.address);
    json_object *l_emi_header = json_object_new_object();
    json_object *l_emi_data = json_object_new_object();
    if (!l_emi_obj || !l_emi_version || !l_emi_type || !l_emi_address || !l_emi_header || ! l_emi_data) {
        json_object_put(l_emi_obj);
        json_object_put(l_emi_version);
        json_object_put(l_emi_type);
        json_object_put(l_emi_address);
        json_object_put(l_emi_header);
        json_object_put(l_emi_data);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object_object_add(l_emi_header, "version", l_emi_version);
    json_object_object_add(l_emi_header, "type", l_emi_type);
    json_object_object_add(l_emi_header, "address", l_emi_address);
    json_object_object_add(l_emi_obj, "header", l_emi_header);
    switch (a_emission->hdr.type){
        case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH: {
            json_object *l_obj_size = json_object_new_uint64(a_emission->data.type_auth.size);
            json_object *l_obj_tsd_total_size = json_object_new_uint64(a_emission->data.type_auth.tsd_total_size);
            json_object *l_obj_signs_count = json_object_new_uint64(a_emission->data.type_auth.signs_count);
            if (!l_obj_size || !l_obj_tsd_total_size || !l_obj_signs_count) {
                json_object_put(l_obj_size);
                json_object_put(l_obj_tsd_total_size);
                json_object_put(l_obj_signs_count);
                json_object_put(l_emi_data);
                json_object_put(l_emi_obj);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object_object_add(l_emi_data, "size", l_obj_size);
            json_object_object_add(l_emi_data, "tsd_total_size", l_obj_tsd_total_size);
            json_object_object_add(l_emi_data, "signs_count", l_obj_signs_count);
            if (((void *) a_emission->tsd_n_signs + a_emission->data.type_auth.tsd_total_size) >
                  ((void *) a_emission + a_emission_size)) {
                char *l_err_str = dap_strdup_printf("Malformed DATUM type %d, TSD section is out-of-buffer (%" DAP_UINT64_FORMAT_U " vs %zu)",
                                                            a_emission->hdr.type, a_emission->data.type_auth.tsd_total_size, a_emission_size);
                if (!l_err_str){
                    json_object_put(l_emi_data);
                    json_object_put(l_emi_obj);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object *l_err_tsd = json_object_new_string(l_err_str);
                DAP_DELETE(l_err_str);
                if (!l_err_tsd) {
                    json_object_put(l_emi_data);
                    json_object_put(l_emi_obj);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_emi_data, "ERROR", l_err_tsd);
            }
            json_object *l_obj_signs = json_object_new_array();
            if (!l_obj_signs){
                json_object_put(l_emi_data);
                json_object_put(l_emi_obj);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            size_t l_offset = a_emission->data.type_auth.tsd_total_size;
            for (int i = 0; i < a_emission->data.type_auth.signs_count; i++) {
                dap_sign_t *l_sign = (dap_sign_t *) ((byte_t*)a_emission->tsd_n_signs + l_offset);
                l_offset += dap_sign_get_size(l_sign);
                json_object *l_obj_sign = dap_sign_to_json(l_sign);
                if (!l_obj_sign) {
                    json_object_put(l_obj_signs);
                    json_object_put(l_emi_data);
                    json_object_put(l_emi_obj);
                    dap_json_rpc_error_add(3, "Failed to serialize signature to JSON object.");
                    return NULL;
                }
                json_object_array_add(l_obj_signs, l_obj_sign);
            }
            json_object_object_add(l_emi_data, "signs", l_obj_signs);

        } break;
        case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ALGO: {
            json_object *l_code_name = json_object_new_string(a_emission->data.type_algo.codename);
            if (!l_code_name) {
                json_object_put(l_emi_data);
                json_object_put(l_emi_obj);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object_object_add(l_emi_data, "codename", l_code_name);
        } break;
        case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ATOM_OWNER: {
            json_object *l_value_start = json_object_new_uint64(a_emission->data.type_atom_owner.value_start);
            json_object *l_value_change_algo_codename = json_object_new_string(
                    a_emission->data.type_atom_owner.value_change_algo_codename);
            if (!l_value_start || !l_value_change_algo_codename) {
                json_object_put(l_value_start);
                json_object_put(l_value_change_algo_codename);
                json_object_put(l_emi_data);
                json_object_put(l_emi_obj);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object_object_add(l_emi_data, "value_start", l_value_start);
            json_object_object_add(l_emi_data, "value_change_algo_codename", l_value_change_algo_codename);
        } break;
        case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_SMART_CONTRACT:
        {
            json_object *l_obj_addr = dap_chain_addr_to_json(&a_emission->data.type_presale.addr);
            json_object *l_obj_flags = json_object_new_int64(a_emission->data.type_presale.flags);
            json_object *l_obj_lock_time = json_object_new_uint64(a_emission->data.type_presale.lock_time);
            if (!l_obj_addr || !l_obj_flags || !l_obj_lock_time) {
                json_object_put(l_obj_addr);
                json_object_put(l_obj_flags);
                json_object_put(l_obj_lock_time);
                json_object_put(l_emi_data);
                json_object_put(l_emi_obj);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object_object_add(l_emi_data, "addr", l_obj_addr);
            json_object_object_add(l_emi_data, "flags", l_obj_flags);
            json_object_object_add(l_emi_data, "lock_time", l_obj_lock_time);
        }break;
    }
    json_object_object_add(l_emi_obj, "data", l_emi_data);
    return  l_emi_obj;
}

