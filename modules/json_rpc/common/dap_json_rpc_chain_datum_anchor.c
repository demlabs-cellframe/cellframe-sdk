#include "dap_json_rpc_chain_datum_anchor.h"
#include "json.h"

#define LOG_TAG "dap_json_rpc_chain_datum_anchor"


json_object *s_dap_chain_datum_anchor_sign_to_json(byte_t * a_signs, size_t a_certs_size) {
    json_object *l_jobs_signs = json_object_new_array();
    size_t l_offset = 0;
    for (int i = 1; l_offset < (a_certs_size); i++) {
        json_object *l_jobj_sign = json_object_new_object();
        dap_sign_t *l_sign = (dap_sign_t*)(a_signs + l_offset);
        l_offset += dap_sign_get_size(l_sign);
        if (l_sign->header.sign_size == 0) {
            json_object *l_wrn_text = json_object_new_string("<CORRUPTED - 0 size signature>");
            json_object_object_add(l_jobj_sign, "warning", l_wrn_text);
            continue;
        }

        dap_chain_hash_fast_t l_pkey_hash = {0};
        if (dap_sign_get_pkey_hash(l_sign, &l_pkey_hash) == false) {
            json_object *l_wrn_text = json_object_new_string("<CORRUPTED - can't calc hash>");
            json_object_object_add(l_jobj_sign, "warning", l_wrn_text);
            continue;
        }
        char *l_hash_str = dap_chain_hash_fast_to_str_new(&l_pkey_hash);
        json_object *l_jobj_hash_str = json_object_new_string(l_hash_str);
        json_object *l_jobj_type_str = json_object_new_string(dap_sign_type_to_str(l_sign->header.type));
        json_object *l_jobj_sign_size = json_object_new_uint64(l_sign->header.sign_size);
        json_object_object_add(l_jobj_sign, "hash", l_jobj_hash_str);
        json_object_object_add(l_jobj_sign, "type", l_jobj_type_str);
        json_object_object_add(l_jobj_sign, "size", l_jobj_sign_size);
        DAP_DEL_Z(l_hash_str);
        json_object_array_add(l_jobs_signs, l_jobj_sign);
    }
    return l_jobs_signs;
}

json_object *dap_chain_datum_anchor_to_json(dap_chain_datum_anchor_t *a_anchor){
    json_object *l_obj_anchor = json_object_new_object();
    if (!l_obj_anchor) {
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_version = json_object_new_uint64(a_anchor->anchor_version);
    if (!l_obj_version){
        json_object_put(l_obj_anchor);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_ts_created = json_object_new_uint64(a_anchor->header.ts_created);
    if (!l_obj_ts_created) {
        json_object_put(l_obj_version);
        json_object_put(l_obj_anchor);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_tsd_array = json_object_new_array();
    if(!l_obj_tsd_array) {
        json_object_put(l_obj_ts_created);
        json_object_put(l_obj_version);
        json_object_put(l_obj_anchor);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    size_t l_tsd_offset = 0, tsd_data_size = a_anchor->header.data_size;

    while(l_tsd_offset < tsd_data_size){
        json_object *l_jobj_tsd = json_object_new_object();
        if (!l_jobj_tsd) {
            json_object_put(l_obj_tsd_array);
            json_object_put(l_obj_ts_created);
            json_object_put(l_obj_version);
            json_object_put(l_obj_anchor);
            dap_json_rpc_allocation_error;
            return NULL;
        }
        dap_tsd_t *l_tsd = (dap_tsd_t*)a_anchor->data_n_sign + l_tsd_offset;
        size_t l_tsd_size = l_tsd->size + sizeof(dap_tsd_t);
        if(l_tsd_size > tsd_data_size){
            json_object *l_jobj_wgn = json_object_new_string("TSD size is greater than all data size. It's possible corrupt data.");
            if (!l_jobj_wgn){
                json_object_put(l_jobj_tsd);
                json_object_put(l_obj_tsd_array);
                json_object_put(l_obj_ts_created);
                json_object_put(l_obj_ts_created);
                json_object_put(l_obj_version);
                json_object_put(l_obj_anchor);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object_object_add(l_jobj_tsd, "warning", l_jobj_wgn);
            json_object_array_add(l_obj_tsd_array, l_jobj_tsd);
            break;
        }
        if (l_tsd->type == DAP_CHAIN_DATUM_ANCHOR_TSD_TYPE_DECREE_HASH){
            json_object *l_obj_tsd_type = json_object_new_string("DAP_CHAIN_DATUM_ANCHOR_TSD_TYPE_DECREE_HASH");
            if (!l_obj_tsd_type){
                json_object_put(l_jobj_tsd);
                json_object_put(l_obj_tsd_array);
                json_object_put(l_obj_ts_created);
                json_object_put(l_obj_ts_created);
                json_object_put(l_obj_version);
                json_object_put(l_obj_anchor);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object_object_add(l_jobj_tsd, "type", l_obj_tsd_type);
            if(l_tsd->size > sizeof(dap_hash_fast_t)){
                json_object *l_jobj_wgn = json_object_new_string("Wrong fee tsd data size.");
                if (!l_jobj_wgn){
                    json_object_put(l_jobj_tsd);
                    json_object_put(l_obj_tsd_array);
                    json_object_put(l_obj_ts_created);
                    json_object_put(l_obj_ts_created);
                    json_object_put(l_obj_version);
                    json_object_put(l_obj_anchor);
                    dap_json_rpc_allocation_error;
                    return NULL;
                }
                json_object_object_add(l_jobj_tsd, "warning", l_jobj_wgn);
                json_object_array_add(l_obj_tsd_array, l_jobj_tsd);
                break;
            }
            dap_hash_fast_t l_out_hash = {0};
            _dap_tsd_get_scalar(l_tsd, &l_out_hash);
            char *l_hash_str = dap_hash_fast_to_str_new(&l_out_hash);
            if (!l_hash_str) {
                json_object_put(l_jobj_tsd);
                json_object_put(l_obj_tsd_array);
                json_object_put(l_obj_ts_created);
                json_object_put(l_obj_ts_created);
                json_object_put(l_obj_version);
                json_object_put(l_obj_anchor);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object *l_obj_tsd_hash = json_object_new_string(l_hash_str);
            DAP_DELETE(l_hash_str);
            if (!l_obj_tsd_hash){
                json_object_put(l_jobj_tsd);
                json_object_put(l_obj_tsd_array);
                json_object_put(l_obj_ts_created);
                json_object_put(l_obj_ts_created);
                json_object_put(l_obj_version);
                json_object_put(l_obj_anchor);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object_object_add(l_jobj_tsd, "hash", l_obj_tsd_hash);
        }
        json_object_array_add(l_obj_tsd_array, l_jobj_tsd);
        l_tsd_offset += l_tsd_size;
    }
    json_object_object_add(l_obj_anchor, "version", l_obj_version);
    json_object_object_add(l_obj_anchor, "ts_created", l_obj_ts_created);
    json_object_object_add(l_obj_anchor, "TSD", l_obj_tsd_array);
    json_object *l_jobj_signs = s_dap_chain_datum_anchor_sign_to_json(a_anchor->data_n_sign + a_anchor->header.data_size,
                                                                      a_anchor->header.signs_size);
    if (!l_jobj_signs) {
        json_object_put(l_obj_tsd_array);
        json_object_put(l_obj_ts_created);
        json_object_put(l_obj_ts_created);
        json_object_put(l_obj_version);
        json_object_put(l_obj_anchor);
        dap_json_rpc_error_add(DAP_JSON_RPC_ERR_CODE_SERIALIZATION_SIGN_TO_JSON, "I can't serialize the anchor signature in JSON.");
        return NULL;
    }
    json_object_object_add(l_obj_anchor, "signs", l_jobj_signs);
    return l_obj_anchor;
}
