#include "dap_common.h"
#include "dap_sign.h"
#include "dap_chain_datum_tx_receipt.h"

#include "dap_json_rpc_sign.h"
#include "dap_json_rpc_chain_datum_tx_receipt.h"

#define LOG_TAG "dap_json_rpc_chain_datum_tx_receipt"


json_object* dap_chain_receipt_info_to_json(dap_chain_receipt_info_t *a_info){
    json_object *l_obj = json_object_new_object();
    if (!l_obj) {
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object_object_add(l_obj, "uid", json_object_new_uint64(a_info->srv_uid.uint64));
#if DAP_CHAIN_NET_SRV_UID_SIZE == 8
    json_object_object_add(l_obj, "ext_size", json_object_new_uint64(a_info->addition));
#endif
    json_object_object_add(l_obj, "units", json_object_new_uint64(a_info->units));
    json_object_object_add(l_obj, "units_type", json_object_new_string(dap_chain_srv_unit_enum_to_str(a_info->units_type.enm)));

    const char *l_value, *l_datoshi_value = dap_uint256_to_char(a_info->value_datoshi, &l_value);
    json_object_object_add(l_obj, "value", json_object_new_string(l_value));
    json_object_object_add(l_obj, "value_datoshi", json_object_new_string(l_datoshi_value));
    return l_obj;
}

json_object *dap_chain_datum_tx_receipt_to_json(dap_chain_datum_tx_receipt_t *a_receipt) {
    json_object *l_obj = json_object_new_object();
    if (!l_obj) {
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_info = dap_chain_receipt_info_to_json(&a_receipt->receipt_info);
    if (!l_obj_info) {
        json_object_put(l_obj);
        return NULL;
    }
    json_object *l_obj_size = json_object_new_uint64(a_receipt->size);
    if (!l_obj_size) {
        json_object_put(l_obj);
        json_object_put(l_obj_info);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    //Provider
    dap_sign_t *l_first_sign  = dap_chain_datum_tx_receipt_sign_get(a_receipt, a_receipt->size, 1);
    //Client
    dap_sign_t *l_second_sign  = dap_chain_datum_tx_receipt_sign_get(a_receipt, a_receipt->size, 2);
    json_object *l_obj_signs = json_object_new_object();
    if (!l_obj_signs) {
        json_object_put(l_obj_size);
        json_object_put(l_obj_info);
        json_object_put(l_obj);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_provider_sign = dap_sign_to_json(l_first_sign);
    json_object *l_obj_client_sign = dap_sign_to_json(l_second_sign);
    json_object_object_add(l_obj_signs, "provider", l_obj_provider_sign);
    json_object_object_add(l_obj_signs, "client", l_obj_client_sign);
    json_object *l_exts_data = json_object_new_string_len((char *)a_receipt->exts_n_signs, a_receipt->exts_size);
    if (!l_exts_data) {
        json_object_put(l_obj_size);
        json_object_put(l_obj_info);
        json_object_put(l_obj_signs);
        json_object_put(l_obj);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object_object_add(l_obj, "info", l_obj_info);
    json_object_object_add(l_obj, "size", l_obj_size);
    json_object_object_add(l_obj, "sings", l_obj_signs);
    json_object_object_add(l_obj, "exts_data", l_exts_data);
    return l_obj;
}
