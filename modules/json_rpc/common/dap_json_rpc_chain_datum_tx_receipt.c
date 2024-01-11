#include "dap_common.h"
#include "dap_enc_key.h"
#include "dap_sign.h"
#include "dap_chain_datum_tx_receipt.h"

#include "dap_json_rpc_sign.h"
#include "dap_json_rpc_chain_datum_tx_receipt.h"
#include "json.h"

#define LOG_TAG "dap_json_rpc_chain_datum_tx_receipt"


json_object* dap_chain_receipt_info_to_json(dap_chain_receipt_info_t *a_info){
    json_object *l_obj = json_object_new_object();
    if (!l_obj) {
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj_srv_uid = json_object_new_uint64(a_info->srv_uid.uint64);
    if (!l_obj_srv_uid) {
        json_object_put(l_obj);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object_object_add(l_obj, "uid", l_obj_srv_uid);

#if DAP_CHAIN_NET_SRV_UID_SIZE == 8
    json_object *l_obj_addition = json_object_new_uint64(a_info->addition);
    if (!l_obj_addition){
        json_object_put(l_obj);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object_object_add(l_obj, "ext_size", l_obj_addition);
#endif

    json_object * l_obj_units = json_object_new_uint64(a_info->units);
    json_object *l_obj_units_type = json_object_new_string(dap_chain_srv_unit_enum_to_str(a_info->units_type.enm));
    if (!l_obj_units_type || !l_obj_units) {
        json_object_put(l_obj);
        json_object_put(l_obj_units);
        json_object_put(l_obj_units_type);
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object_object_add(l_obj, "units", l_obj_units);
    json_object_object_add(l_obj, "units_type", l_obj_units_type);

    char *l_value = dap_chain_balance_to_coins(a_info->value_datoshi);
    char *l_datoshi_value = dap_chain_balance_print(a_info->value_datoshi);
    json_object *l_obj_datoshi = json_object_new_string(l_datoshi_value);
    json_object *l_obj_value = json_object_new_string(l_value);
    if (!l_obj_datoshi || !l_obj_value) {
        json_object_put(l_obj_value);
        json_object_put(l_obj_datoshi);
        DAP_DELETE(l_datoshi_value);
        dap_json_rpc_allocation_error;
        return NULL;
    }

    DAP_DELETE(l_datoshi_value);
    DAP_DELETE(l_value);

    json_object_object_add(l_obj, "value", l_obj_value);
    json_object_object_add(l_obj, "value_datoshi", l_obj_datoshi);
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
