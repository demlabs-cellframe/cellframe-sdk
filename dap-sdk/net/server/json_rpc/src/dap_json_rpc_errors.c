#include "dap_json_rpc_errors.h"

#define LOG_TAG "dap_json_rpc_errors"

dap_json_rpc_error_t *dap_json_rpc_error_create(int a_code, const char *a_message) {
    dap_json_rpc_error_t *l_ret = DAP_NEW(dap_json_rpc_error_t);
    l_ret->code_error = a_code;
    l_ret->msg = dap_strdup(a_message);
    return l_ret;
}

void dap_json_rpc_error_delete(dap_json_rpc_error_t *a_error){
    if (a_error) {
        DAP_DELETE(a_error->msg);
        DAP_DELETE(a_error);
    }
}

json_object *dap_json_rpc_error_to_json(dap_json_rpc_error_t *a_error){
    json_object *l_res = json_object_new_object();
    json_object *l_code = json_object_new_int(a_error->code_error);
    json_object *l_msg = json_object_new_string(a_error->msg);
    json_object_object_add(l_res, "code", l_code);
    json_object_object_add(l_res, "message", l_msg);
    return l_res;
}

dap_json_rpc_error_t *_dap_json_rpc_error_from_json(json_object *a_json, char *a_log_tag){
    if (!a_json) {
        _log_it(a_log_tag, L_DEBUG, "The dap_json_rpc_error_from_json function is passed a null pointer "
                                    "to a JSON object.");
        return NULL;
    }
    int32_t l_code = 0;
    char *l_msg;
    json_object *l_jobj_code = json_object_object_get(a_json, "code");
    if (!l_jobj_code) {
        _log_it(a_log_tag, L_DEBUG, "object with key 'code' was not found in the input JSON.");
        return NULL;
    }
    json_object *l_jobj_msg = json_object_object_get(a_json, "message");
    if (!l_jobj_msg) {
        _log_it(a_log_tag, L_DEBUG, "Object with key 'message' was not found in the input JSON.");
        return NULL;
    }
    if (json_object_get_type(l_jobj_code) == json_type_int) {
        l_code = json_object_get_int(l_jobj_code);
    } else {
        _log_it(a_log_tag, L_DEBUG, "The object with the key \"code\" in the input JSON is not a integer.");
        return NULL;
    }
    if (json_object_get_type(l_jobj_msg) == json_type_string) {
        l_msg = dap_strdup(json_object_get_string(l_jobj_msg));
    } else {
        _log_it(a_log_tag, L_DEBUG, "The object with the key \"code\" in the input JSON is not a string.");
        return NULL;
    }
    dap_json_rpc_error_t *l_ret = DAP_NEW(dap_json_rpc_error_t);
    l_ret->code_error = l_code;
    l_ret->msg = l_msg;
    return l_ret;
}

dap_json_rpc_error_t *_dap_json_rpc_error_from_json_str(char *a_json, char *a_log_tag){
    if (!a_json) {
        _log_it(a_log_tag, L_DEBUG, "The dap_json_rpc_error_from_json function is passed a null pointer "
                                    "to a JSON object.");
        return NULL;
    }
    json_object *l_from = json_tokener_parse(a_json);
    return _dap_json_rpc_error_from_json(l_from, a_log_tag);
}