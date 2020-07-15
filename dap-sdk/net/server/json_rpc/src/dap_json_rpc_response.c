#include "dap_json_rpc_response.h"

void dap_json_rpc_response_free(dap_json_rpc_response_t *a_response){
    DAP_FREE(a_response->error);
    if (a_response->type_result == TYPE_RESPONSE_STRING){
        DAP_FREE(a_response->result_string);
    }
    DAP_FREE(a_response);
}

void dap_json_rpc_response_send(dap_json_rpc_response_t *a_response, dap_client_remote_t *a_client_remote){
    char *str_response = NULL;
    json_object *l_jobj = json_object_new_object();
    json_object *l_jobj_error = json_object_new_object();
    json_object *l_jobj_result;
    if (a_response->error != NULL){
        switch (a_response->type_result) {
        case TYPE_RESPONSE_STRING:
            l_jobj_result = json_object_new_string(a_response->result_string);
            break;
        case TYPE_RESPONSE_DOUBLE:
            l_jobj_result = json_object_new_double(a_response->result_double);
            break;
        case TYPE_RESPONSE_BOOLEAN:
            l_jobj_result = json_object_new_boolean(a_response->result_boolean);
            break;
        case TYPE_RESPONSE_INTEGER:
            l_jobj_result = json_object_new_int64(a_response->result_int);
            break;
        }
    }else{
        l_jobj_result = json_object_new_object();
        json_object *l_jobj_error_code = json_object_new_int(a_response->error->code_error);
        json_object *l_jobj_error_msg = json_object_new_string(a_response->error->msg);
        json_object_object_add(l_jobj_error, "code", l_jobj_error_code);
        json_object_object_add(l_jobj_error, "message", l_jobj_error_msg);
    }
    json_object_object_add(l_jobj, "result", l_jobj_result);
    json_object_object_add(l_jobj, "error", l_jobj_error);
    json_object_object_add(l_jobj, "id", json_object_new_int(a_response->id));
    str_response = strdup(json_object_get_string(l_jobj));
    a_client_remote->buf_out_size = strlen(str_response);
    memcpy(a_client_remote->buf_out, str_response, a_client_remote->buf_out_size);
    DAP_FREE(str_response);
}
