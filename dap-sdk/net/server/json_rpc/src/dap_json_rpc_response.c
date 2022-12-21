#include "dap_json_rpc_response.h"

#define LOG_TAG "dap_json_rpc_response"

void dap_json_rpc_request_JSON_free(dap_json_rpc_request_JSON_t *l_request_JSON)
{
    if (l_request_JSON->struct_error)
        dap_json_rpc_error_JSON_free(l_request_JSON->struct_error);
    json_object_put(l_request_JSON->obj_result);
    json_object_put(l_request_JSON->obj_error);
    json_object_put(l_request_JSON->obj_id);
    DAP_FREE(l_request_JSON);
}

void dap_json_rpc_response_free(dap_json_rpc_response_t *a_response)
{
    DAP_FREE(a_response->error);
    if (a_response->type_result == TYPE_RESPONSE_STRING){
        DAP_FREE(a_response->result_string);
    }
    DAP_FREE(a_response);
}

void dap_json_rpc_response_send(dap_json_rpc_response_t *a_response, dap_http_simple_t *a_client)
{
    json_object *l_jobj = json_object_new_object();
    json_object *l_obj_id = json_object_new_int64(a_response->id);
    json_object *l_obj_result = NULL;
    json_object *l_obj_error = NULL;
    const char *str_response = NULL;
    if (a_response->error == NULL){
        l_obj_error = json_object_new_null();
        switch (a_response->type_result) {
            case TYPE_RESPONSE_STRING:
                l_obj_result = json_object_new_string(a_response->result_string);
                break;
            case TYPE_RESPONSE_DOUBLE:
                l_obj_result = json_object_new_double(a_response->result_double);
                break;
            case TYPE_RESPONSE_BOOLEAN:
                l_obj_result = json_object_new_boolean(a_response->result_boolean);
                break;
            case TYPE_RESPONSE_INTEGER:
                l_obj_result = json_object_new_int64(a_response->result_int);
                break;
            case TYPE_RESPONSE_JSON:
                l_obj_result = json_object_get(a_response->result_json_object);
                json_object_put(a_response->result_json_object);
                break;
            default:{}
        }
    }else{
        l_obj_error = json_object_new_object();
        json_object *l_obj_err_code = json_object_new_int(a_response->error->code_error);
        json_object *l_obj_err_msg = json_object_new_string(a_response->error->msg);
        json_object_object_add(l_obj_error, "code", l_obj_err_code);
        json_object_object_add(l_obj_error, "message", l_obj_err_msg);
    }
    json_object_object_add(l_jobj, "result", l_obj_result);
    json_object_object_add(l_jobj, "id", l_obj_id);
    json_object_object_add(l_jobj, "error", l_obj_error);
    str_response = json_object_to_json_string(l_jobj);
    dap_http_simple_reply(a_client, str_response, strlen(str_response));
    json_object_put(l_jobj);
}

dap_json_rpc_response_t *dap_json_rpc_response_from_json(char *a_data_json)
{
    json_object *l_jobj = json_tokener_parse(a_data_json);
    json_object *l_jobj_result = json_object_object_get(l_jobj, "result");
    json_object *l_jobj_error = json_object_object_get(l_jobj, "error");
    json_object *l_jobj_id = json_object_object_get(l_jobj, "id");
    dap_json_rpc_response_t *l_response = DAP_NEW(dap_json_rpc_response_t);
    l_response->id = json_object_get_int64(l_jobj_id);
    if (json_object_is_type(l_jobj_error, json_type_null)){
        l_response->error = NULL;
        switch(json_object_get_type(l_jobj_result)){
        case json_type_int:
            l_response->type_result = TYPE_RESPONSE_INTEGER;
            l_response->result_int = json_object_get_int64(l_jobj_result);
            break;
        case json_type_double:
            l_response->type_result = TYPE_RESPONSE_DOUBLE;
            l_response->result_double = json_object_get_double(l_jobj_result);
            break;
        case json_type_boolean:
            l_response->type_result = TYPE_RESPONSE_BOOLEAN;
            l_response->result_boolean = json_object_get_boolean(l_jobj_result);
            break;
        case json_type_string:
            l_response->type_result = TYPE_RESPONSE_STRING;
            l_response->result_string = dap_strdup(json_object_get_string(l_jobj_result));
            break;
        default:
            l_response->type_result = TYPE_RESPONSE_NULL;
            break;
        }
    } else {
        l_response->error = dap_json_rpc_create_from_json_object(l_jobj_error);
        l_response->type_result = TYPE_RESPONSE_NULL;
    }
//    json_object_put(l_jobj_id);
//    json_object_put(l_jobj_error);
//    json_object_put(l_jobj_result);
    json_object_put(l_jobj);
    return l_response;
}


