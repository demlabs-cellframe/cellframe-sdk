#include "dap_chain_mempool_rpc.h"
#include "dap_chain_mempool.h"

#define LOG_TAG "dap_chain_mempool_rpc"

int dap_chain_mempool_rpc_init(void) {
    dap_json_rpc_registration_request_handler("mempool_list", dap_chain_mempool_rpc_handler_list);
    dap_json_rpc_registration_request_handler("memtest", dap_chain_mempool_rpc_handler_test);
    return 0;
}

void dap_chain_mempool_rpc_handler_test(dap_json_rpc_params_t *a_params,
                                        dap_json_rpc_response_t *a_response, const char *a_method) {
    UNUSED(a_method);
    char *l_tn = NULL;
//    char *l_chain_str = NULL;
    for (uint32_t i = 0; i < a_params->length; i++) {
        dap_json_rpc_param_t *l_prm = a_params->params[i];
        if (i == 0)
            l_tn = l_prm->value_param;
    }
    if (dap_strcmp(l_tn, "NULL") == 0) {
        a_response->type = TYPE_RESPONSE_NULL;
    } else if (dap_strcmp(l_tn, "STRING") == 0) {
        a_response->type = TYPE_RESPONSE_STRING;
        a_response->result_string = dap_strdup("This test string");
    } else if (dap_strcmp(l_tn, "INTEGER") == 0) {
        a_response->type = TYPE_RESPONSE_INTEGER;
        a_response->result_int = 4555745;
    } else if (dap_strcmp(l_tn, "BOOLEAN") == 0) {
        a_response->type = TYPE_RESPONSE_BOOLEAN;
        a_response->result_boolean = true;
    } else if (dap_strcmp(l_tn, "DOUBLE") == 0) {
        a_response->type = TYPE_RESPONSE_DOUBLE;
        a_response->result_double = 75.545;
    } else if (dap_strcmp(l_tn, "JSON") == 0) {
        a_response->type = TYPE_RESPONSE_JSON;
        json_object *l_obj = json_object_new_object();
        json_object *l_int = json_object_new_uint64(45577445);
        json_object *l_boolean = json_object_new_boolean((json_bool)1);
        json_object *l_double = json_object_new_double(457.74514);
        json_object *l_arr = json_object_new_array();
        for (int i = 1000; i < 1997; i++) {
            json_object *l_cur = json_object_new_int(i);
            json_object_array_add(l_arr, l_cur);
        }
        json_object_object_add(l_obj, "int", l_int);
        json_object_object_add(l_obj, "boolean", l_boolean);
        json_object_object_add(l_obj, "double", l_double);
        json_object_object_add(l_obj, "array", l_arr);
        a_response->result_json_object = json_object_get(l_obj);
        json_object_put(l_obj);
    } else {
        //set ERR code
    }
}

void dap_chain_mempool_rpc_handler_list(dap_json_rpc_params_t *a_params,
                                        dap_json_rpc_response_t *a_response, const char *a_method) {
    char *l_net_str = NULL;
    char *l_chain_str = NULL;
    for (uint32_t i = 0; i < a_params->length; i++) {
        dap_json_rpc_param_t *l_prm = a_params->params[i];
        if (i == 0)
            l_net_str = l_prm->value_param;
        if (i == 1)
            l_chain_str = l_prm->value_param;
    }
    dap_chain_net_t  *l_net = dap_chain_net_by_name(l_net_str);
    dap_chain_t *l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
    a_response->type = TYPE_RESPONSE_STRING;
    char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_new(l_chain);
    if(!l_gdb_group_mempool){
        a_response->result_string = "{\"datums\":[]}";
        return;
    }
    size_t l_objs_size = 0;
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_gdb_group_mempool, &l_objs_size);
    json_object *l_object = json_object_new_object();
    json_object *l_object_array = json_object_new_array();

    for(size_t i = 0; i < l_objs_size; i++) {
        dap_chain_datum_t *l_datum = (dap_chain_datum_t *)l_objs[i].value;
        //dap_time_t l_ts_create = (dap_time_t) l_datum->header.ts_create;
        if (!l_datum->header.data_size || (l_datum->header.data_size > l_objs[i].value_len)) {
            log_it(L_ERROR, "Trash datum in GDB %s.%s, key: %s data_size:%u, value_len:%zu",
                   l_net->pub.name, l_chain->name, l_objs[i].key, l_datum->header.data_size, l_objs[i].value_len);
            dap_global_db_del(l_gdb_group_mempool, l_objs[i].key, NULL, NULL);
            continue;
        }

        json_object *l_obj_datum = dap_chain_datum_to_json(l_datum);
        json_object_array_add(l_object_array, l_obj_datum);
    }
    json_object_object_add(l_object, "datums", l_object_array);
    a_response->type = TYPE_RESPONSE_JSON;
    a_response->result_json_object = l_object;

    DAP_DELETE(l_gdb_group_mempool);
}

#undef LOG_TAG
