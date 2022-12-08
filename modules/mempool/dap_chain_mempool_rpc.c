#include "dap_chain_mempool_rpc.h"
#include "dap_chain_mempool.h"

#define LOG_TAG "dap_chain_mempool_rpc"

int dap_chain_mempool_rpc_init(void) {
    dap_json_rpc_registration_request_handler("mempool_list", dap_chain_mempool_rpc_handler_list);
}
void dap_chain_mempool_rpc_handler_list(dap_json_rpc_params_t *a_params,
                                        dap_json_rpc_response_t *a_response, const char *a_method) {
    char *l_net_str = NULL;
    char *l_chain_str = NULL;
    for (int32_t i = 0; i < a_params->lenght; i++) {
        dap_json_rpc_param_t *l_prm = a_params->params[i];
        if (i == 0)
            l_net_str = l_prm->value_param;
        if (i == 1)
            l_chain_str = l_prm->value_param;
    }
    dap_chain_net_t  *l_net = dap_chain_net_by_name(l_net_str);
    dap_chain_t *l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
    a_response->type_result = TYPE_RESPONSE_STRING;
    char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);
    if(!l_gdb_group_mempool){
        a_response->result_string = "{\"datums\":[]}";
        return;
    }
    size_t l_objs_size = 0;
    size_t l_objs_addr = 0;
    dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(l_gdb_group_mempool, &l_objs_size);
    json_object *l_object = json_object_new_object();
    json_object *l_object_array = json_object_new_array();

    for(size_t i = 0; i < l_objs_size; i++) {
        dap_chain_datum_t *l_datum = (dap_chain_datum_t *)l_objs[i].value;
        dap_time_t l_ts_create = (dap_time_t) l_datum->header.ts_create;

        if (!l_datum->header.data_size || (l_datum->header.data_size > l_objs[i].value_len)) {
            log_it(L_ERROR, "Trash datum in GDB %s.%s, key: %s data_size:%u, value_len:%zu",
                   l_net->pub.name, l_chain->name, l_objs[i].key, l_datum->header.data_size, l_objs[i].value_len);
            dap_chain_global_db_gr_del(l_objs[i].key, l_gdb_group_mempool);
            continue;
        }
        json_object *l_obj_datum = dap_chain_datum_to_json(l_datum);
        json_object_array_add(l_object_array, l_obj_datum);
//        json_object_put(l_obj_datum);
    }
    json_object_object_add(l_object, "datums", l_object_array);
    a_response->type_result = TYPE_RESPONSE_JSON;
    a_response->result_json_object = l_object;
//    const char *l_ret_str = json_object_to_json_string(l_object);
//    size_t l_ret_str_size = dap_strlen(l_ret_str) + 1;
//    char * l_ret = DAP_NEW_Z_SIZE(char, l_ret_str_size);
//    strcpy(l_ret, l_ret_str);
//    a_response->result_string = l_ret;
//    json_object_put(l_object);
//    json_object_put(l_object_array);
    //TODO: Free memory.

    DAP_DELETE(l_gdb_group_mempool);
}

#undef LOG_TAG