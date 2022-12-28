#include "dap_chain_mempool_rpc.h"
#include "dap_chain_mempool.h"
#include "dap_json.h"

#define LOG_TAG "dap_chain_mempool_rpc"

#define MEMPOOL_RPC_LIST "mempool_list"
#define MEMPOOL_RPC_TX_CREATED "tx_created"
#define TEST_RPC "memtest"

int dap_chain_mempool_rpc_init(void) {
    dap_json_rpc_registration_request_handler(MEMPOOL_RPC_LIST, dap_chain_mempool_rpc_handler_list);
    dap_json_rpc_registration_request_handler(TEST_RPC, dap_chain_mempool_rpc_handler_test);
    dap_json_rpc_registration_request_handler(MEMPOOL_RPC_TX_CREATED, dap_chain_mempool_rpc_handler_tx_create);
}

void dap_chain_mempool_rpc_handler_test(dap_json_rpc_params_t *a_params,
                                        dap_json_rpc_response_t *a_response, const char *a_method) {
    UNUSED(a_method);
    char *l_tn = NULL;
//    char *l_chain_str = NULL;
    for (uint32_t i = 0; i < a_params->lenght; i++) {
        dap_json_rpc_param_t *l_prm = a_params->params[i];
        if (i == 0)
            l_tn = l_prm->value_param;
    }
    if (dap_strcmp(l_tn, "NULL") == 0) {
        a_response->type_result = TYPE_RESPONSE_NULL;
    } else if (dap_strcmp(l_tn, "STRING") == 0) {
        a_response->type_result = TYPE_RESPONSE_STRING;
        a_response->result_string = dap_strdup("This test string");
    } else if (dap_strcmp(l_tn, "INTEGER") == 0) {
        a_response->type_result = TYPE_RESPONSE_INTEGER;
        a_response->result_int = 4555745;
    } else if (dap_strcmp(l_tn, "BOOLEAN") == 0) {
        a_response->type_result = TYPE_RESPONSE_BOOLEAN;
        a_response->result_boolean = true;
    } else if (dap_strcmp(l_tn, "DOUBLE") == 0) {
        a_response->type_result = TYPE_RESPONSE_DOUBLE;
        a_response->result_double = 75.545;
    } else if (dap_strcmp(l_tn, "JSON") == 0) {
        a_response->type_result = TYPE_RESPONSE_JSON;
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
    for (uint32_t i = 0; i < a_params->lenght; i++) {
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
    }
    json_object_object_add(l_object, "datums", l_object_array);
    a_response->type_result = TYPE_RESPONSE_JSON;
    a_response->result_json_object = l_object;

    DAP_DELETE(l_gdb_group_mempool);
}

void dap_chain_mempool_rpc_handler_tx_create(dap_json_rpc_params_t *a_params,
                                             dap_json_rpc_response_t *a_response, const char *a_method) {
    UNUSED(a_method);
    const char *l_net_str = NULL;
    const char *l_chain_str = NULL;
    json_object *l_json_items = NULL;
    for (uint32_t i = 0; i < a_params->lenght; i++) {
        dap_json_rpc_param_t *l_prm = a_params->params[i];
        if (i == 0)
            if (l_prm->type == TYPE_PARAM_STRING)
                l_net_str = l_prm->value_param;
        if (i == 1)
            if (l_prm->type == TYPE_PARAM_STRING)
                l_chain_str = l_prm->value_param;
        if (i == 2)
            if (l_prm->type == TYPE_PARAM_JSON)
                l_json_items = l_prm->value_param;
    }
    if (l_net_str) {
        dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
        if (l_net) {
            dap_chain_t *l_chain = NULL;
            if (l_chain_str) {
                l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
            } else {
                l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
            }
            if (json_object_get_type(l_json_items) == json_type_array) {
                size_t l_items_count = json_object_array_length(l_json_items);
                dap_chain_datum_tx_t *l_tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, sizeof(dap_chain_datum_tx_t));
                l_tx->header.ts_created = time(NULL);
                size_t l_items_ready = 0;
                size_t l_receipt_count = 0;
                dap_list_t *l_in_list = NULL;
                dap_list_t *l_in_cond_list = NULL;
                dap_list_t *l_out_list = NULL;
                dap_list_t *l_sign_list = NULL;
                dap_list_t *l_tsd_list = NULL;
                uint256_t l_value_need = { };// how many tokens are needed in the 'out' item
                const char *l_token_out = NULL;// what token is used in the 'out' item
                // Creating and adding items to the transaction
                for(size_t i = 0; i < l_items_count; ++i) {
                    struct json_object *l_json_item_obj = json_object_array_get_idx(l_json_items, i);
                    if(!l_json_item_obj || !json_object_is_type(l_json_item_obj, json_type_object)) {
                        continue;
                    }
                    struct json_object *l_json_item_type = json_object_object_get(l_json_item_obj, "type");
                    if(!l_json_item_type && json_object_is_type(l_json_item_type, json_type_string)) {
                        log_it(L_WARNING, "Item %zu without type", i);
                        continue;
                    }
                    const char *l_item_type_str = json_object_get_string(l_json_item_type);
                    dap_chain_tx_item_type_t l_item_type = dap_chain_datum_tx_item_str_to_type(l_item_type_str);
                    if(l_item_type == TX_ITEM_TYPE_UNKNOWN) {
                        log_it(L_WARNING, "Item %zu has invalid type '%s'", i, l_item_type_str);
                        continue;
                    }
                    // Create an item depending on its type
                    const uint8_t *l_item = NULL;
                    switch (l_item_type) {
                        case TX_ITEM_TYPE_IN: {
                            // Save item obj for in
                            l_in_list = dap_list_append(l_in_list, l_json_item_obj);
                        }
                            break;
                        case TX_ITEM_TYPE_IN_COND: {
                            // Save item obj for in
                            l_in_cond_list = dap_list_append(l_in_cond_list, l_json_item_obj);
                        }
                            break;
                        case TX_ITEM_TYPE_OUT:
                        case TX_ITEM_TYPE_OUT_EXT: {
                            // Read address and value
                            uint256_t l_value = { };
                            const char *l_json_item_addr_str = dap_json_get_text(l_json_item_obj, "addr");
                            bool l_is_value = dap_json_get_uint256(l_json_item_obj, "value", &l_value);
                            if(l_is_value && l_json_item_addr_str) {
                                dap_chain_addr_t *l_addr = dap_chain_addr_from_str(l_json_item_addr_str);
                                if(l_addr && !IS_ZERO_256(l_value)) {
                                    if(l_item_type == TX_ITEM_TYPE_OUT) {
                                        // Create OUT item
                                        dap_chain_tx_out_t *l_out_item = dap_chain_datum_tx_item_out_create(l_addr, l_value);
                                        l_item = (const uint8_t*) l_out_item;
                                    }
                                    else if(l_item_type == TX_ITEM_TYPE_OUT_EXT) {
                                        // Read address and value
                                        const char *l_token = dap_json_get_text(l_json_item_obj, "token");
                                        if(l_token) {
                                            // Create OUT_EXT item
                                            dap_chain_tx_out_ext_t *l_out_ext_item = dap_chain_datum_tx_item_out_ext_create(l_addr, l_value, l_token);
                                            l_item = (const uint8_t*) l_out_ext_item;
                                            l_token_out = l_token;
                                        }
                                        else {
                                            log_it(L_WARNING, "Invalid 'out_ext' item %zu", i);
                                            continue;
                                        }
                                    }
                                    // Save value for using in In item
                                    if(l_item) {
                                        SUM_256_256(l_value_need, l_value, &l_value_need);
                                    }
                                }
                                else {
                                    if(l_item_type == TX_ITEM_TYPE_OUT) {
                                        log_it(L_WARNING, "Invalid 'out' item %zu", i);
                                    }
                                    else if(l_item_type == TX_ITEM_TYPE_OUT_EXT) {
                                        log_it(L_WARNING, "Invalid 'out_ext' item %zu", i);
                                    }
                                    continue;
                                }
                            }
                        }
                            break;
                        case TX_ITEM_TYPE_OUT_COND: {
                            // Read subtype of item
                            const char *l_subtype_str = dap_json_get_text(l_json_item_obj, "subtype");
                            dap_chain_tx_out_cond_subtype_t l_subtype = dap_chain_tx_out_cond_subtype_from_str(l_subtype_str);
                            switch (l_subtype) {

                                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY:{
                                    uint256_t l_value = { };
                                    bool l_is_value = dap_json_get_uint256(l_json_item_obj, "value", &l_value);
                                    if(!l_is_value || IS_ZERO_256(l_value)) {
                                        break;
                                    }
                                    uint256_t l_value_max_per_unit = { };
                                    l_is_value = dap_json_get_uint256(l_json_item_obj, "value_max_per_unit", &l_value_max_per_unit);
                                    if(!l_is_value || IS_ZERO_256(l_value_max_per_unit)) {
                                        break;
                                    }
                                    dap_chain_net_srv_price_unit_uid_t l_price_unit;
                                    if(!dap_json_get_unit(l_json_item_obj, "price_unit", &l_price_unit)) {
                                        break;
                                    }
                                    dap_chain_net_srv_uid_t l_srv_uid;
                                    if(!dap_json_get_srv_uid(l_json_item_obj, "service_id", "service", &l_srv_uid.uint64)){
                                        // Default service DAP_CHAIN_NET_SRV_VPN_ID
                                        l_srv_uid.uint64 = 0x0000000000000001;
                                    }

                                    // From "wallet" or "cert"
                                    dap_pkey_t *l_pkey = dap_json_get_pkey(l_json_item_obj);
                                    if(!l_pkey) {
                                        break;
                                    }
                                    const char *l_params_str = dap_json_get_text(l_json_item_obj, "params");
                                    size_t l_params_size = dap_strlen(l_params_str);
                                    dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_srv_pay(l_pkey, l_srv_uid, l_value, l_value_max_per_unit,
                                                                                                                               l_price_unit, l_params_str, l_params_size);
                                    l_item = (const uint8_t*) l_out_cond_item;
                                    // Save value for using in In item
                                    if(l_item) {
                                        SUM_256_256(l_value_need, l_value, &l_value_need);
                                    }
                                    DAP_DELETE(l_pkey);
                                }
                                    break;
                                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE: {

                                    dap_chain_net_srv_uid_t l_srv_uid;
                                    if(!dap_json_get_srv_uid(l_json_item_obj, "service_id", "service", &l_srv_uid.uint64)) {
                                        // Default service DAP_CHAIN_NET_SRV_XCHANGE_ID
                                        l_srv_uid.uint64 = 0x2;
                                    }
                                    dap_chain_net_t *l_net = dap_chain_net_by_name(dap_json_get_text(l_json_item_obj, "net"));
                                    if(!l_net) {
                                        break;
                                    }
                                    const char *l_token = dap_json_get_text(l_json_item_obj, "token");
                                    if(!l_token) {
                                        break;
                                    }
                                    uint256_t l_value = { };
                                    if(!dap_json_get_uint256(l_json_item_obj, "value", &l_value) || IS_ZERO_256(l_value)) {
                                        break;
                                    }
                                    const char *l_params_str = dap_json_get_text(l_json_item_obj, "params");
                                    size_t l_params_size = dap_strlen(l_params_str);
                                    dap_chain_tx_out_cond_t *l_out_cond_item = NULL; //dap_chain_datum_tx_item_out_cond_create_srv_xchange(l_srv_uid, l_net->pub.id, l_token, l_value, l_params_str, l_params_size);
                                    l_item = (const uint8_t*) l_out_cond_item;
                                    // Save value for using in In item
                                    if(l_item) {
                                        SUM_256_256(l_value_need, l_value, &l_value_need);
                                        l_token_out = l_token;
                                    }
                                }
                                    break;
                                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE:{
                                    dap_chain_net_srv_uid_t l_srv_uid;
                                    if(!dap_json_get_srv_uid(l_json_item_obj, "service_id", "service", &l_srv_uid.uint64)) {
                                        // Default service DAP_CHAIN_NET_SRV_STAKE_ID
                                        l_srv_uid.uint64 = 0x13;
                                    }
                                    uint256_t l_value = { };
                                    if(!dap_json_get_uint256(l_json_item_obj, "value", &l_value) || IS_ZERO_256(l_value)) {
                                        break;
                                    }
                                    uint256_t l_fee_value = { };
                                    if(!dap_json_get_uint256(l_json_item_obj, "fee", &l_fee_value) || IS_ZERO_256(l_fee_value)) {
                                        break;
                                    }
                                    const char *l_fee_addr_str = dap_json_get_text(l_json_item_obj, "fee_addr");
                                    const char *l_hldr_addr_str = dap_json_get_text(l_json_item_obj, "hldr_addr");
                                    const char *l_signing_addr_str = dap_json_get_text(l_json_item_obj, "signing_addr");
                                    dap_chain_addr_t *l_fee_addr = dap_chain_addr_from_str(l_fee_addr_str);
                                    dap_chain_addr_t *l_hldr_addr = dap_chain_addr_from_str(l_hldr_addr_str);
                                    dap_chain_addr_t *l_signing_addr = dap_chain_addr_from_str(l_signing_addr_str);
                                    if(!l_fee_addr || !l_hldr_addr || !l_signing_addr) {
                                        break;
                                    }
                                    dap_chain_node_addr_t l_signer_node_addr;
                                    const char *l_node_addr_str = dap_json_get_text(l_json_item_obj, "node_addr");
                                    if(!l_node_addr_str || dap_chain_node_addr_from_str(&l_signer_node_addr, l_node_addr_str)) {
                                        break;
                                    }
                                    dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_srv_stake(l_srv_uid, l_value, l_fee_value,
                                                                                                                                 l_fee_addr, l_hldr_addr, l_signing_addr, &l_signer_node_addr);
                                    l_item = (const uint8_t*) l_out_cond_item;
                                    // Save value for using in In item
                                    if(l_item) {
                                        SUM_256_256(l_value_need, l_value, &l_value_need);
                                    }
                                }
                                    break;
                                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE: {
                                    uint256_t l_value = { };
                                    bool l_is_value = dap_json_get_uint256(l_json_item_obj, "value", &l_value);
                                    if(!IS_ZERO_256(l_value)) {
                                        dap_chain_tx_out_cond_t *l_out_cond_item = dap_chain_datum_tx_item_out_cond_create_fee(l_value);
                                        l_item = (const uint8_t*) l_out_cond_item;
                                        // Save value for using in In item
                                        if(l_item) {
                                            SUM_256_256(l_value_need, l_value, &l_value_need);
                                        }
                                    }
                                }
                                    break;
                                case DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED:
                                    log_it(L_WARNING, "Undefined subtype: '%s' of 'out_cond' item %zu ", l_subtype_str, i);
                                    break;
                            }
                        }

                            break;
                        case TX_ITEM_TYPE_SIG: {
                            // Save item obj for sign
                            l_sign_list = dap_list_append(l_sign_list, l_json_item_obj);
                        }
                            break;
                        case TX_ITEM_TYPE_RECEIPT: {
                            dap_chain_net_srv_uid_t l_srv_uid;
                            if(!dap_json_get_srv_uid(l_json_item_obj, "service_id", "service", &l_srv_uid.uint64)) {
                                break;
                            }
                            dap_chain_net_srv_price_unit_uid_t l_price_unit;
                            if(!dap_json_get_unit(l_json_item_obj, "price_unit", &l_price_unit)) {
                                break;
                            }
                            int64_t l_units;
                            if(!dap_json_get_int64(l_json_item_obj, "units", &l_units)) {
                                break;
                            }
                            uint256_t l_value = { };
                            if(!dap_json_get_uint256(l_json_item_obj, "value", &l_value) || IS_ZERO_256(l_value)) {
                                break;
                            }
                            const char *l_params_str = dap_json_get_text(l_json_item_obj, "params");
                            size_t l_params_size = dap_strlen(l_params_str);
                            dap_chain_datum_tx_receipt_t *l_receipt = dap_chain_datum_tx_receipt_create(l_srv_uid, l_price_unit, l_units, l_value, l_params_str, l_params_size);
                            l_item = (const uint8_t*) l_receipt;
                            if(l_item)
                                l_receipt_count++;
                        }
                            break;
                        case TX_ITEM_TYPE_TSD: {
                            int64_t l_tsd_type;
                            if(!dap_json_get_int64(l_json_item_obj, "type_tsd", &l_tsd_type)) {
                                break;
                            }
                            const char *l_tsd_data = dap_json_get_text(l_json_item_obj, "data");
                            if (!l_tsd_data) {
                                break;
                            }
                            size_t l_data_size = dap_strlen(l_tsd_data);
                            dap_chain_tx_tsd_t *l_tsd = dap_chain_datum_tx_item_tsd_create((void*)l_tsd_data, (int)l_tsd_type, l_data_size);
                            l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
                        }
                            break;
                            //case TX_ITEM_TYPE_PKEY:
                            //break;
                            //case TX_ITEM_TYPE_TOKEN:
                            //break;
                            //case TX_ITEM_TYPE_TOKEN_EXT:
                            //break;
                    }
                    // Add item to transaction
                    if(l_item) {
                        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_item);
                        l_items_ready++;
                    }
                }

                // Add In items
                dap_list_t *l_list = l_in_list;
                while(l_list) {
                    const uint8_t *l_item = NULL;
                    struct json_object *l_json_item_obj = (struct json_object*) l_list->data;
                    // Read prev_hash and out_prev_idx
                    const char *l_prev_hash_str = dap_json_get_text(l_json_item_obj, "prev_hash");
                    int64_t l_out_prev_idx;
                    bool l_is_out_prev_idx = dap_json_get_int64(l_json_item_obj, "out_prev_idx", &l_out_prev_idx);
                    // If prev_hash and out_prev_idx were read
                    if(l_prev_hash_str && l_is_out_prev_idx) {
                        dap_chain_hash_fast_t l_tx_prev_hash;
                        if(!dap_chain_hash_fast_from_str(l_prev_hash_str, &l_tx_prev_hash)) {
                            // Create IN item
                            dap_chain_tx_in_t *l_in_item = dap_chain_datum_tx_item_in_create(&l_tx_prev_hash, (uint32_t) l_out_prev_idx);
                            l_item = (const uint8_t*) l_in_item;
                        }
                        else {
                            log_it(L_WARNING, "Invalid 'in' item, bad prev_hash %s", l_prev_hash_str);
                            // Go to the next item
                            l_list = dap_list_next(l_list);
                            continue;
                        }
                    }
                        // Read addr_from
                    else {
                        const char *l_json_item_addr_str = dap_json_get_text(l_json_item_obj, "addr_from");
                        const char *l_json_item_token = dap_json_get_text(l_json_item_obj, "token");
                        dap_chain_addr_t *l_addr_from = NULL;
                        if(l_json_item_addr_str) {
                            l_addr_from = dap_chain_addr_from_str(l_json_item_addr_str);
                        }
                        else {
                            log_it(L_WARNING, "Invalid 'in' item, incorrect addr_from: '%s'", l_json_item_addr_str ? l_json_item_addr_str : "[null]");
                            // Go to the next item
                            l_list = dap_list_next(l_list);
                            continue;
                        }
                        if(!l_json_item_token) {
                            log_it(L_WARNING, "Invalid 'in' item, not found token name");
                            // Go to the next item
                            l_list = dap_list_next(l_list);
                            continue;
                        }
                        if(IS_ZERO_256(l_value_need)) {
                            log_it(L_WARNING, "Invalid 'in' item, not found value in out items");
                            // Go to the next item
                            l_list = dap_list_next(l_list);
                            continue;
                        }
                        if(l_addr_from)
                        {
                            // find the transactions from which to take away coins
                            uint256_t l_value_transfer = { }; // how many coins to transfer
                            //SUM_256_256(a_value, a_value_fee, &l_value_need);
                            dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_outs_with_val(l_chain->ledger, l_json_item_token,
                                                                                                     l_addr_from, l_value_need, &l_value_transfer);
                            if(!l_list_used_out) {
                                log_it(L_WARNING, "Not enough funds in previous tx to transfer");
                                // Go to the next item
                                l_list = dap_list_next(l_list);
                                continue;
                            }
                            // add 'in' items
                            uint256_t l_value_got = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
                            assert(EQUAL_256(l_value_got, l_value_transfer));
                            dap_list_free_full(l_list_used_out, free);
                            if(!IS_ZERO_256(l_value_got)) {
                                l_items_ready++;

                                // add 'out' item for coin back
                                uint256_t l_value_back;
                                SUBTRACT_256_256(l_value_got, l_value_need, &l_value_back);
                                if(!IS_ZERO_256(l_value_back)) {
                                    dap_chain_datum_tx_add_out_item(&l_tx, l_addr_from, l_value_back);
                                }
                            }
                        }
                    }
                    // Go to the next 'in' item
                    l_list = dap_list_next(l_list);
                }
                dap_list_free(l_in_list);


                // Add in_cond items
                l_list = l_in_cond_list;
                while(l_list) {
                    const uint8_t *l_item = NULL;
                    struct json_object *l_json_item_obj = (struct json_object*) l_list->data;

                    // Read prev_hash and out_prev_idx
                    const char *l_prev_hash_str = dap_json_get_text(l_json_item_obj, "prev_hash");
                    int64_t l_out_prev_idx;
                    int64_t l_receipt_idx;
                    bool l_is_out_prev_idx = dap_json_get_int64(l_json_item_obj, "out_prev_idx", &l_out_prev_idx);
                    bool l_is_receipt_idx = dap_json_get_int64(l_json_item_obj, "receipt_idx", &l_receipt_idx);
                    if(l_prev_hash_str && l_is_out_prev_idx && l_is_receipt_idx) {
                        dap_chain_hash_fast_t l_tx_prev_hash;
                        if(!dap_chain_hash_fast_from_str(l_prev_hash_str, &l_tx_prev_hash)) {
                            // Create IN_COND item
                            dap_chain_tx_in_cond_t *l_in_cond_item = dap_chain_datum_tx_item_in_cond_create(&l_tx_prev_hash, (uint32_t) l_out_prev_idx, (uint32_t) l_receipt_idx);
                            l_item = (const uint8_t*) l_in_cond_item;
                        }
                    }
                        // Read addr_from
                    else {
                        // Get receipt number
                        int64_t l_receipt_idx = 0;
                        // If not only one receipt exists
                        if(l_receipt_count != 1) {
                            if(!l_receipt_count) {
                                log_it(L_WARNING, "Found %zu receipt", l_receipt_count);
                                // Go to the next item
                                l_list = dap_list_next(l_list);
                                continue;
                            }
                            bool l_is_receipt_idx = dap_json_get_int64(l_json_item_obj, "receipt_idx", &l_receipt_idx);
                            if(!l_is_receipt_idx) {
                                log_it(L_WARNING, "Found %zu receipts, add parameter 'receipt_idx' to select required receipts", l_receipt_count);
                                // Go to the next item
                                l_list = dap_list_next(l_list);
                                continue;
                            }
                        }

                        const char *l_json_item_addr_str = dap_json_get_text(l_json_item_obj, "addr_from");
                        const char *l_json_item_token = dap_json_get_text(l_json_item_obj, "token");
                        const char *l_subtype_str = dap_json_get_text(l_json_item_obj, "subtype");
                        dap_chain_addr_t *l_addr_from = NULL;
                        if(l_json_item_addr_str) {
                            l_addr_from = dap_chain_addr_from_str(l_json_item_addr_str);
                        }
                        else {
                            log_it(L_WARNING, "Invalid 'in_cond' item, incorrect addr_from: '%s'", l_json_item_addr_str ? l_json_item_addr_str : "[null]");
                            // Go to the next item
                            l_list = dap_list_next(l_list);
                            continue;
                        }
                        if(!l_json_item_token) {
                            log_it(L_WARNING, "Invalid 'in_cond' item, not found token name");
                            // Go to the next item
                            l_list = dap_list_next(l_list);
                            continue;
                        }
                        if(IS_ZERO_256(l_value_need)) {
                            log_it(L_WARNING, "Invalid 'in_cond' item, not found value in out items");
                            // Go to the next item
                            l_list = dap_list_next(l_list);
                            continue;
                        }
                        if(!l_subtype_str) {
                            log_it(L_WARNING, "Invalid 'in_cond' item, not found subtype name");
                            // Go to the next item
                            l_list = dap_list_next(l_list);
                            continue;
                        }
                        if(l_addr_from)
                        {
                            dap_chain_tx_out_cond_subtype_t l_subtype = dap_chain_tx_out_cond_subtype_from_str(l_subtype_str);
                            // find the transactions from which to take away coins
                            uint256_t l_value_transfer = { }; // how many coins to transfer
                            dap_list_t *l_list_used_out = dap_chain_ledger_get_list_tx_cond_outs_with_val(l_chain->ledger, l_json_item_token,
                                                                                                          l_addr_from, l_subtype, l_value_need, &l_value_transfer);
                            if(!l_list_used_out) {
                                log_it(L_WARNING, "Not enough funds in previous tx to transfer");
                                // Go to the next item
                                l_list = dap_list_next(l_list);
                                continue;
                            }
                            // add 'in_cond' items
                            dap_list_t *l_list_tmp = l_list_used_out;
                            uint256_t l_value_got = { }; // how many datoshi to transfer
                            while(l_list_tmp) {
                                list_used_item_t *l_item = l_list_tmp->data;
                                if(dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_item->tx_hash_fast, l_item->num_idx_out, l_receipt_idx) != -1) {
                                    //if (dap_chain_datum_tx_add_in_item(&l_tx, &l_item->tx_hash_fast, l_item->num_idx_out) == 1) {
                                    SUM_256_256(l_value_got, l_item->value, &l_value_got);
                                }
                                l_list_tmp = dap_list_next(l_list_tmp);
                            }
                            dap_list_free_full(l_list_used_out, free);
                            //uint256_t l_value_got = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
                            assert(EQUAL_256(l_value_got, l_value_transfer));
                            if(!IS_ZERO_256(l_value_got)) {
                                l_items_ready++;

                                // add 'out' item for coin back
                                uint256_t l_value_back;
                                SUBTRACT_256_256(l_value_got, l_value_need, &l_value_back);
                                if(!IS_ZERO_256(l_value_back)) {
                                    dap_chain_datum_tx_add_out_item(&l_tx, l_addr_from, l_value_back);
                                }
                            }
                        }

                    }

                    // Go to the next 'in_cond' item
                    l_list = dap_list_next(l_list);
                }
                dap_list_free(l_in_cond_list);

                // Add TSD section
                l_list = l_tsd_list;
                while(l_list) {
                    dap_chain_datum_tx_add_item(&l_tx, l_list->data);
                    l_items_ready++;
                    l_list = dap_list_next(l_list);
                }
                dap_list_free(l_tsd_list);

                // Add signs
                l_list = l_sign_list;
                while(l_list){
                    bool is_add = false;
                    struct json_object *l_json_item_obj = (struct json_object*) l_list->data;
                    // From wallet
                    dap_chain_wallet_t *l_wallet = dap_json_get_wallet(l_json_item_obj, "wallet");
                    if(l_wallet) {
                        dap_enc_key_t *l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);
                        // sign all previous items in transaction
                        if(dap_chain_datum_tx_add_sign_item(&l_tx, l_enc_key)>0){
                            is_add = true;
                            l_items_ready++;
                        }
                        dap_chain_wallet_close(l_wallet);
                    }
                    // If wallet not found
                    if(!is_add) {
                        // From cert
                        const dap_cert_t *l_cert = dap_json_get_cert(l_json_item_obj, "cert");
                        if(l_cert && l_cert->enc_key) {
                            // sign all previous items in transaction
                            if(dap_chain_datum_tx_add_sign_item(&l_tx, l_cert->enc_key) > 0) {
                                is_add = true;
                                l_items_ready++;
                            }
                        }
                    }
                    l_list = dap_list_next(l_list);
                }
                dap_list_free(l_sign_list);
                if (l_items_ready == l_items_count) {
                    // Pack transaction into the datum
                    dap_chain_datum_t *l_datum_tx = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, dap_chain_datum_tx_get_size(l_tx));
                    size_t l_datum_tx_size = dap_chain_datum_size(l_datum_tx);
                    DAP_DELETE(l_tx);

                    // Add transaction to mempool
                    char *l_gdb_group_mempool_base_tx = dap_chain_net_get_gdb_group_mempool(l_chain);// get group name for mempool
                    dap_chain_hash_fast_t *l_datum_tx_hash = DAP_NEW(dap_hash_fast_t);
                    dap_hash_fast(l_datum_tx->data, l_datum_tx->header.data_size, l_datum_tx_hash);// Calculate datum hash
                    char *l_tx_hash_str = dap_chain_hash_fast_to_str_new(l_datum_tx_hash);
                    bool l_placed = dap_chain_global_db_gr_set(l_tx_hash_str, l_datum_tx, l_datum_tx_size, l_gdb_group_mempool_base_tx);

                    DAP_DELETE(l_datum_tx);
                    DAP_DELETE(l_gdb_group_mempool_base_tx);
                    if(!l_placed) {
                        DAP_DELETE(l_tx_hash_str);
//                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't add transaction to mempool");
                        return -90;
                    }
                    // Completed successfully
                    json_object *l_result = json_object_new_object();
                    json_object *l_new_tx = json_object_new_string(l_tx_hash_str);
                    json_object_object_add(l_result, "hash", l_new_tx);
                    a_response->type_result = TYPE_RESPONSE_JSON;
                    a_response->result_json_object = l_result;
//                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Transaction %s with %d items created and added to mempool successfully", l_tx_hash_str, l_items_ready);
                    DAP_DELETE(l_tx_hash_str);
//                    return l_err_code;
                } else {}
//                json_object_put(l_json);
            } else {
                // TODO: ERROR JSON
            }
        } else {
            //TODO: ERROR can't net find.
        }
//        json_object_object_foreach()
    } else  {
        //TODO: ERROR net
    }
}

#undef LOG_TAG