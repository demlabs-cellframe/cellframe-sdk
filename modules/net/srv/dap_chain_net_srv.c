/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Aleksandr Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

 DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 DAP is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#ifdef DAP_OS_LINUX
#include <dlfcn.h>
#endif
#include "json.h"
#include "json_object.h"
#include <pthread.h>
#include <dirent.h>
#include "uthash.h"
#include "utlist.h"

#include "dap_chain_net.h"
#include "dap_hash.h"
#include "dap_common.h"
#include "dap_enc_base58.h"
#include "dap_list.h"
#include "dap_string.h"
#include "dap_file_utils.h"
#include "dap_chain.h"
#include "dap_chain_common.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_net_srv_order.h"
#include "dap_chain_net_srv_stream_session.h"
#include "dap_stream_ch_chain_net_srv.h"
#include "dap_chain_cs_blocks.h"
#ifdef DAP_MODULES_DYNAMIC
#include "dap_modules_dynamic_cdb.h"
#endif

#include "dap_chain_node_cli_cmd.h"

#define LOG_TAG "chain_net_srv"

typedef struct service_list {
    dap_chain_net_srv_uid_t uid;
    dap_chain_net_srv_t * srv;
    char name[32];
    UT_hash_handle hh;
} service_list_t;

// list of active services
static service_list_t *s_srv_list = NULL;
// for separate access to s_srv_list
static pthread_mutex_t s_srv_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static int s_cli_net_srv(int argc, char **argv, void **reply, int a_version);
static void s_load(const char * a_path);
static void s_load_all();

static int s_pay_verificator_callback(dap_ledger_t * a_ledger, dap_chain_tx_out_cond_t *a_cond,
                                       dap_chain_datum_tx_t *a_tx_in, bool a_owner);
static int s_fee_verificator_callback(dap_ledger_t * a_ledger, dap_chain_tx_out_cond_t *a_cond,
                                       dap_chain_datum_tx_t *a_tx_in, bool a_owner);
static int s_str_to_price_unit(const char *a_price_unit_str, dap_chain_net_srv_price_unit_uid_t *a_price_unit);

/**
 * @brief dap_chain_net_srv_init
 * @return
 */
int dap_chain_net_srv_init()
{
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, s_pay_verificator_callback, NULL, NULL);
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE, s_fee_verificator_callback, NULL, NULL);

    dap_cli_server_cmd_add ("net_srv", s_cli_net_srv, "Network services managment",
        "net_srv -net <net_name> order find [-direction {sell|buy}] [-srv_uid <service_UID>] [-price_unit <price_unit>]"
        " [-price_token <token_ticker>] [-price_min <price_minimum>] [-price_max <price_maximum>]\n"
        "\tOrders list, all or by UID and/or class\n"
        "net_srv -net <net_name> order delete -hash <order_hash>\n"
        "\tOrder delete\n"
        "net_srv -net <net_name> order dump -hash <order_hash>\n"
        "\tOrder dump info\n"
        "net_srv -net <net_name> order create -direction {sell|buy} -srv_uid <service_UID> -price <price>\n"
        " -price_unit <price_unit> -price_token <token_ticker> -units <units> [-node_addr <node_address>] [-tx_cond <TX_cond_hash>]\n"
        " [-expires <unix_time_when_expires>] [-cert <cert_name_to_sign_order>]\n"
        " [{-ext <extension_with_params>|-region <region_name> -continent <continent_name>}]\n"
        "net_srv get_limits -net <net_name> -srv_uid <service_UID> -provider_pkey_hash <service_provider_public_key_hash> -client_pkey_hash <client_public_key_hash>\n"
        "net_srv report\n"
        "\tGet report about srv usage"
        );

    s_load_all();

    return 0;
}

/**
 * @brief s_load_all
 */
void s_load_all()
{
    char * l_net_dir_str = dap_strdup_printf("%s/service.d", dap_config_path());
    DIR * l_net_dir = opendir( l_net_dir_str);
    if ( l_net_dir ) {
        struct dirent * l_dir_entry = NULL;
        while ( (l_dir_entry = readdir(l_net_dir) )!= NULL ){
            if (l_dir_entry->d_name[0]=='\0' || l_dir_entry->d_name[0]=='.')
                continue;
            // don't search in directories
            char l_full_path[MAX_PATH + 1];
            snprintf(l_full_path, sizeof(l_full_path), "%s/%s", l_net_dir_str, l_dir_entry->d_name);
            if(dap_dir_test(l_full_path)) {
                continue;
            }
            // search only ".cfg" files
            if(strlen(l_dir_entry->d_name) > 4) { // It has non zero name excluding file extension
                if(strncmp(l_dir_entry->d_name + strlen(l_dir_entry->d_name) - 4, ".cfg", 4) != 0) {
                    // its not .cfg file
                    continue;
                }
            }
            log_it(L_DEBUG,"Service config %s try to load", l_dir_entry->d_name);
            //char* l_dot_pos = rindex(l_dir_entry->d_name,'.');
            char* l_dot_pos = strchr(l_dir_entry->d_name,'.');
            if ( l_dot_pos )
                *l_dot_pos = '\0';
            s_load(l_full_path );
        }
        closedir(l_net_dir);
    }
    DAP_DELETE (l_net_dir_str);
}

/**
 * @brief s_load
 * @param a_name
 */
static void s_load(const char * a_path)
{
    log_it ( L_INFO, "Service config %s", a_path);
    // TODO open service
}


/**
 * @brief dap_chain_net_srv_deinit
 */
void dap_chain_net_srv_deinit(void)
{
    // TODO Stop all services

    dap_chain_net_srv_del_all();
}

/**
 * @brief s_cli_net_srv
 * @param argc
 * @param argv
 * @param a_str_reply
 * @return
 */
static int s_cli_net_srv( int argc, char **argv, void **a_str_reply, int a_version)
{
    json_object **json_arr_reply = (json_object **)a_str_reply;
    int arg_index = 1;
    dap_chain_net_t * l_net = NULL;    
    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type, "hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_HASH_ERR, "invalid parameter -H, valid values: -H <hex | base58>");
        return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_HASH_ERR;
    }

    int l_report = dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "report", NULL);
    if (l_report) {
        json_object* json_obj_net_srv = json_object_new_object();
        char *l_report_str = dap_stream_ch_chain_net_srv_create_statistic_report();
        json_object_object_add(json_obj_net_srv, "report", json_object_new_string(l_report_str));
        DAP_DELETE(l_report_str);

        json_object_array_add(*json_arr_reply, json_obj_net_srv);
        return DAP_CHAIN_NET_SRV_CLI_COM_ORDER_OK;
    }

    int l_ret = dap_chain_node_cli_cmd_values_parse_net_chain_for_json(*json_arr_reply, &arg_index, argc, argv, NULL, &l_net, CHAIN_TYPE_INVALID);
    json_object* json_obj_net_srv = NULL;
    if ( l_net ) {

        const char *l_order_str = NULL;
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "order", &l_order_str);

        const char *l_get_limits_str = NULL;
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "get_limits", &l_get_limits_str);

        // Order direction
        const char *l_direction_str = NULL;
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-direction", &l_direction_str);

        const char* l_srv_uid_str = NULL;
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-srv_uid", &l_srv_uid_str);

        const char* l_srv_class_str = NULL;
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-srv_class", &l_srv_class_str);

        const char* l_node_addr_str = NULL;
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-node_addr", &l_node_addr_str);

        const char* l_tx_cond_hash_str = NULL;
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-tx_cond", &l_tx_cond_hash_str);

        const char* l_price_str = NULL;
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-price", &l_price_str);

        const char* l_expires_str = NULL;
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-expires", &l_expires_str);

        const char* l_price_unit_str = NULL;
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-price_unit", &l_price_unit_str);

        const char* l_price_token_str = NULL;
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-price_token", &l_price_token_str);

        const char* l_ext = NULL;
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-ext", &l_ext);

        const char *l_order_hash_str = NULL;
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-hash", &l_order_hash_str);

        const char* l_region_str = NULL;
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-region", &l_region_str);

        const char* l_continent_str = NULL;
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-continent", &l_continent_str);
        int8_t l_continent_num = dap_chain_net_srv_order_continent_to_num(l_continent_str);

        const char *l_units_str = NULL;
        dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-units", &l_units_str);

        if (l_order_str){
            char l_order_hash_hex_str[128] = "", l_order_hash_base58_str[128] = "";
            // datum hash may be in hex or base58 format
            if (l_order_hash_str) {
                if(!dap_strncmp(l_order_hash_str, "0x", 2) || !dap_strncmp(l_order_hash_str, "0X", 2)) {
                    dap_strncpy(l_order_hash_hex_str, l_order_hash_str, sizeof(l_order_hash_hex_str));
                    char *l_tmp = dap_enc_base58_from_hex_str_to_str(l_order_hash_str);
                    dap_strncpy(l_order_hash_base58_str, l_tmp, sizeof(l_order_hash_base58_str));
                    DAP_DELETE(l_tmp);
                } else {
                    char *l_tmp = dap_enc_base58_to_hex_str_from_str(l_order_hash_str);
                    dap_strncpy(l_order_hash_hex_str, l_tmp, sizeof(l_order_hash_hex_str));
                    DAP_DELETE(l_tmp);
                    dap_strncpy(l_order_hash_base58_str, l_order_hash_str, sizeof(l_order_hash_base58_str));
                }
            }
            if(l_continent_str && l_continent_num <= 0) {         
                dap_string_t *l_string_err = dap_string_new("Unrecognized \"-continent\" option=");
                dap_string_append_printf(l_string_err, "\"%s\". Variants: ", l_continent_str);
                int i;
                for (i = 0; i < (int)dap_chain_net_srv_order_continents_count() - 1; ++i)
                    dap_string_append_printf(l_string_err, "\"%s\", ", dap_chain_net_srv_order_continent_to_str(i));
                dap_string_append_printf(l_string_err, "\"%s\"", dap_chain_net_srv_order_continent_to_str(i));

                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CONT_ERR, "%s\n", l_string_err->str);
                dap_string_free(l_string_err, true);
                l_ret = -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CONT_ERR;
            } else if (!dap_strcmp(l_order_str, "update")) {
                if (!l_order_hash_str) {
                    dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_ERR, "Can't find option '-hash'\n");
                    l_ret = -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_ERR;
                } else {
                    dap_chain_net_srv_order_t * l_order = dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_hex_str);
                    if(!l_order) {
                        l_ret = -2;
                        if(!dap_strcmp(l_hash_out_type,"hex"))
                            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_HASH_ERR, "Can't find order with hash %s\n", l_order_hash_hex_str);
                        else
                            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_HASH_ERR, "Can't find order with hash %s\n", l_order_hash_base58_str);
                    } else {
                        if (l_ext) {
                            l_order->ext_size = strlen(l_ext) + 1;
                            dap_chain_net_srv_order_t *l_order_new = DAP_REALLOC_RET_VAL_IF_FAIL(l_order, sizeof(dap_chain_net_srv_order_t) + l_order->ext_size,
                                                                                                 -7, l_order, l_order_hash_hex_str, l_order_hash_base58_str);
                            l_order = l_order_new;
                            memcpy(l_order->ext_n_sign, l_ext, l_order->ext_size);
                        } else
                            dap_chain_net_srv_order_set_continent_region(&l_order, l_continent_num, l_region_str);
                        char *l_new_order_hash_str = dap_chain_net_srv_order_save(l_net, l_order, false);
                        if (l_new_order_hash_str) {
                            /*const char *l_cert_str = NULL;
                            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-cert", &l_cert_str);
                            if (!l_cert_str) {
                                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_PARAM_CERT_ERR, "Fee order creation requires parameter -cert");
                                return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_PARAM_CERT_ERR;
                            }
                            dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
                            if (!l_cert) {
                                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_LOAD_CERT_ERR, "Can't load cert %s", l_cert_str);
                                DAP_DEL_MULTY(l_new_order_hash_str, l_order_hash_hex_str, l_order_hash_base58_str, l_order);
                                return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_LOAD_CERT_ERR;
                            }
                            */ // WTF is this? ^^^
                            // delete prev order
                            if(dap_strcmp(l_new_order_hash_str, l_order_hash_hex_str))
                                dap_chain_net_srv_order_delete_by_hash_str_sync(l_net, l_order_hash_hex_str);
                            DAP_DELETE(l_new_order_hash_str);
                            json_obj_net_srv = json_object_new_object();
                            json_object_object_add(json_obj_net_srv, "status", json_object_new_string("updated"));
                        } else {
                            json_obj_net_srv = json_object_new_object();
                            json_object_object_add(json_obj_net_srv, "status", json_object_new_string("not updated"));
                        }
                        DAP_DELETE(l_order);
                    }
                }
            } else if (!dap_strcmp( l_order_str, "find" )) {
            // Order direction
                const char *l_direction_str = NULL;
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-direction", &l_direction_str);

            // Select with specified service uid
                const char *l_srv_uid_str = NULL;
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-srv_uid", &l_srv_uid_str);

            // Select with specified price units
                const char*  l_price_unit_str = NULL;
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-price_unit", &l_price_unit_str);

            // Token ticker
                const char*  l_price_token_str = NULL;
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-price_token", &l_price_token_str);

            // Select with price not more than price_min
                const char*  l_price_min_str = NULL;
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-price_min", &l_price_min_str);

            // Select with price not more than price_max
                const char*  l_price_max_str = NULL;
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-price_max", &l_price_max_str);

                dap_chain_net_srv_order_direction_t l_direction = SERV_DIR_UNDEFINED;
                dap_chain_net_srv_uid_t l_srv_uid={{0}};
                uint256_t l_price_min = {};
                uint256_t l_price_max = {};
                dap_chain_net_srv_price_unit_uid_t l_price_unit={{0}};

                if ( l_direction_str ) {
                    if (!strcmp(l_direction_str, "sell"))
                        l_direction = SERV_DIR_SELL;
                    else if (!strcmp(l_direction_str, "buy"))
                        l_direction = SERV_DIR_BUY;
                    else {                        
                        dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_PARAM_CERT_ERR, "Wrong direction of the token was "
                                                                       "specified, possible directions: buy, sell.");
                        return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_PARAM_CERT_ERR;
                    }
                }

                if (l_srv_uid_str && dap_id_uint64_parse(l_srv_uid_str ,&l_srv_uid.uint64)) {
                    dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_HEX_ERR,
                                                                        "Can't recognize '%s' string as 64-bit id, hex or dec.", l_srv_uid_str);
                    return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_HEX_ERR;
                }

                if ( l_price_min_str )
                    l_price_min = dap_chain_balance_scan(l_price_min_str);

                if ( l_price_max_str )
                    l_price_max = dap_chain_balance_scan(l_price_max_str);

                l_price_unit.uint32 = dap_chain_srv_str_to_unit_enum(l_price_unit_str);

                dap_list_t *l_orders;
                size_t l_orders_num = 0;
                if( !dap_chain_net_srv_order_find_all_by(l_net, l_direction, l_srv_uid,
                                                        l_price_unit, l_price_token_str,
                                                        l_price_min, l_price_max,
                                                        &l_orders, &l_orders_num) )
                {
                    json_obj_net_srv = json_object_new_object();
                    json_object_object_add(json_obj_net_srv, "count", json_object_new_uint64(l_orders_num));
                    json_object* json_arr_out = json_object_new_array();
                    for (dap_list_t *l_temp = l_orders; l_temp; l_temp = l_temp->next){
                        json_object* json_obj_order = json_object_new_object();
                        dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t*)l_temp->data;
                        dap_chain_net_srv_order_dump_to_json(l_order, json_obj_order, l_hash_out_type, l_net->pub.native_ticker, a_version);
                        json_object_array_add(json_arr_out, json_obj_order);
                    }
                    json_object_object_add(json_obj_net_srv, "orders", json_arr_out);
                    l_ret = 0;
                    dap_list_free_full(l_orders, NULL);
                } else {                    
                    dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_CANT_GET_ERR, "Can't get orders: some internal error or wrong params");
                    l_ret = -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_CANT_GET_ERR ;
                }
            } else if(!dap_strcmp( l_order_str, "dump" )) {
                // Select with specified service uid
                if ( l_order_hash_str ){
                    dap_chain_net_srv_order_t * l_order = dap_chain_net_srv_order_find_by_hash_str( l_net, l_order_hash_hex_str );
                    json_obj_net_srv = json_object_new_object();                    
                    if (l_order) {
                        dap_chain_net_srv_order_dump_to_json(l_order, json_obj_net_srv, l_hash_out_type, l_net->pub.native_ticker, a_version);
                        l_ret = 0;
                    }else{                        
                        if(!dap_strcmp(l_hash_out_type,"hex"))
                            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_DUMP_CANT_FIND_ERR,
                                                        "Can't find order with hash %s\n", l_order_hash_hex_str );
                        else
                            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_DUMP_CANT_FIND_ERR,
                                                        "Can't find order with hash %s\n", l_order_hash_base58_str );
                        l_ret = -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_DUMP_CANT_FIND_ERR ;
                    }
                } else {
                    dap_list_t * l_orders = NULL;
                    size_t l_orders_num = 0;
                    dap_chain_net_srv_uid_t l_srv_uid={{0}};
                    uint256_t l_price_min = {};
                    uint256_t l_price_max = {};
                    dap_chain_net_srv_price_unit_uid_t l_price_unit={{0}};
                    dap_chain_net_srv_order_direction_t l_direction = SERV_DIR_UNDEFINED;

                    if( !dap_chain_net_srv_order_find_all_by( l_net,l_direction,l_srv_uid,l_price_unit, NULL, l_price_min, l_price_max,&l_orders,&l_orders_num) ){
                        json_obj_net_srv = json_object_new_object();
                        json_object_object_add(json_obj_net_srv, "count", json_object_new_uint64(l_orders_num));
                        json_object* json_arr_out = json_object_new_array();
                        for(dap_list_t *l_temp = l_orders;l_temp; l_temp = l_orders->next) {
                            json_object* json_obj_order = json_object_new_object();
                            dap_chain_net_srv_order_t *l_order =(dap_chain_net_srv_order_t *) l_temp->data;
                            dap_chain_net_srv_order_dump_to_json(l_order, json_obj_order, l_hash_out_type, l_net->pub.native_ticker, a_version);
                            json_object_array_add(json_arr_out, json_obj_order);
                        }
                        json_object_object_add(json_obj_net_srv, "orders", json_arr_out);
                        l_ret = 0;
                    }else{
                        dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_CANT_GET_ERR,"Can't get orders: some internal error or wrong params");
                        l_ret = -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_CANT_GET_ERR ;
                    }
                    dap_list_free_full(l_orders, NULL);
                }
            } else if (!dap_strcmp(l_order_str, "delete")) {
                if (l_order_hash_str) {
                    json_obj_net_srv = json_object_new_object();
                    l_ret = dap_chain_net_srv_order_delete_by_hash_str_sync(l_net, l_order_hash_hex_str);
                    if (!l_ret)
                        json_object_object_add(json_obj_net_srv, "order_hash", json_object_new_string(l_order_hash_str));
                    else {
                        dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_DEL_CANT_FIND_HASH_ERR, "Can't find order with hash %s\n", l_order_hash_str);
                        l_ret = -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_DEL_CANT_FIND_HASH_ERR;
                    }
                } else {
                    dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_DEL_NEED_HASH_PARAM_ERR, "need -hash param to obtain what the order we need to dump\n");
                    l_ret = -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_DEL_NEED_HASH_PARAM_ERR;
                }
            } else if(!dap_strcmp( l_order_str, "create" )) {
                if (dap_chain_net_get_role(l_net).enums > NODE_ROLE_MASTER) {
                    dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_ROLE_ERR, "Node role should be not lower than master\n");
                    return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_ROLE_ERR;
                }
                const char *l_order_cert_name = NULL;
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-cert", &l_order_cert_name);
                if ( l_srv_uid_str && l_price_str && l_price_token_str && l_price_unit_str && l_units_str) {
                    dap_chain_net_srv_uid_t l_srv_uid={{0}};
                    dap_chain_node_addr_t l_node_addr={0};
                    dap_chain_hash_fast_t l_tx_cond_hash={{0}};
                    dap_time_t l_expires = 0; // TS when the service expires
                    uint256_t l_price = {0};
                    char l_price_token[DAP_CHAIN_TICKER_SIZE_MAX]={0};
                    dap_chain_net_srv_price_unit_uid_t l_price_unit={{0}};
                    dap_chain_net_srv_order_direction_t l_direction = SERV_DIR_UNDEFINED;
                    if ( l_direction_str ){
                        if (!strcmp(l_direction_str, "sell")) {
                            l_direction = SERV_DIR_SELL;
                            log_it(L_DEBUG, "Created order to sell");
                        } else if (!strcmp(l_direction_str, "buy")) {
                            l_direction = SERV_DIR_BUY;
                            log_it(L_DEBUG, "Created order to buy");
                        } else {
                            log_it(L_WARNING, "Undefined order direction");
                            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_UNDEF_ORDER_DIR_ERR, "Wrong direction of the token was "
                                                                           "specified, possible directions: buy, sell.");
                            return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_UNDEF_ORDER_DIR_ERR;
                        }
                    }

                    if (l_expires_str)
                        l_expires = (dap_time_t ) atoll( l_expires_str);
                    if (l_srv_uid_str && dap_id_uint64_parse(l_srv_uid_str ,&l_srv_uid.uint64)) {
                        dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CANT_RECOGNIZE_ERR,
                                                    "Can't recognize '%s' string as 64-bit id, hex or dec.", l_srv_uid_str);
                        return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CANT_RECOGNIZE_ERR;
                    }else if (!l_srv_uid_str){
                        dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_REQUIRED_PARAM_UID_ERR, "Parameter -srv_uid is required.");
                        return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_REQUIRED_PARAM_UID_ERR;
                    }
                    if (l_node_addr_str){
                        if (dap_chain_node_addr_str_check(l_node_addr_str)) {
                            dap_chain_node_addr_from_str( &l_node_addr, l_node_addr_str );
                        } else {
                            log_it(L_ERROR, "Can't parse \"%s\" as node addr", l_node_addr_str);
                            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CANT_PARSE_NODE_ADDR_ERR, "The order has not been created. "
                                                                           "Failed to convert string representation of '%s' "
                                                                           "to node address.", l_node_addr_str);
                            return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CANT_PARSE_NODE_ADDR_ERR;
                        }
                    } else {
                        l_node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
                    }
                    if (l_tx_cond_hash_str)
                        dap_chain_hash_fast_from_str (l_tx_cond_hash_str, &l_tx_cond_hash);
                    l_price = dap_chain_balance_scan(l_price_str);

                    uint64_t l_units = strtoull(l_units_str, NULL, 10);
                    
                    if (!dap_strcmp(l_price_unit_str, "B")){
                        l_price_unit.enm = SERV_UNIT_B;
                    } else if (!dap_strcmp(l_price_unit_str, "KB")){
                        l_price_unit.enm = SERV_UNIT_B;
                        l_units *= 1024;
                    } else if (!dap_strcmp(l_price_unit_str, "MB")){
                        l_price_unit.enm = SERV_UNIT_B;
                        l_units *= 1024*1024;
                    } else if (!dap_strcmp(l_price_unit_str, "DAY")){
                        l_price_unit.enm = SERV_UNIT_SEC;
                        l_units *= 3600*24;
                    } else if (!dap_strcmp(l_price_unit_str, "SEC")){
                        l_price_unit.enm = SERV_UNIT_SEC;
                    } else if (!dap_strcmp(l_price_unit_str, "PCS")){
                        l_price_unit.enm = SERV_UNIT_PCS;
                    } else {
                        log_it(L_ERROR, "Undefined price unit");
                        dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_UNDEF_PRICE_UNIT_ERR,
                                                    "Wrong unit type sepcified, possible values: B, KB, MB, SEC, DAY, PCS");
                        return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_UNDEF_PRICE_UNIT_ERR;
                    }                     
                    strncpy(l_price_token, l_price_token_str, DAP_CHAIN_TICKER_SIZE_MAX - 1);
                    size_t l_ext_len = l_ext? strlen(l_ext) + 1 : 0;
                    // get cert to order sign
                    dap_cert_t *l_cert = NULL;
                    dap_enc_key_t *l_key = NULL;
                    if (l_order_cert_name) {
                        l_cert = dap_cert_find_by_name(l_order_cert_name);
                        if (l_cert) {
                            l_key = l_cert->enc_key;
                            if (!l_key->priv_key_data || !l_key->priv_key_data_size) {
                                log_it(L_ERROR, "Certificate '%s' doesn't contain a private key", l_order_cert_name);
                                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CERT_WITHOUT_KEY_ERR,
                                                    "Certificate '%s' doesn't contain a private key", l_order_cert_name);
                                return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CERT_WITHOUT_KEY_ERR;
                            }
                        } else {
                            log_it(L_ERROR, "Can't load cert '%s' for sign order", l_order_cert_name);
                            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CANT_LOAD_CERT_ERR, "Can't load cert '%s' for sign "
                                                                           "order", l_order_cert_name);
                            return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CANT_LOAD_CERT_ERR;
                        }
                    } else {
                        dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CERT_NAME_NOT_WALID_ERR,
                                                                        "The certificate name was not "
                                                                        "specified. Since version 5.2 it is not possible to "
                                                                        "create unsigned orders.");
                        return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CERT_NAME_NOT_WALID_ERR;
                    }
                // create order
                    char * l_order_new_hash_str = dap_chain_net_srv_order_create(
                        l_net,l_direction, l_srv_uid, l_node_addr,l_tx_cond_hash, &l_price, l_price_unit,
                        l_price_token, l_expires, (uint8_t*)l_ext, l_ext_len, l_units, l_region_str, l_continent_num, l_key);
                    if (l_order_new_hash_str) {
                        json_obj_net_srv = json_object_new_object();
                        json_object_object_add(json_obj_net_srv, "order_hash", json_object_new_string(l_order_new_hash_str));
                        DAP_DELETE(l_order_new_hash_str);
                    }
                    else {
                        dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_ORDER_ERR,
                                                                        "Error! Can't created order\n");
                        l_ret = -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_ORDER_ERR;
                    }
                } else {
                    dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_MISSED_PARAM_ERR,
                                                                        "Missed some required params\n");
                    return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_MISSED_PARAM_ERR;
                }
            } else if (l_order_str) {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UNKNOWN_SUB_COM_ERR,
                                                                        "Unrecognized subcommand '%s'", l_order_str);
                return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UNKNOWN_SUB_COM_ERR;
            }            
        } else if (l_get_limits_str){
            const char *l_provider_pkey_hash_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-provider_pkey_hash", &l_provider_pkey_hash_str);

            const char *l_client_pkey_hash_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-client_pkey_hash", &l_client_pkey_hash_str);

            if (!l_provider_pkey_hash_str){
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_REQUIRED_PARAM_PPKHASH_ERR,
                                            "Command 'get_limits' require the parameter provider_pkey_hash");
                 return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_REQUIRED_PARAM_PPKHASH_ERR;
            }

            if (!l_client_pkey_hash_str){
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_REQUIRED_PARAM_CPKHASH_ERR,
                                            "Command 'get_limits' require the parameter client_pkey_hash");
                return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_REQUIRED_PARAM_CPKHASH_ERR;
            }

            dap_chain_net_srv_uid_t l_srv_uid={{0}};
            if (l_srv_uid_str && dap_id_uint64_parse(l_srv_uid_str ,&l_srv_uid.uint64)) {
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_CANT_REC_UID_STR_ERR,
                                            "Can't recognize '%s' string as 64-bit id, hex or dec.", l_srv_uid_str);
                return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_CANT_REC_UID_STR_ERR;
            } else if (!l_srv_uid_str){
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_REQUIRED_PARAM_UID_ERR,
                                            "Parameter -srv_uid is required.");
                return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_REQUIRED_PARAM_UID_ERR;
            }

            dap_stream_ch_chain_net_srv_remain_service_store_t *l_remain_service = NULL;
            size_t l_remain_service_size = 0;
            char *l_remain_limits_gdb_group =  dap_strdup_printf( "local.%s.0x%016"DAP_UINT64_FORMAT_x".remain_limits.%s",
                                                                l_net->pub.gdb_groups_prefix, l_srv_uid.uint64,
                                                                l_provider_pkey_hash_str);

            l_remain_service = (dap_stream_ch_chain_net_srv_remain_service_store_t*) dap_global_db_get_sync(l_remain_limits_gdb_group, l_client_pkey_hash_str, &l_remain_service_size, NULL, NULL);
            DAP_DELETE(l_remain_limits_gdb_group);

            if(!l_remain_service || !l_remain_service_size){
                dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_CANT_GET_REM_SERV_DATA_ERR,
                                            "Can't get remain service data");
                return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_CANT_GET_REM_SERV_DATA_ERR;
            }
            json_obj_net_srv = json_object_new_object();

            json_object_object_add(json_obj_net_srv, a_version == 1 ? "provider" : "sig_inf_provider", json_object_new_string(l_provider_pkey_hash_str));
            json_object_object_add(json_obj_net_srv, a_version == 1 ? "client" : "sig_inf_client", json_object_new_string(l_client_pkey_hash_str));
            json_object_object_add(json_obj_net_srv, "sec", json_object_new_uint64((uint64_t)l_remain_service->limits_ts));
            json_object_object_add(json_obj_net_srv, "bytes", json_object_new_uint64((uint64_t)l_remain_service->limits_bytes));
            DAP_DELETE(l_remain_service);
        } else {
            dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UNKNOWN,
                                            "Unrecognized command.");
            return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UNKNOWN;
        }
    }
    if (json_obj_net_srv != NULL)
                json_object_array_add(*json_arr_reply, json_obj_net_srv);
    return l_ret;
}

/**
 * @brief s_fee_verificator_callback
 * @param a_ledger
 * @param a_tx_out_hash
 * @param a_cond
 * @param a_tx_in
 * @param a_owner
 * @return
 */
static int s_fee_verificator_callback(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t UNUSED_ARG *a_cond,
                                       dap_chain_datum_tx_t *a_tx_in, bool UNUSED_ARG a_owner)
{
    dap_chain_net_t *l_net = a_ledger->net;
    assert(l_net);
    dap_chain_t *l_chain;
    DL_FOREACH(l_net->pub.chains, l_chain) {
        if (!l_chain->callback_block_find_by_tx_hash)
            continue;
        dap_chain_tx_in_cond_t *l_tx_in_cond = (dap_chain_tx_in_cond_t*)dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_IN_COND, NULL);
        if (!l_tx_in_cond)
            return -1;
        if (dap_hash_fast_is_blank(&l_tx_in_cond->header.tx_prev_hash))
            return -2;
        size_t l_block_size = 0;
        dap_chain_block_t *l_block = (dap_chain_block_t *)l_chain->callback_block_find_by_tx_hash(
                                                    l_chain, &l_tx_in_cond->header.tx_prev_hash, &l_block_size);
        if (!l_block)
            continue;
        dap_sign_t *l_sign_block = dap_chain_block_sign_get(l_block, l_block_size, 0);
        if (!l_sign_block)
            return -3;

        // TX sign is already verified, just compare pkeys
        dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
        dap_sign_t *l_sign_tx = dap_chain_datum_tx_item_sign_get_sig(l_tx_sig);
        return dap_sign_compare_pkeys(l_sign_block, l_sign_tx) ? 0 : -5;
    }
    return -4;
}

/**
 * @brief s_pay_verificator_callback
 * @param a_ledger
 * @param a_tx_out
 * @param a_cond
 * @param a_tx_in
 * @param a_owner
 * @return
 */
static int s_pay_verificator_callback(dap_ledger_t * a_ledger, dap_chain_tx_out_cond_t *a_cond,
                                       dap_chain_datum_tx_t *a_tx_in, bool a_owner)
{
    if (a_owner)
        return 0;
    size_t l_receipt_size = 0;
    dap_chain_datum_tx_receipt_old_t *l_receipt_old = (dap_chain_datum_tx_receipt_old_t *)
                                               dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_RECEIPT_OLD, &l_receipt_size);
    dap_chain_datum_tx_receipt_t *l_receipt = NULL;

    if (!l_receipt_old){
        if ((l_receipt = (dap_chain_datum_tx_receipt_t *)dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_RECEIPT, &l_receipt_size))==NULL){
            log_it(L_ERROR, "Can't find receipt.");
            return -1;
        }
    } else if (l_receipt_old->receipt_info.version > 1) {
        log_it(L_ERROR, "Old receipt version is wrong.");
        return -17;
    }

    // Checking politics
    if (dap_chain_policy_is_activated(a_ledger->net->pub.id, DAP_CHAIN_POLICY_ACCEPT_RECEIPT_VERSION_2) &&
        (!l_receipt || l_receipt->receipt_info.version < 2)){
        log_it(L_ERROR, "Receipt version must be >= 2.");
        return -17;
    }

    // Checking provider sign
    dap_sign_t *l_sign = dap_chain_datum_tx_receipt_sign_get(l_receipt ? l_receipt : (dap_chain_datum_tx_receipt_t *)l_receipt_old, l_receipt_size, 0);

    if (!l_sign){
        log_it(L_ERROR, "Can't get provider sign from receipt.");
        return -2;
    }

    if (l_receipt){
        if (dap_sign_verify_all(l_sign, dap_sign_get_size(l_sign), &l_receipt->receipt_info, sizeof(dap_chain_receipt_info_t))){
            log_it(L_ERROR, "Provider sign in receipt not passed verification.");
            return -3;
        }
    } else {
        if (dap_sign_verify_all(l_sign, dap_sign_get_size(l_sign), &l_receipt_old->receipt_info, sizeof(dap_chain_receipt_info_old_t))){
            log_it(L_ERROR, "Provider sign in receipt not passed verification.");
            return -3;
        }
    }

    // Checking the signature matches the provider's signature
    dap_hash_fast_t l_tx_sign_pkey_hash = {};
    dap_hash_fast_t l_provider_pkey_hash = {};
    if (!dap_sign_get_pkey_hash(l_sign, &l_provider_pkey_hash)){
        log_it(L_ERROR, "Can't get pkey hash from provider sign.");
        return -4;
    }

    size_t l_item_size = 0;
    uint8_t* l_sig = dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_SIG, &l_item_size);
    if(!l_sig){
        log_it(L_ERROR, "Can't get item with provider signature from tx");
        return false;
    }

    l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_sig);
    if (!l_sign){
        log_it(L_ERROR, "Provider sign from tx sig_item");
        return -5;
    }

    if(!dap_sign_get_pkey_hash(l_sign, &l_tx_sign_pkey_hash)){
        log_it(L_ERROR, "Can't get pkey hash from tx provider signature");
        return -6;
    }

    if(!dap_hash_fast_compare(&l_tx_sign_pkey_hash, &l_provider_pkey_hash)){
        log_it(L_ERROR, "Provider signature in receipt and tx is different.");
        return -7;
    }

    // Checking client sign
    l_sign = dap_chain_datum_tx_receipt_sign_get(l_receipt ? l_receipt : (dap_chain_datum_tx_receipt_t *)l_receipt_old, l_receipt_size, 1);
    if (!l_sign){
        log_it(L_ERROR, "Can't get client signature from receipt.");
        return -8;
    }
    dap_hash_fast_t l_pkey_hash = {};
    if (!dap_sign_get_pkey_hash(l_sign, &l_pkey_hash)){
        log_it(L_ERROR, "Can't get pkey hash from receipt client signature");
        return -9;
    }

    if(!dap_hash_fast_compare(&l_pkey_hash, &a_cond->subtype.srv_pay.pkey_hash)){
        log_it(L_ERROR, "Client signature in receipt is invalid!");
        return -10;
    }

    // Verifyig of client sign
    if (l_receipt){
        if (dap_sign_verify_all(l_sign, dap_sign_get_size(l_sign), &l_receipt->receipt_info, sizeof(dap_chain_receipt_info_t))){
            log_it(L_ERROR, "Client sign in receipt not passed verification.");
            return -3;
        }
    } else {
        if (dap_sign_verify_all(l_sign, dap_sign_get_size(l_sign), &l_receipt_old->receipt_info, sizeof(dap_chain_receipt_info_old_t))){
            log_it(L_ERROR, "CLient sign in receipt not passed verification.");
            return -3;
        }
    }

    // Checking price is less than maximum
    dap_chain_tx_in_cond_t *l_tx_in_cond = (dap_chain_tx_in_cond_t*)dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_IN_COND, NULL);
    dap_chain_datum_tx_t *l_tx_prev = dap_ledger_tx_find_by_hash(a_ledger , &l_tx_in_cond->header.tx_prev_hash);
    dap_chain_tx_out_cond_t *l_prev_out_cond = dap_chain_datum_tx_out_cond_get(l_tx_prev, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, NULL);
    if (!l_prev_out_cond) {
        log_it(L_ERROR, "Can't find datum tx");
        return -15;
    }

    // Checking the tx hash in receipt matched tx hash in in cond
    if (l_receipt && l_receipt->receipt_info.version > 1 && !dap_hash_fast_compare(&l_receipt->receipt_info.prev_tx_cond_hash, &l_tx_in_cond->header.tx_prev_hash)){
        log_it(L_ERROR, "The hashes of previous transactions in receipt and conditional input doesn't match.");
        return -16;
    }

    uint256_t l_unit_price = {};
    uint256_t l_receipt_value_datoshi = dap_chain_datum_tx_receipt_value_get(l_receipt ? l_receipt : (dap_chain_datum_tx_receipt_t *)l_receipt_old);
    uint64_t l_receipt_units = dap_chain_datum_tx_receipt_units_get(l_receipt ? l_receipt : (dap_chain_datum_tx_receipt_t *)l_receipt_old);
    if (!l_receipt_units) {
        log_it(L_ERROR, "Receipt units can't be a zero");
        return -11;
    }
    DIV_256(l_receipt_value_datoshi, GET_256_FROM_64(l_receipt_units), &l_unit_price);

    if( !IS_ZERO_256(l_prev_out_cond->subtype.srv_pay.unit_price_max_datoshi) &&
        compare256(l_unit_price, l_prev_out_cond->subtype.srv_pay.unit_price_max_datoshi) > 0){
        log_it(L_ERROR, "Value in receipt is exceed max allowable price.");
        return -12;
    }

    // checking remainder on srv pay cond out is valid
    // find 'out' items
    uint256_t l_cond_out_value = {};
    dap_chain_addr_t l_network_fee_addr = {}, l_out_addr = {};
    dap_chain_net_tx_get_fee(a_ledger->net->pub.id, NULL, &l_network_fee_addr);
    byte_t *l_item; size_t l_size; int i, l_item_idx = -1;
    TX_ITEM_ITER_TX_TYPE(l_item, TX_ITEM_TYPE_OUT_ALL, l_size, i, a_tx_in) {
        ++l_item_idx;
        switch (*l_item) {
        case TX_ITEM_TYPE_OUT: { // 256
            dap_chain_tx_out_t *l_tx_out = (dap_chain_tx_out_t*)l_item;
            l_out_addr = l_tx_out->addr;
            if (dap_chain_addr_compare(&l_out_addr, &l_network_fee_addr) &&
                    SUM_256_256(l_receipt_value_datoshi, l_tx_out->header.value, &l_receipt_value_datoshi)) {
                log_it(L_WARNING, "Integer overflow while sum of outs calculation");
                return -14;
            }
        } break;
        case TX_ITEM_TYPE_OUT_EXT: { // 256
            dap_chain_tx_out_ext_t *l_tx_out = (dap_chain_tx_out_ext_t*)l_item;
            l_out_addr = l_tx_out->addr;
            if (dap_chain_addr_compare(&l_out_addr, &l_network_fee_addr) &&
                    SUM_256_256(l_receipt_value_datoshi, l_tx_out->header.value, &l_receipt_value_datoshi)) {
                log_it(L_WARNING, "Integer overflow while sum of outs calculation");
                return -14;
            }
        } break;
        case TX_ITEM_TYPE_OUT_COND: {
            dap_chain_tx_out_cond_t *l_tx_out = (dap_chain_tx_out_cond_t*)l_item;
            if (l_tx_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE) {
                if (SUM_256_256(l_receipt_value_datoshi, l_tx_out->header.value, &l_receipt_value_datoshi)) {
                    log_it(L_WARNING, "Integer overflow while sum of outs calculation");
                    return -14;
                }
            } else if (l_tx_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY){
                l_cond_out_value = l_tx_out->header.value;
            }
        } break;
        default:
            break;
        }
    }

    if (SUBTRACT_256_256(l_prev_out_cond->header.value, l_receipt_value_datoshi, &l_receipt_value_datoshi)) {
        log_it(L_WARNING, "Integer overflow while payback calculation");
        return -14;
    }

    return compare256(l_receipt_value_datoshi, l_cond_out_value) ? log_it(L_ERROR, "Value in tx out is invalid!"), -13 : 0;
}

dap_chain_net_srv_price_t * dap_chain_net_srv_get_price_from_order(dap_chain_net_srv_t *a_srv, const char *a_config_section, dap_chain_hash_fast_t* a_order_hash){

    const char *l_wallet_addr = dap_config_get_item_str_default(g_config, a_config_section, "wallet_addr", NULL);
    const char *l_cert_name = dap_config_get_item_str_default(g_config, a_config_section, "receipt_sign_cert", NULL);
    const char *l_net_name = dap_config_get_item_str_default(g_config, a_config_section, "net", NULL);
    if (!l_wallet_addr){
        log_it(L_CRITICAL, "Wallet addr is not defined. Check node configuration file.");
        return NULL;
    }
    if (!l_cert_name){
        log_it(L_CRITICAL, "Receipt sign certificate is not defined. Check node configuration file.");
        return NULL;
    }
    if (!l_net_name){
        log_it(L_CRITICAL, "Net for is not defined. Check node configuration file.");
        return NULL;
    }
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name);
    if (!l_net) {
        log_it(L_CRITICAL, "Can't find net %s. Check node configuration file.", l_net_name);
        return NULL;
    }

    dap_chain_node_addr_t *l_node_addr = NULL;
    l_node_addr = &g_node_addr;//dap_chain_net_get_cur_addr(l_net);
    if (!l_node_addr){
        return NULL;
    }

    dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_find_by_hash(l_net, a_order_hash);
    if (!l_order){
        log_it(L_ERROR, "Can't find order!");
        return NULL;
    }

    dap_chain_net_srv_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_price_t);
    if (!l_price) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DEL_Z(l_order);
        return NULL;
    }
    if (l_order->node_addr.uint64 != g_node_addr.uint64 &&
        l_order->srv_uid.uint64 != a_srv->uid.uint64) {
        DAP_DELETE(l_price);
        DAP_DEL_Z(l_order);
        return NULL;
    }

    l_price->net = l_net;
    l_price->net_name = dap_strdup(l_net->pub.name);
    if ((IS_ZERO_256(l_order->price) || l_order->units == 0 ) && !a_srv->allow_free_srv){
        log_it(L_ERROR, "Invalid order: units count or price unspecified");
        DAP_DELETE(l_price);
        DAP_DEL_Z(l_order);
        return NULL;
    }
    l_price->value_datoshi = l_order->price;
    dap_stpcpy(l_price->token, l_order->price_ticker);
    l_price->units = l_order->units;
    l_price->units_uid = l_order->price_unit;

    l_price->wallet_addr = dap_chain_addr_from_str(l_wallet_addr);
    if(!l_price->wallet_addr){
        log_it(L_ERROR, "Can't get wallet addr from wallet_addr in config file.");
        DAP_DELETE(l_price);
        DAP_DEL_Z(l_order);
        return NULL;
    }

    l_price->receipt_sign_cert = dap_cert_find_by_name(l_cert_name);
    if(!l_price->receipt_sign_cert){
        log_it(L_ERROR, "Can't find cert %s.", l_cert_name);
        DAP_DEL_Z(l_order);
        DAP_DELETE(l_price);
        return NULL;
    }

    dap_hash_fast_t order_pkey_hash = {};
    dap_hash_fast_t price_pkey_hash = {};
    dap_sign_get_pkey_hash((dap_sign_t*)(l_order->ext_n_sign + l_order->ext_size), &order_pkey_hash);
    size_t l_key_size = 0;
    uint8_t *l_pub_key = dap_enc_key_serialize_pub_key(l_price->receipt_sign_cert->enc_key, &l_key_size);
    if (!l_pub_key || !l_key_size)
    {
        log_it(L_ERROR, "Can't get pkey from cert %s.", l_cert_name);
        DAP_DEL_Z(l_order);
        DAP_DELETE(l_price);
        return NULL;
    }

    dap_hash_fast(l_pub_key, l_key_size, &price_pkey_hash);
    DAP_DELETE(l_pub_key);

    if (!dap_hash_fast_compare(&order_pkey_hash, &price_pkey_hash))
    {
        log_it(L_ERROR, "pkey in order not equal to pkey in config.");
        DAP_DEL_Z(l_order);
        DAP_DELETE(l_price);
        return NULL;
    }

    DAP_DELETE(l_order);
    return l_price;
}

int dap_chain_net_srv_price_apply_from_my_order(dap_chain_net_srv_t *a_srv, const char *a_config_section)
{



    return 0;
}

/**
 * @brief dap_chain_net_srv_add
 * @param a_uid
 * @param a_callback_request
 * @param a_callback_response_success
 * @param a_callback_response_error
 * @return
 */
dap_chain_net_srv_t* dap_chain_net_srv_add(dap_chain_net_srv_uid_t a_uid,
                                           const char *a_config_section,
                                           dap_chain_net_srv_callbacks_t* a_callbacks)

{
    service_list_t *l_sdata = NULL;
    dap_chain_net_srv_t * l_srv = NULL;
    dap_chain_net_srv_uid_t l_uid = {.uint64 = a_uid.uint64 }; // Copy to let then compiler to pass args via registers not stack
    const char* l_net_name_str = dap_config_get_item_str_default(g_config, a_config_section, "net", "");
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name_str);
    if(!l_net && a_uid.uint64 == 1){
        log_it(L_ERROR, "Can't find net [%s]. Check configuration file.", l_net_name_str);
        return NULL;
    }

    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_FIND(hh, s_srv_list, &l_uid, sizeof(l_uid), l_sdata);
    if(!l_sdata) {
        l_srv = DAP_NEW_Z(dap_chain_net_srv_t);
        if (!l_srv) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            pthread_mutex_unlock(&s_srv_list_mutex);
            return NULL;
        }
        l_srv->uid.uint64 = a_uid.uint64;
        if (a_callbacks)
            l_srv->callbacks = *a_callbacks;
        l_sdata = DAP_NEW_Z(service_list_t);
        if (!l_sdata) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            DAP_DEL_Z(l_srv);
            pthread_mutex_unlock(&s_srv_list_mutex);
            return NULL;
        }
        l_sdata->uid = l_uid;
        strncpy(l_sdata->name, a_config_section, sizeof(l_sdata->name) - 1);
        l_sdata->srv = l_srv;
        if (a_uid.uint64 == 1){
            l_srv->grace_period = dap_config_get_item_uint32_default(g_config, a_config_section, "grace_period", DAP_CHAIN_NET_SRV_GRACE_PERIOD_DEFAULT);
            l_srv->allow_free_srv = dap_config_get_item_bool_default(g_config, a_config_section, "allow_free_srv", false);
        }
        HASH_ADD(hh, s_srv_list, uid, sizeof(l_srv->uid), l_sdata);
        dap_stream_ch_chain_net_srv_init(l_srv);
        if (l_net)
            dap_ledger_tx_add_notify(l_net->pub.ledger, dap_stream_ch_chain_net_srv_tx_cond_added_cb, NULL);
    }else{
        log_it(L_ERROR, "Already present service with 0x%016"DAP_UINT64_FORMAT_X, a_uid.uint64);
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
    return l_srv;
}

/**
 * @brief dap_chain_net_srv_del
 * @param a_srv
 */
void dap_chain_net_srv_del(dap_chain_net_srv_t *a_srv)
{
// sanity check
    dap_return_if_pass(!a_srv);
// func work
    service_list_t *l_sdata = NULL;
    // delete srv from hash table
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_FIND(hh, s_srv_list, a_srv, sizeof(dap_chain_net_srv_uid_t), l_sdata);
    if(l_sdata) {
        // grace table clean
        dap_chain_net_srv_grace_usage_t *l_gdata, *l_gdata_tmp;
        pthread_mutex_lock(&a_srv->grace_mutex);
        HASH_ITER(hh, a_srv->grace_hash_tab, l_gdata, l_gdata_tmp)
        {
            HASH_DEL(a_srv->grace_hash_tab, l_gdata);
            DAP_DELETE(l_gdata);
        } 
        pthread_mutex_unlock(&a_srv->grace_mutex);

        HASH_DEL(s_srv_list, l_sdata);
        DAP_DELETE(a_srv);
        DAP_DELETE(l_sdata);
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
}

/**
 * @brief dap_chain_net_srv_call_write_all
 * @param a_client
 */
void dap_chain_net_srv_call_write_all(dap_stream_ch_t * a_client)
{
    service_list_t *l_sdata, *l_sdata_tmp;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_ITER(hh, s_srv_list , l_sdata, l_sdata_tmp)
    {
        if (l_sdata->srv->callbacks.stream_ch_write)
            l_sdata->srv->callbacks.stream_ch_write(l_sdata->srv, a_client);
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
}

/**
 * @brief dap_chain_net_srv_call_opened_all
 * @param a_client
 */
void dap_chain_net_srv_call_opened_all(dap_stream_ch_t * a_client)
{
    service_list_t *l_sdata, *l_sdata_tmp;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_ITER(hh, s_srv_list , l_sdata, l_sdata_tmp)
    {
        if (l_sdata->srv->callbacks.stream_ch_opened)
            l_sdata->srv->callbacks.stream_ch_opened(l_sdata->srv, a_client);
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
}

void dap_chain_net_srv_call_closed_all(dap_stream_ch_t * a_client)
{
    service_list_t *l_sdata, *l_sdata_tmp;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_ITER(hh, s_srv_list , l_sdata, l_sdata_tmp)
    {
        if (l_sdata->srv->callbacks.stream_ch_closed)
            l_sdata->srv->callbacks.stream_ch_closed(l_sdata->srv, a_client);
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
}



/**
 * @brief dap_chain_net_srv_del_all
 * @param a_srv
 */
void dap_chain_net_srv_del_all(void)
{
    service_list_t *l_sdata, *l_sdata_tmp;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_ITER(hh, s_srv_list , l_sdata, l_sdata_tmp)
    {
        // Clang bug at this, l_sdata should change at every loop cycle
        HASH_DEL(s_srv_list, l_sdata);
        DAP_DELETE(l_sdata->srv);
        DAP_DELETE(l_sdata);
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
}

/**
 * @brief dap_chain_net_srv_get
 * @param a_uid
 * @return
 */
dap_chain_net_srv_t *dap_chain_net_srv_get(dap_chain_net_srv_uid_t a_uid)
{
    service_list_t *l_sdata = NULL;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_FIND(hh, s_srv_list, &a_uid, sizeof(dap_chain_net_srv_uid_t), l_sdata);
    pthread_mutex_unlock(&s_srv_list_mutex);
    return (l_sdata) ? l_sdata->srv : NULL;
}

/**
 * @brief dap_chain_net_srv_get_by_name
 * @param a_client
 */
dap_chain_net_srv_t* dap_chain_net_srv_get_by_name(const char *a_name)
{
    if(!a_name)
        return NULL;
    dap_chain_net_srv_t *l_srv = NULL;
    service_list_t *l_sdata, *l_sdata_tmp;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_ITER(hh, s_srv_list , l_sdata, l_sdata_tmp)
    {
        if(!dap_strcmp(l_sdata->name, a_name))
            l_srv = l_sdata->srv;
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
    return l_srv;
}

/**
 * @brief dap_chain_net_srv_count
 * @return
 */
 size_t dap_chain_net_srv_count(void)
{
    size_t l_count = 0;
    service_list_t *l_sdata, *l_sdata_tmp;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_ITER(hh, s_srv_list , l_sdata, l_sdata_tmp)
    {
        l_count++;
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
    return l_count;
}

/**
 * @brief dap_chain_net_srv_list
 * @return
 */
const dap_chain_net_srv_uid_t * dap_chain_net_srv_list(void)
{
    static dap_chain_net_srv_uid_t *l_srv_uids = NULL;
    static size_t l_count_last = 0;
    size_t l_count_cur = 0;
    dap_list_t *l_list = NULL;
    service_list_t *l_sdata, *l_sdata_tmp;
    pthread_mutex_lock(&s_srv_list_mutex);
    // count the number of services and save them in list
    HASH_ITER(hh, s_srv_list , l_sdata, l_sdata_tmp)
    {
        l_list = dap_list_append(l_list, l_sdata);
        l_count_cur++;
    }
    // fill the output array
    if(l_count_cur > 0) {
        if(l_count_cur != l_count_last) {
            DAP_DELETE(l_srv_uids);
            l_srv_uids = DAP_NEW_Z_COUNT(dap_chain_net_srv_uid_t, l_count_cur);
        }
        for(size_t i = 0; i < l_count_cur; i++) {
            *(l_srv_uids + i) = ((service_list_t*)(l_list->data))->uid;
        }
    }
    // save new number of services
    l_count_last = l_count_cur;
    pthread_mutex_unlock(&s_srv_list_mutex);
    dap_list_free(l_list);
    return l_srv_uids;
}

/**
 * @brief dap_chain_net_srv_issue_receipt
 * @param a_srv
 * @param a_usage
 * @param a_price
 * @return
 */
dap_chain_datum_tx_receipt_t * dap_chain_net_srv_issue_receipt(dap_chain_net_srv_t *a_srv,
                                                               dap_chain_net_srv_price_t * a_price,
                                                               const void * a_ext, size_t a_ext_size, dap_hash_fast_t *a_prev_tx_hash)
{
    dap_chain_datum_tx_receipt_t * l_receipt = dap_chain_datum_tx_receipt_create(
                    a_srv->uid, a_price->units_uid, a_price->units, a_price->value_datoshi, a_ext, a_ext_size, a_prev_tx_hash);
    // Sign with our wallet
    return dap_chain_datum_tx_receipt_sign_add(l_receipt, a_price->receipt_sign_cert->enc_key);
}

/**
 * @brief s_str_to_price_unit
 * @param a_str_price_unit
 * @param a_price_unit
 * @return 0 if OK, other if error
 */
int s_str_to_price_unit(const char* a_price_unit_str, dap_chain_net_srv_price_unit_uid_t* a_price_unit)
{
    if (!a_price_unit_str || !a_price_unit)
        return -1;
    a_price_unit->enm = dap_chain_srv_str_to_unit_enum((char *)a_price_unit_str);
    return a_price_unit->enm != SERV_UNIT_UNDEFINED ? 0 : -1;
}
