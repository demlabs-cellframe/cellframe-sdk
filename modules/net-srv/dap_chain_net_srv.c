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
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#ifdef DAP_OS_LINUX
#include <dlfcn.h>
#endif
#include <pthread.h>
#include <dirent.h>
#include "uthash.h"

#include "dap_chain_net.h"
#include "dap_chain_ledger.h"
#include "dap_hash.h"
#include "dap_common.h"
#include "dap_enc_base58.h"
#include "dap_list.h"
#include "dap_string.h"
#include "dap_file_utils.h"
#include "dap_chain.h"
#include "dap_chain_common.h"
#include "dap_chain_srv.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_policy.h"  // For policy functions from common module
#include "dap_chain_net_tx.h"
#include "dap_chain_net_srv_order.h"
#include "dap_chain_net_srv_stream_session.h"
#include "dap_chain_net_srv_ch.h"

#ifdef DAP_MODULES_DYNAMIC
#include "dap_modules_dynamic_cdb.h"
#endif

#include "dap_chain_node_cli_cmd.h"

#define LOG_TAG "chain_net_srv"

static int s_cli_net_srv(int argc, char **argv, dap_json_t *a_json_arr_reply, int a_version);

static int s_pay_verificator_callback(dap_ledger_t * a_ledger, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_in_hash, dap_chain_tx_out_cond_t *a_cond, bool a_owner, bool a_from_mempool);
static void s_pay_updater_callback(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_out, dap_hash_fast_t *a_tx_out_hash, dap_chain_tx_out_cond_t *a_cond);
static int s_str_to_price_unit(const char *a_price_unit_str, dap_chain_net_srv_price_unit_uid_t *a_price_unit);

/**
 * @brief dap_chain_net_srv_init
 * @return
 */
int dap_chain_net_srv_init()
{
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, s_pay_verificator_callback, NULL, NULL, s_pay_updater_callback, NULL, NULL);
    dap_cli_server_cmd_add ("net_srv", s_cli_net_srv, "Network services managment",  dap_chain_node_cli_cmd_id_from_str("net_srv"),
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
            "\tCreate general service order (VPN as usually)"
        "net_srv get_limits -net <net_name> -srv_uid <service_UID> -provider_pkey_hash <service_provider_public_key_hash> -client_pkey_hash <client_public_key_hash>\n"
            "\tShow service billing info"
        "net_srv report\n"
            "\tGet report about srv usage\n\n"

        "Hint:\n"
            "\texample coins amount syntax (only natural) 1.0 123.4567\n"
            "\texample datoshi amount syntax (only integer) 1 20 0.4321e+4\n\n"
        );
    dap_chain_net_srv_ch_init();
    return 0;
}
/**
 * @brief dap_chain_net_srv_deinit
 */
void dap_chain_net_srv_deinit(void)
{

}

/**
 * @brief s_cli_net_srv
 * @param argc
 * @param argv
 * @param a_str_reply
 * @return
 */
static int s_cli_net_srv( int argc, char **argv, dap_json_t *a_json_arr_reply, int a_version)
{
    int arg_index = 1;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type, "hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_HASH_ERR, "invalid parameter -H, valid values: -H <hex | base58>");
        return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_HASH_ERR;
    }


    int l_report = dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "report", NULL);
    if (l_report) {
        dap_json_t *json_obj_net_srv = dap_json_object_new();
        char *l_report_str = dap_chain_net_srv_ch_create_statistic_report();
        dap_json_object_add_string(json_obj_net_srv, "report", l_report_str);
        DAP_DELETE(l_report_str);

        dap_json_array_add(a_json_arr_reply, json_obj_net_srv);
        return DAP_CHAIN_NET_SRV_CLI_COM_ORDER_OK;
    }

    int l_ret = dap_chain_node_cli_cmd_values_parse_net_chain_for_json(a_json_arr_reply, &arg_index, argc, argv, NULL, &l_net, CHAIN_TYPE_INVALID);
    dap_json_t* json_obj_net_srv = NULL;
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

                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CONT_ERR, "%s\n", l_string_err->str);
                dap_string_free(l_string_err, true);
                l_ret = -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CONT_ERR;
            } else if (!dap_strcmp(l_order_str, "update")) {
                if (!l_order_hash_str) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_ERR, "Can't find option '-hash'\n");
                    l_ret = -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_ERR;                    
                } else {
                    dap_chain_net_srv_order_t * l_order = dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_hex_str);
                    if(!l_order) {
                        l_ret = -2;
                        if(!dap_strcmp(l_hash_out_type,"hex"))
                            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_HASH_ERR, "Can't find order with hash %s\n", l_order_hash_hex_str);
                        else
                            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_HASH_ERR, "Can't find order with hash %s\n", l_order_hash_base58_str);
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
                            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_PARAM_CERT_ERR, "Fee order creation requires parameter -cert");
                                return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_PARAM_CERT_ERR;
                            }
                            dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
                            if (!l_cert) {
                                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_LOAD_CERT_ERR, "Can't load cert %s", l_cert_str);
                                DAP_DEL_MULTY(l_new_order_hash_str, l_order_hash_hex_str, l_order_hash_base58_str, l_order);
                                return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UPDATE_LOAD_CERT_ERR;
                            }
                            */ // WTF is this? ^^^
                            // delete prev order
                            if(dap_strcmp(l_new_order_hash_str, l_order_hash_hex_str))
                                dap_chain_net_srv_order_delete_by_hash_str_sync(l_net, l_order_hash_hex_str);
                            DAP_DELETE(l_new_order_hash_str);
                            json_obj_net_srv = dap_json_object_new();
                            dap_json_object_add_string(json_obj_net_srv, "status", "updated");

                        } else {
                            json_obj_net_srv = dap_json_object_new();
                            dap_json_object_add_string(json_obj_net_srv, "status", "not updated");
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
                dap_chain_srv_uid_t l_srv_uid={{0}};
                uint256_t l_price_min = {};
                uint256_t l_price_max = {};
                dap_chain_net_srv_price_unit_uid_t l_price_unit={{0}};

                if ( l_direction_str ) {
                    if (!strcmp(l_direction_str, "sell"))
                        l_direction = SERV_DIR_SELL;
                    else if (!strcmp(l_direction_str, "buy"))
                        l_direction = SERV_DIR_BUY;
                    else {
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_PARAM_CERT_ERR, "Wrong direction of the token was "
                                                                "specified, possible directions: buy, sell.");
                        return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_PARAM_CERT_ERR;
                    }
                }
                uint64_t l_64 = 0;
                if (l_srv_uid_str && dap_id_uint64_parse(l_srv_uid_str, &l_64)) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_HEX_ERR,
                                                            "Can't recognize '%s' string as 64-bit id, hex or dec.", l_srv_uid_str);
                    return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_HEX_ERR;
                }
                l_srv_uid.uint64 = l_64;

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
                    json_obj_net_srv = dap_json_object_new();
                    dap_json_object_add_uint64(json_obj_net_srv, "count", l_orders_num);
                    dap_json_t *json_arr_out = dap_json_array_new();
                    for (dap_list_t *l_temp = l_orders; l_temp; l_temp = l_temp->next){
                        dap_json_t *json_obj_order = dap_json_object_new();
                        dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t*)l_temp->data;
                        dap_chain_net_srv_order_dump_to_json(l_order, json_obj_order, l_hash_out_type, l_net->pub.native_ticker, a_version);
                        dap_json_array_add(json_arr_out, json_obj_order);
                    }
                    dap_json_object_add_object(json_obj_net_srv, "orders", json_arr_out);
                    l_ret = 0;
                    dap_list_free_full(l_orders, NULL);
                } else {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_CANT_GET_ERR, "Can't get orders: some internal error or wrong params");
                    l_ret = -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_CANT_GET_ERR ;
                }
            } else if(!dap_strcmp( l_order_str, "dump" )) {
                // Select with specified service uid
                bool l_tx_to_json = dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-tx_to_json", NULL);
                if ( l_order_hash_str ){
                    dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_find_by_hash_str( l_net, l_order_hash_hex_str );
                    json_obj_net_srv = dap_json_object_new();                    
                    if (l_order) {
                        if (l_tx_to_json) {
                            uint64_t l_order_size = dap_chain_net_srv_order_get_size(l_order);
                            char *l_tx_hash_str = dap_hash_fast_str_new(l_order, dap_chain_net_srv_order_get_size(l_order));

                            dap_json_object_add_object(json_obj_net_srv, "data_hash", dap_json_object_new_string(l_tx_hash_str));
                            DAP_DELETE(l_tx_hash_str);
                            dap_json_object_add_object(json_obj_net_srv,"data_type", dap_json_object_new_string("order"));
                            dap_json_object_add_object(json_obj_net_srv,"data_size", dap_json_object_new_uint64(l_order_size));
                            char *l_data_str = dap_enc_base58_encode_to_str(l_order, l_order_size);
                            dap_json_object_add_object(json_obj_net_srv,"data", dap_json_object_new_string(l_data_str));
                        } else {
                            dap_chain_net_srv_order_dump_to_json(l_order, json_obj_net_srv, l_hash_out_type, l_net->pub.native_ticker, a_version);
                            l_ret = 0;
                        }
                    } else {                        
                        if(!dap_strcmp(l_hash_out_type,"hex"))
                            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_DUMP_CANT_FIND_ERR,
                                                                    "Can't find order with hash %s\n", l_order_hash_hex_str );
                        else
                            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_DUMP_CANT_FIND_ERR,
                                                                    "Can't find order with hash %s\n", l_order_hash_base58_str );
                        l_ret = -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_DUMP_CANT_FIND_ERR;                        
                    }
                }
                // else {  memory ciller cmd
                //     dap_list_t * l_orders = NULL;
                //     size_t l_orders_num = 0;
                //     dap_chain_net_srv_uid_t l_srv_uid={{0}};
                //     uint256_t l_price_min = {};
                //     uint256_t l_price_max = {};
                //     dap_chain_net_srv_price_unit_uid_t l_price_unit={{0}};
                //     dap_chain_net_srv_order_direction_t l_direction = SERV_DIR_UNDEFINED;

                //     if( !dap_chain_net_srv_order_find_all_by( l_net,l_direction,l_srv_uid,l_price_unit, NULL, l_price_min, l_price_max,&l_orders,&l_orders_num) ){
                //         json_obj_net_srv = dap_json_object_new();
                //         dap_json_object_add_object(json_obj_net_srv, "count", dap_json_object_new_uint64(l_orders_num));
                //         dap_json_t *json_arr_out = dap_json_array_new();
                //         for(dap_list_t *l_temp = l_orders;l_temp; l_temp = l_orders->next) {
                //             dap_json_t *json_obj_order = dap_json_object_new();
                //             dap_chain_net_srv_order_t *l_order =(dap_chain_net_srv_order_t *) l_temp->data;
                //             dap_chain_net_srv_order_dump_to_json(l_order, json_obj_order, l_hash_out_type, l_net->pub.native_ticker, l_need_sign, a_version);
                //             dap_json_array_add(json_arr_out, json_obj_order);
                //         }
                //         dap_json_object_add_object(json_obj_net_srv, "orders", json_arr_out);
                //         l_ret = 0;
                //     }else{
                //         dap_json_rpc_error_add(*json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_CANT_GET_ERR,"Can't get orders: some internal error or wrong params");
                //         l_ret = -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_FIND_CANT_GET_ERR ;
                //     }
                //     dap_list_free_full(l_orders, NULL);
                // }
            } else if (!dap_strcmp(l_order_str, "delete")) {
                if (l_order_hash_str) {

                    json_obj_net_srv = dap_json_object_new();                    
                    l_ret = dap_chain_net_srv_order_delete_by_hash_str_sync(l_net, l_order_hash_hex_str);
                    if (!l_ret)
                        dap_json_object_add_string(json_obj_net_srv, "order_hash", l_order_hash_str);
                    else {
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_DEL_CANT_FIND_HASH_ERR, "Can't find order with hash %s\n", l_order_hash_str);
                        l_ret = -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_DEL_CANT_FIND_HASH_ERR;
                    }
                } else {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_DEL_NEED_HASH_PARAM_ERR, "need -hash param to obtain what the order we need to dump\n");
                    l_ret = -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_DEL_NEED_HASH_PARAM_ERR;
                }
            } else if(!dap_strcmp( l_order_str, "create" )) {
                if (dap_chain_net_get_role(l_net).enums > NODE_ROLE_MASTER) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_ROLE_ERR, "Node role should be not lower than master\n");
                    return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_ROLE_ERR;
                }
                const char *l_order_cert_name = NULL;
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-cert", &l_order_cert_name);
                if ( l_srv_uid_str && l_price_str && l_price_token_str && l_price_unit_str && l_units_str) {
                    dap_chain_srv_uid_t l_srv_uid={{0}};
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
                            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_UNDEF_ORDER_DIR_ERR, "Wrong direction of the token was "
                                                                                                                    "specified, possible directions: buy, sell.");
                            return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_UNDEF_ORDER_DIR_ERR;
                        }
                    }

                    if (l_expires_str)
                        l_expires = (dap_time_t ) atoll( l_expires_str);
                    uint64_t l_64 = 0;
                    if (l_srv_uid_str && dap_id_uint64_parse(l_srv_uid_str, &l_64)) {
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CANT_RECOGNIZE_ERR,
                                                                    "Can't recognize '%s' string as 64-bit id, hex or dec.", l_srv_uid_str);
                        return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CANT_RECOGNIZE_ERR;
                    } else if (!l_srv_uid_str){
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_REQUIRED_PARAM_UID_ERR, "Parameter -srv_uid is required.");
                        return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_REQUIRED_PARAM_UID_ERR;
                    }
                    l_srv_uid.uint64 = l_64;
                    if (l_node_addr_str){
                        if (dap_chain_node_addr_str_check(l_node_addr_str)) {
                            dap_chain_node_addr_from_str( &l_node_addr, l_node_addr_str );
                        } else {
                            log_it(L_ERROR, "Can't parse \"%s\" as node addr", l_node_addr_str);
                            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CANT_PARSE_NODE_ADDR_ERR, "The order has not been created. "
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
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_UNDEF_PRICE_UNIT_ERR,
                                                                "Wrong unit type sepcified, possible values: B, KB, MB, SEC, DAY, PCS");
                        return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_UNDEF_PRICE_UNIT_ERR;
                    } 
                    
                    strncpy(l_price_token, l_price_token_str, DAP_CHAIN_TICKER_SIZE_MAX - 1);
                    size_t l_ext_len = l_ext ? strlen(l_ext) + 1 : 0;
                    // get cert to order sign
                    dap_cert_t *l_cert = NULL;
                    dap_enc_key_t *l_key = NULL;
                    if (l_order_cert_name) {
                        l_cert = dap_cert_find_by_name(l_order_cert_name);
                        if (l_cert) {
                            l_key = l_cert->enc_key;
                            if (!l_key->priv_key_data || !l_key->priv_key_data_size) {
                                log_it(L_ERROR, "Certificate '%s' doesn't contain a private key", l_order_cert_name);
                                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CERT_WITHOUT_KEY_ERR,
                                    "Certificate '%s' doesn't contain a private key", l_order_cert_name);
                                return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CERT_WITHOUT_KEY_ERR;
                            }
                        } else {
                            log_it(L_ERROR, "Can't load cert '%s' for sign order", l_order_cert_name);
                            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CANT_LOAD_CERT_ERR, "Can't load cert '%s' for sign "
                                                                                "order", l_order_cert_name);
                            return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CANT_LOAD_CERT_ERR;
                        }
                    } else {
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CERT_NAME_NOT_WALID_ERR,
                                                                "The certificate name was not "
                                                                "specified. Since version 5.2 it is not possible to "
                                                                "create unsigned orders.");
                        return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_CERT_NAME_NOT_WALID_ERR;
                    }
                // create order
                    char * l_order_new_hash_str = dap_chain_net_srv_order_create(
                        l_net,l_direction, l_srv_uid, l_node_addr,l_tx_cond_hash, &l_price, l_price_unit,
                        l_price_token, l_expires, (uint8_t *)l_ext, l_ext_len, l_units, l_region_str, l_continent_num, l_key);
                    if (l_order_new_hash_str) {
                        json_obj_net_srv = dap_json_object_new();
                        dap_json_object_add_string(json_obj_net_srv, "order_hash", l_order_new_hash_str);
                        DAP_DELETE(l_order_new_hash_str);
                    } else {
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_ORDER_ERR,
                            "Error! Can't created order\n");
                        l_ret = -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_ORDER_ERR;
                    }    
                } else {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_MISSED_PARAM_ERR,
                        "Missed some required params\n");
                    return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_CREATE_MISSED_PARAM_ERR;
                }
            } else if (l_order_str) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UNKNOWN_SUB_COM_ERR,
                    "Unrecognized subcommand '%s'", l_order_str);
                return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UNKNOWN_SUB_COM_ERR;
            }
        } else if (l_get_limits_str){
            const char *l_provider_pkey_hash_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-provider_pkey_hash", &l_provider_pkey_hash_str);

            const char *l_client_pkey_hash_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-client_pkey_hash", &l_client_pkey_hash_str);

            if (!l_provider_pkey_hash_str){
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_REQUIRED_PARAM_PPKHASH_ERR,
                    "Command 'get_limits' require the parameter provider_pkey_hash");
                return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_REQUIRED_PARAM_PPKHASH_ERR;
            }

            if (!l_client_pkey_hash_str){
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_REQUIRED_PARAM_CPKHASH_ERR,
                    "Command 'get_limits' require the parameter client_pkey_hash");
                return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_REQUIRED_PARAM_CPKHASH_ERR;
            }

            uint64_t l_64 = 0;
            if (l_srv_uid_str && dap_id_uint64_parse(l_srv_uid_str, &l_64)) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_CANT_REC_UID_STR_ERR,
                                                            "Can't recognize '%s' string as 64-bit id, hex or dec.", l_srv_uid_str);
                return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_CANT_REC_UID_STR_ERR;
            } else if (!l_srv_uid_str){
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_REQUIRED_PARAM_UID_ERR,
                                                                                                "Parameter -srv_uid is required.");
                return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_REQUIRED_PARAM_UID_ERR;
            }

            dap_chain_srv_uid_t l_srv_uid= { .uint64 = l_64};
            dap_chain_net_srv_ch_remain_service_store_t *l_remain_service = NULL;
            size_t l_remain_service_size = 0;
            char *l_remain_limits_gdb_group =  dap_strdup_printf( "local.%s.0x%016"DAP_UINT64_FORMAT_x".remain_limits.%s",
                                                                l_net->pub.gdb_groups_prefix, l_srv_uid.uint64,
                                                                l_provider_pkey_hash_str);

            l_remain_service = (dap_chain_net_srv_ch_remain_service_store_t*) dap_global_db_get_sync(l_remain_limits_gdb_group, l_client_pkey_hash_str, &l_remain_service_size, NULL, NULL);
            DAP_DELETE(l_remain_limits_gdb_group);

            if(!l_remain_service || !l_remain_service_size){
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_CANT_GET_REM_SERV_DATA_ERR,
                                                                                            "Can't get remain service data");
                return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_GETLIM_CANT_GET_REM_SERV_DATA_ERR;
            }
            json_obj_net_srv = dap_json_object_new();

            dap_json_object_add_string(json_obj_net_srv, a_version == 1 ? "provider" : "sig_inf_provider", l_provider_pkey_hash_str);
            dap_json_object_add_string(json_obj_net_srv, a_version == 1 ? "client" : "sig_inf_client", l_client_pkey_hash_str);
            dap_json_object_add_object(json_obj_net_srv, "sec", dap_json_object_new_uint64((uint64_t)l_remain_service->limits_ts));
            dap_json_object_add_object(json_obj_net_srv, "bytes", dap_json_object_new_uint64((uint64_t)l_remain_service->limits_bytes));
            DAP_DELETE(l_remain_service);
        } else {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UNKNOWN,
                                                                        "Unrecognized command.");
            return -DAP_CHAIN_NET_SRV_CLI_COM_ORDER_UNKNOWN;
        }
    }
    if (json_obj_net_srv)
        dap_json_array_add(a_json_arr_reply, json_obj_net_srv);
    return l_ret;
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
static int s_pay_verificator_callback(dap_ledger_t * a_ledger, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_in_hash, dap_chain_tx_out_cond_t *a_cond, bool a_owner, bool a_from_mempool)
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

    l_sign = dap_chain_datum_tx_item_sig_get_sign((dap_chain_tx_sig_t *)l_sig);
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

static void s_pay_updater_callback(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_out, dap_hash_fast_t *a_tx_out_hash, dap_chain_tx_out_cond_t *a_cond)
{
    if (dap_chain_net_get_load_mode(a_ledger->net))
        return;
    dap_chain_net_srv_t *l_net_srv = dap_chain_srv_get_internal(a_ledger->net->pub.id, a_cond->header.srv_uid);
    if (!l_net_srv) // No error, just no active service found
        return;
    dap_chain_net_srv_ch_grace_control(l_net_srv, a_tx_out_hash);
}

dap_chain_net_srv_price_t *dap_chain_net_srv_get_price_from_order(dap_chain_net_srv_t *a_service, dap_chain_net_srv_order_t *a_order)
{
    dap_chain_net_srv_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_price_t);
    if (!l_price) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    l_price->value_datoshi = a_order->price;
    dap_stpcpy(l_price->token, a_order->price_ticker);
    l_price->units = a_order->units;
    l_price->units_uid = a_order->price_unit;
    dap_hash_fast_t l_order_pkey_hash = {};
    dap_sign_get_pkey_hash((dap_sign_t*)(a_order->ext_n_sign + a_order->ext_size), &l_order_pkey_hash);
    dap_hash_fast_t l_price_pkey_hash = {};
    dap_cert_get_pkey_hash(a_service->receipt_sign_cert, &l_price_pkey_hash);
    if (!dap_hash_fast_compare(&l_order_pkey_hash, &l_price_pkey_hash)) {
        log_it(L_ERROR, "pkey in order not equal to pkey in config.");
        DAP_DELETE(l_price);
        return NULL;
    }
    return l_price;
}

/**
 * @brief dap_chain_net_srv_add
 * @param a_uid
 * @param a_callback_request
 * @param a_callback_response_success
 * @param a_callback_response_error
 * @return
 */
dap_chain_net_srv_t *dap_chain_net_srv_create(dap_chain_net_id_t a_net_id, dap_chain_srv_uid_t a_srv_uid, dap_config_t *a_config, dap_chain_net_srv_callbacks_t *a_network_callbacks)
{
    const char *l_billing_section_name = "billing";
    dap_chain_net_srv_t *l_srv = DAP_NEW_Z(dap_chain_net_srv_t);
    if (!l_srv) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    pthread_mutex_init(&l_srv->grace_mutex, NULL);
    if (a_network_callbacks)
        l_srv->callbacks = *a_network_callbacks;
    l_srv->net_id = a_net_id;
    l_srv->uid = a_srv_uid;
    l_srv->allow_free_srv = dap_config_get_item_bool_default(a_config, l_billing_section_name, "allow_free_srv", false);
    if (l_srv->allow_free_srv)
        return l_srv;
    l_srv->grace_period = dap_config_get_item_uint32_default(a_config, l_billing_section_name, "grace_period", DAP_CHAIN_NET_SRV_GRACE_PERIOD_DEFAULT);
    const char *l_wallet_addr_str = dap_config_get_item_str(a_config, "wallet_addr", NULL);
    if (!l_wallet_addr_str) {
        log_it(L_ERROR, "Wallet address is not defined. Check service configuration file.");
        DAP_DELETE(l_srv);
        return NULL;
    }
    dap_chain_addr_t *l_wallet_addr = dap_chain_addr_from_str(l_wallet_addr_str);
    if(l_wallet_addr) {
        log_it(L_ERROR, "Can't get wallet addr from wallet_addr in config file.");
        DAP_DELETE(l_srv);
        return NULL;
    }
    l_srv->wallet_addr = *l_wallet_addr;
    DAP_DELETE(l_wallet_addr);
    const char *l_cert_name = dap_config_get_item_str_default(a_config, l_billing_section_name, "receipt_sign_cert", NULL);
    if (!l_cert_name) {
        log_it(L_ERROR, "Receipt sign certificate is not defined. Check node configuration file.");
        DAP_DELETE(l_srv);
        return NULL;
    }
    dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_name);
    if (!l_cert) {
        log_it(L_ERROR, "Can't find cert %s.", l_cert_name);
        DAP_DEL_Z(l_srv);
        return NULL;
    }
    if (!l_cert->enc_key || !l_cert->enc_key->priv_key_data || !l_cert->enc_key->priv_key_data_size) {
        log_it(L_ERROR, "Certificate %s doesn't contain a private key", l_cert_name);
        DAP_DEL_Z(l_srv);
        return NULL;
    }
    l_srv->receipt_sign_cert = l_cert;
    return l_srv;
}

/**
 * @brief dap_chain_net_srv_del
 * @param a_srv
 */
void dap_chain_net_srv_del(dap_chain_net_srv_t *a_srv)
{
// sanity check
    dap_return_if_fail(a_srv);
// grace table clean
    dap_chain_net_srv_grace_usage_t *l_gdata, *l_gdata_tmp;
    pthread_mutex_lock(&a_srv->grace_mutex);
    HASH_ITER(hh, a_srv->grace_hash_tab, l_gdata, l_gdata_tmp) {
        HASH_DEL(a_srv->grace_hash_tab, l_gdata);
        DAP_DELETE(l_gdata);
    }
    pthread_mutex_unlock(&a_srv->grace_mutex);
    DAP_DELETE(a_srv);
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
    return dap_chain_datum_tx_receipt_sign_add(l_receipt, a_srv->receipt_sign_cert->enc_key);
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