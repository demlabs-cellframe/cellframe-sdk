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
#include "dap_chain_net_srv_ch.h"

#ifdef DAP_MODULES_DYNAMIC
#include "dap_modules_dynamic_cdb.h"
#endif

#include "dap_chain_node_cli_cmd.h"

#define LOG_TAG "chain_net_srv"

static int s_cli_net_srv(int argc, char **argv, void **reply);

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
            "\tCreate general service order (VPN as usually)"
        "net_srv get_limits -net <net_name> -srv_uid <service_UID> -provider_pkey_hash <service_provider_public_key_hash> -client_pkey_hash <client_public_key_hash>\n"
            "\tShow service billing info"
        "net_srv report\n"
            "\tGet report about srv usage"
        );
    dap_ledger_tx_add_notify(a_net->pub.ledger, dap_chain_net_srv_ch_tx_cond_added_cb, NULL);
    dap_chain_net_srv_ch_init();
    return 0;
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
static int s_cli_net_srv( int argc, char **argv, void **a_str_reply)
{
    int arg_index = 1;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type, "hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }


    int l_report = dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "report", NULL);
    if (l_report) {
        const char *l_report_str = dap_chain_net_srv_ch_create_statistic_report();
        dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_report_str);
        DAP_DEL_Z(l_report_str);
        return 0;
    }

    int l_ret = dap_chain_node_cli_cmd_values_parse_net_chain( &arg_index, argc, argv, a_str_reply, NULL, &l_net,
                                                               CHAIN_TYPE_INVALID);
    if ( l_net ) {
        dap_string_t *l_string_ret = dap_string_new("");

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
            char *l_order_hash_hex_str = NULL;
            char *l_order_hash_base58_str = NULL;
            // datum hash may be in hex or base58 format
            if (l_order_hash_str) {
                if(!dap_strncmp(l_order_hash_str, "0x", 2) || !dap_strncmp(l_order_hash_str, "0X", 2)) {
                    l_order_hash_hex_str = dap_strdup(l_order_hash_str);
                    l_order_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_order_hash_str);
                } else {
                    l_order_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_order_hash_str);
                    l_order_hash_base58_str = dap_strdup(l_order_hash_str);
                }
            }
            if(l_continent_str && l_continent_num <= 0) {
                dap_string_t *l_string_err = dap_string_new("Unrecognized \"-continent\" option=");
                dap_string_append_printf(l_string_err, "\"%s\". Variants: ", l_continent_str);
                int i = 0;
                while(1) {
                    const char *l_continent = dap_chain_net_srv_order_continent_to_str(i);
                    if(!l_continent)
                        break;
                    if(!i)
                        dap_string_append_printf(l_string_err, "\"%s\"", l_continent);
                    else
                        dap_string_append_printf(l_string_err, ", \"%s\"", l_continent);
                    i++;
                }
                dap_string_append_printf(l_string_ret, "%s\n", l_string_err->str);
                dap_string_free(l_string_err, true);
                l_ret = -1;
            } else if(!dap_strcmp(l_order_str, "update")) {
                if (!l_order_hash_str) {
                    l_ret = -1;
                    dap_string_append(l_string_ret, "Can't find option '-hash'\n");
                } else {
                    dap_chain_net_srv_order_t * l_order = dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_hex_str);
                    if(!l_order) {
                        l_ret = -2;
                        if(!dap_strcmp(l_hash_out_type,"hex"))
                            dap_string_append_printf(l_string_ret, "Can't find order with hash %s\n", l_order_hash_hex_str);
                        else
                            dap_string_append_printf(l_string_ret, "Can't find order with hash %s\n", l_order_hash_base58_str);
                    } else {
                        if (l_ext) {
                            l_order->ext_size = strlen(l_ext) + 1;
                            l_order = DAP_REALLOC(l_order, sizeof(dap_chain_net_srv_order_t) + l_order->ext_size);
                            memcpy(l_order->ext_n_sign, l_ext, l_order->ext_size);
                        } else
                            dap_chain_net_srv_order_set_continent_region(&l_order, l_continent_num, l_region_str);
                        /*if(l_region_str) {
                            strncpy(l_order->region, l_region_str, dap_min(sizeof(l_order->region) - 1, strlen(l_region_str) + 1));
                        }
                        if(l_continent_num>=0)
                            l_order->continent = l_continent_num;*/
                        char *l_new_order_hash_str = dap_chain_net_srv_order_save(l_net, l_order, false);
                        if (l_new_order_hash_str) {
                            const char *l_cert_str = NULL;
                            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-cert", &l_cert_str);
                            if (!l_cert_str) {
                                dap_cli_server_cmd_set_reply_text(a_str_reply, "Fee order creation requires parameter -cert");
                                return -7;
                            }
                            dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
                            if (!l_cert) {
                                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't load cert %s", l_cert_str);
                                return -8;
                            }
                            // delete prev order
                            if(dap_strcmp(l_new_order_hash_str, l_order_hash_hex_str))
                                dap_chain_net_srv_order_delete_by_hash_str_sync(l_net, l_order_hash_hex_str);
                            DAP_DELETE(l_new_order_hash_str);
                            dap_string_append_printf(l_string_ret, "order updated\n");
                        } else
                            dap_string_append_printf(l_string_ret, "Order did not updated\n");
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
                        dap_string_free(l_string_ret, true);
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Wrong direction of the token was "
                                                                       "specified, possible directions: buy, sell.");
                        return -18;
                    }
                }

                if (l_srv_uid_str && dap_id_uint64_parse(l_srv_uid_str ,&l_srv_uid.uint64)) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't recognize '%s' string as 64-bit id, hex or dec.", l_srv_uid_str);
                    return -21;
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
                    dap_string_append_printf(l_string_ret, "Found %zu orders:\n", l_orders_num);
                    for (dap_list_t *l_temp = l_orders; l_temp; l_temp = l_temp->next){
                        dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t*)l_temp->data;
                        dap_chain_net_srv_order_dump_to_string(l_order, l_string_ret, l_hash_out_type, l_net->pub.native_ticker);
                        dap_string_append(l_string_ret,"\n");
                    }
                    l_ret = 0;
                    dap_list_free_full(l_orders, NULL);
                } else {
                    l_ret = -5 ;
                    dap_string_append(l_string_ret,"Can't get orders: some internal error or wrong params\n");
                }
            } else if(!dap_strcmp( l_order_str, "dump" )) {
                // Select with specified service uid
                if ( l_order_hash_str ){
                    dap_chain_net_srv_order_t * l_order = dap_chain_net_srv_order_find_by_hash_str( l_net, l_order_hash_hex_str );                    if (l_order) {
                        dap_chain_net_srv_order_dump_to_string(l_order,l_string_ret, l_hash_out_type, l_net->pub.native_ticker);
                        l_ret = 0;
                    }else{
                        l_ret = -7 ;
                        if(!dap_strcmp(l_hash_out_type,"hex"))
                            dap_string_append_printf(l_string_ret,"Can't find order with hash %s\n", l_order_hash_hex_str );
                        else
                            dap_string_append_printf(l_string_ret,"Can't find order with hash %s\n", l_order_hash_base58_str );
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
                        dap_string_append_printf(l_string_ret,"Found %zd orders:\n",l_orders_num);
                        for(dap_list_t *l_temp = l_orders;l_temp; l_temp = l_orders->next) {
                            dap_chain_net_srv_order_t *l_order =(dap_chain_net_srv_order_t *) l_temp->data;
                            dap_chain_net_srv_order_dump_to_string(l_order, l_string_ret, l_hash_out_type, l_net->pub.native_ticker);
                            dap_string_append(l_string_ret, "\n");
                        }
                        l_ret = 0;
                    }else{
                        l_ret = -5 ;
                        dap_string_append(l_string_ret,"Can't get orders: some internal error or wrong params\n");
                    }
                    dap_list_free_full(l_orders, NULL);
                }
            } else if (!dap_strcmp(l_order_str, "delete")) {
                if (l_order_hash_str) {
                    
                    l_ret = dap_chain_net_srv_order_delete_by_hash_str_sync(l_net, l_order_hash_hex_str);
                    if (!l_ret)
                        dap_string_append_printf(l_string_ret, "Deleted order %s\n", l_order_hash_str);
                    else {
                        l_ret = -8;
                        dap_string_append_printf(l_string_ret, "Can't find order with hash %s\n", l_order_hash_str);
                    }
                } else {
                    l_ret = -9 ;
                    dap_string_append(l_string_ret,"need -hash param to obtain what the order we need to dump\n");
                }

            } else if(!dap_strcmp( l_order_str, "create" )) {
                if (dap_chain_net_get_role(l_net).enums > NODE_ROLE_MASTER) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Node role should be not lower than master\n");
                    return -4;
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
                            dap_cli_server_cmd_set_reply_text(a_str_reply, "Wrong direction of the token was "
                                                                           "specified, possible directions: buy, sell.");
                            return -18;
                        }
                    }

                    if (l_expires_str)
                        l_expires = (dap_time_t ) atoll( l_expires_str);
                    if (l_srv_uid_str && dap_id_uint64_parse(l_srv_uid_str ,&l_srv_uid.uint64)) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't recognize '%s' string as 64-bit id, hex or dec.", l_srv_uid_str);
                        return -21;
                    }else if (!l_srv_uid_str){
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Parameter -srv_uid is required.");
                        return -22;
                    }
                    if (l_node_addr_str){
                        if (dap_chain_node_addr_str_check(l_node_addr_str)) {
                            dap_chain_node_addr_from_str( &l_node_addr, l_node_addr_str );
                        } else {
                            log_it(L_ERROR, "Can't parse \"%s\" as node addr", l_node_addr_str);
                            dap_cli_server_cmd_set_reply_text(a_str_reply, "The order has not been created. "
                                                                           "Failed to convert string representation of '%s' "
                                                                           "to node address.", l_node_addr_str);
                            return -17;
                        }
                    } else {
                        l_node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
                    }
                    if (l_tx_cond_hash_str)
                        dap_chain_hash_fast_from_str (l_tx_cond_hash_str, &l_tx_cond_hash);
                    l_price = dap_chain_balance_scan(l_price_str);

                    uint64_t l_units = atoi(l_units_str);

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
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "Wrong unit type sepcified, possible values: B, KB, MB, SEC, DAY, PCS");
                        return -18;
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
                                dap_cli_server_cmd_set_reply_text(a_str_reply, "Certificate '%s' doesn't contain a private key", l_order_cert_name);
                                return -25;
                            }
                        } else {
                            log_it(L_ERROR, "Can't load cert '%s' for sign order", l_order_cert_name);
                            dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't load cert '%s' for sign "
                                                                           "order", l_order_cert_name);
                            return -19;
                        }
                    } else {
                        dap_cli_server_cmd_set_reply_text(a_str_reply, "The certificate name was not "
                                                                       "specified. Since version 5.2 it is not possible to "
                                                                       "create unsigned orders.");
                        return -20;
                    }
                // create order
                    char * l_order_new_hash_str = dap_chain_net_srv_order_create(
                        l_net,l_direction, l_srv_uid, l_node_addr,l_tx_cond_hash, &l_price, l_price_unit,
                        l_price_token, l_expires, (uint8_t *)l_ext, l_ext_len, l_units, l_region_str, l_continent_num, l_key);
                    if (l_order_new_hash_str)
                        dap_string_append_printf( l_string_ret, "Created order %s\n", l_order_new_hash_str);
                    else {
                        dap_string_append_printf( l_string_ret, "Error! Can't created order\n");
                        l_ret = -4;
                    }
                } else {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Missed some required params\n");
                    return -5;
                }
            } else if (l_order_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Unrecognized subcommand '%s'", l_order_str);
                return -14;
            }
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_string_ret->str);

        } else if (l_get_limits_str){
            const char *l_provider_pkey_hash_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-provider_pkey_hash", &l_provider_pkey_hash_str);

            const char *l_client_pkey_hash_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-client_pkey_hash", &l_client_pkey_hash_str);

            if (!l_provider_pkey_hash_str){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'get_limits' require the parameter provider_pkey_hash");
                dap_string_free(l_string_ret, true);
                return -15;
            }

            if (!l_client_pkey_hash_str){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'get_limits' require the parameter client_pkey_hash");
                dap_string_free(l_string_ret, true);
                return -16;
            }

            dap_chain_net_srv_uid_t l_srv_uid={{0}};
            if (l_srv_uid_str && dap_id_uint64_parse(l_srv_uid_str ,&l_srv_uid.uint64)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't recognize '%s' string as 64-bit id, hex or dec.", l_srv_uid_str);
                dap_string_free(l_string_ret, true);
                return -21;
            } else if (!l_srv_uid_str){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Parameter -srv_uid is required.");
                dap_string_free(l_string_ret, true);
                return -22;
            }

            dap_chain_net_srv_ch_remain_service_store_t *l_remain_service = NULL;
            size_t l_remain_service_size = 0;
            char *l_remain_limits_gdb_group =  dap_strdup_printf( "local.%s.0x%016"DAP_UINT64_FORMAT_x".remain_limits.%s",
                                                                l_net->pub.gdb_groups_prefix, l_srv_uid.uint64,
                                                                l_provider_pkey_hash_str);

            l_remain_service = (dap_chain_net_srv_ch_remain_service_store_t*) dap_global_db_get_sync(l_remain_limits_gdb_group, l_client_pkey_hash_str, &l_remain_service_size, NULL, NULL);
            DAP_DELETE(l_remain_limits_gdb_group);

            if(!l_remain_service || !l_remain_service_size){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't get remain service data");
                dap_string_free(l_string_ret, true);
                return -21;
            }

            dap_cli_server_cmd_set_reply_text(a_str_reply, "Provider %s. Client %s remain service values:\n"
                                                   "SEC: %"DAP_UINT64_FORMAT_U"\n"
                                                   "BYTES: %"DAP_UINT64_FORMAT_U"\n", l_provider_pkey_hash_str, l_client_pkey_hash_str,
                                              (uint64_t)l_remain_service->limits_ts, (uint64_t)l_remain_service->limits_bytes);

            dap_string_free(l_string_ret, true);
            DAP_DELETE(l_remain_service);
        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Unrecognized bcommand.");
            dap_string_free(l_string_ret, true);
            return -17;
        }
    }
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
    dap_chain_datum_tx_receipt_t *l_receipt = (dap_chain_datum_tx_receipt_t *)
                                               dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_RECEIPT, &l_receipt_size);
    if (!l_receipt){
        log_it(L_ERROR, "Can't find receipt.");
        return -1;
    }

    // Check provider sign
    dap_sign_t *l_sign = dap_chain_datum_tx_receipt_sign_get(l_receipt, l_receipt_size, 0);

    if (!l_sign){
        log_it(L_ERROR, "Can't get provider sign from receipt.");
        return -2;
    }

    if (dap_sign_verify_all(l_sign, dap_sign_get_size(l_sign), &l_receipt->receipt_info, sizeof(l_receipt->receipt_info))){
        log_it(L_ERROR, "Provider sign in receipt not passed verification.");
        return -3;
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

    // Check client sign
    l_sign = dap_chain_datum_tx_receipt_sign_get(l_receipt, l_receipt_size, 1);
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

    // Check price is less than maximum
    dap_chain_tx_in_cond_t *l_tx_in_cond = (dap_chain_tx_in_cond_t*)dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_IN_COND, NULL);
    dap_chain_datum_tx_t *l_tx_prev = dap_ledger_tx_find_by_hash(a_ledger , &l_tx_in_cond->header.tx_prev_hash);
    dap_chain_tx_out_cond_t *l_prev_out_cond = dap_chain_datum_tx_out_cond_get(l_tx_prev, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, NULL);

    uint256_t l_unit_price = {};
    if (!l_receipt->receipt_info.units) {
        log_it(L_ERROR, "Receipt units can't be a zero");
        return -11;
    }
    DIV_256(l_receipt->receipt_info.value_datoshi, GET_256_FROM_64(l_receipt->receipt_info.units), &l_unit_price);

    if( !IS_ZERO_256(l_prev_out_cond->subtype.srv_pay.unit_price_max_datoshi) &&
        compare256(l_unit_price, l_prev_out_cond->subtype.srv_pay.unit_price_max_datoshi) > 0){
        log_it(L_ERROR, "Value in receipt is exceed max allowable price.");
        return -12;
    }

    // check remainder on srv pay cond out is valid
    // find 'out' items
    uint256_t l_value = l_receipt->receipt_info.value_datoshi;
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
                    SUM_256_256(l_value, l_tx_out->header.value, &l_value)) {
                log_it(L_WARNING, "Integer overflow while sum of outs calculation");
                return -14;
            }
        } break;
        case TX_ITEM_TYPE_OUT_COND: {
            dap_chain_tx_out_cond_t *l_tx_out = (dap_chain_tx_out_cond_t*)l_item;
            if (l_tx_out->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE) {
                if (SUM_256_256(l_value, l_tx_out->header.value, &l_value)) {
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
    if (SUBTRACT_256_256(l_prev_out_cond->header.value, l_value, &l_value)) {
        log_it(L_WARNING, "Integer overflow while payback calculation");
        return -14;
    }
    return compare256(l_value, l_cond_out_value) ? log_it(L_ERROR, "Value in tx out is invalid!"), -13 : 0;
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

/**
 * @brief dap_chain_net_srv_add
 * @param a_uid
 * @param a_callback_request
 * @param a_callback_response_success
 * @param a_callback_response_error
 * @return
 */
dap_chain_net_srv_t *dap_chain_net_srv_create(const char *a_config_section, dap_chain_net_srv_callbacks_t *a_network_callbacks)

{
    dap_chain_net_srv_t *l_srv = DAP_NEW_Z(dap_chain_net_srv_t);
    if (!l_srv) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    pthread_mutex_init(&l_srv->banlist_mutex, NULL);
    pthread_mutex_init(&l_srv->grace_mutex, NULL);
    if (a_network_callbacks)
        l_srv->callbacks = *a_network_callbacks;
    if (a_config_section) {
        l_srv->grace_period = dap_config_get_item_uint32_default(g_config, a_config_section, "grace_period", DAP_CHAIN_NET_SRV_GRACE_PERIOD_DEFAULT);
        l_srv->allow_free_srv = dap_config_get_item_bool_default(g_config, a_config_section, "allow_free_srv", false);
    }
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
    pthread_mutex_lock(&a_srv->banlist_mutex);
    HASH_ITER(hh, a_srv->grace_hash_tab, l_gdata, l_gdata_tmp) {
        HASH_DEL(a_srv->grace_hash_tab, l_gdata);
        DAP_DELETE(l_gdata);
    }
    dap_chain_net_srv_banlist_item_t *it, *tmp;
    HASH_ITER(hh, a_srv->ban_list, it, tmp) {
        HASH_DEL(a_srv->ban_list, it);
        DAP_DELETE(it);
    }
    pthread_mutex_unlock(&a_srv->grace_mutex);
    pthread_mutex_unlock(&a_srv->banlist_mutex);
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
                                                               const void * a_ext, size_t a_ext_size)
{
    dap_chain_datum_tx_receipt_t * l_receipt = dap_chain_datum_tx_receipt_create(
                    a_srv->uid, a_price->units_uid, a_price->units, a_price->value_datoshi, a_ext, a_ext_size);
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
