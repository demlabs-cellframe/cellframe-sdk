/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Aleksandr Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

 DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
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
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#ifdef DAP_OS_LINUX
#include <dlfcn.h>
#endif
#include "json.h"
#include <pthread.h>
#include <dirent.h>

#include "uthash.h"
#include "utlist.h"
#include "dap_hash.h"
#include "dap_common.h"
#include "dap_enc_base58.h"
#include "dap_list.h"
#include "dap_string.h"
#include "dap_file_utils.h"

#include "dap_chain.h"
#include "dap_chain_common.h"
#include "dap_chain_net.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_order.h"
#include "dap_chain_net_srv_stream_session.h"
#include "dap_stream_ch_chain_net_srv.h"
#ifdef DAP_MODULES_DYNAMIC
#include "dap_modules_dynamic_cdb.h"
#endif

#include "dap_chain_node_cli_cmd.h"

#define LOG_TAG "chain_net_srv"

static size_t m_uid_count;
static dap_chain_net_srv_uid_t * m_uid;


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
static int s_cli_net_srv(int argc, char **argv, char **a_str_reply);
static void s_load(const char * a_path);
static void s_load_all(void);
static bool s_pay_verificator_callback(dap_ledger_t * a_ledger,dap_hash_fast_t *a_tx_out_hash, dap_chain_tx_out_cond_t *a_cond,
                                       dap_chain_datum_tx_t *a_tx_in, bool a_owner);
static bool s_fee_verificator_callback(dap_ledger_t * a_ledger, dap_hash_fast_t *a_tx_out_hash,dap_chain_tx_out_cond_t *a_cond,
                                       dap_chain_datum_tx_t *a_tx_in, bool a_owner);


/**
 * @brief dap_chain_net_srv_init
 * @return
 */
int dap_chain_net_srv_init()
{
    dap_chain_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, s_pay_verificator_callback, NULL);
    dap_chain_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE, s_fee_verificator_callback, NULL);
    dap_stream_ch_chain_net_srv_init();
    m_uid = NULL;
    m_uid_count = 0;
    if( dap_chain_net_srv_order_init() != 0 )
        return -1;
    dap_chain_node_cli_cmd_item_create ("net_srv", s_cli_net_srv, "Network services managment",
        "net_srv -net <net_name> order find [-direction {sell | buy}] [-srv_uid <Service UID>] [-price_unit <price unit>]"
        "[-price_token <Token ticker>] [-price_min <Price minimum>] [-price_max <Price maximum>]\n"
        "\tOrders list, all or by UID and/or class\n"
        "net_srv -net <net_name> order delete -hash <Order hash>\n"
        "\tOrder delete\n"
        "net_srv -net <net_name> order dump -hash <Order hash>\n"
        "\tOrder dump info\n"
        "net_srv -net <net_name> order create -direction {sell | buy} -srv_uid <Service UID> -price <Price>"
        " -price_unit <Price Unit> -price_token <token_ticker> [-node_addr <Node Address>] [-tx_cond <TX Cond Hash>]"
        " [-expires <Unix time when expires>] [-cert <cert name to sign order>]"
        " [{-ext <Extension with params> | -region <Region name> -continent <Continent name>}]\n"
#ifdef DAP_MODULES_DYNAMIC
        "\tOrder create\n"
            "net_srv -net <net_name> order static [save | delete]\n"
            "\tStatic nodelist create/delete\n"
            "net_srv -net <net_name> order recheck\n"
            "\tCheck the availability of orders\n"
#endif
        );

    s_load_all();

    return 0;
}

/**
 * @brief s_load_all
 */
void s_load_all(void)
{
    char * l_net_dir_str = dap_strdup_printf("%s/service.d", dap_config_path());
    DIR * l_net_dir = opendir( l_net_dir_str);
    if ( l_net_dir ){
        struct dirent * l_dir_entry;
        while ( (l_dir_entry = readdir(l_net_dir) )!= NULL ){
            if (l_dir_entry->d_name[0]=='\0' || l_dir_entry->d_name[0]=='.')
                continue;
            // don't search in directories
            char * l_full_path = dap_strdup_printf("%s/%s", l_net_dir_str, l_dir_entry->d_name);
            if(dap_dir_test(l_full_path)) {
                DAP_DELETE(l_full_path);
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
            DAP_DELETE(l_full_path);
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
static int s_cli_net_srv( int argc, char **argv, char **a_str_reply)
{
    int arg_index = 1;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type, "hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    int ret = dap_chain_node_cli_cmd_values_parse_net_chain( &arg_index, argc, argv, a_str_reply, NULL, &l_net );
    if ( l_net ) {
        //char * l_orders_group = dap_chain_net_srv_order_get_gdb_group( l_net );

        dap_string_t *l_string_ret = dap_string_new("");
        const char *l_order_str = NULL;
        int l_order_arg_pos = dap_chain_node_cli_find_option_val(argv, arg_index, argc, "order", &l_order_str);

        // Order direction
        const char *l_direction_str = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-direction", &l_direction_str);

        const char* l_srv_uid_str = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-srv_uid", &l_srv_uid_str);

        const char* l_srv_class_str = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-srv_class", &l_srv_class_str);

        const char* l_node_addr_str = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-node_addr", &l_node_addr_str);

        const char* l_tx_cond_hash_str = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-tx_cond", &l_tx_cond_hash_str);

        const char* l_price_str = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-price", &l_price_str);

        const char* l_expires_str = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-expires", &l_expires_str);

        const char* l_price_unit_str = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-price_unit", &l_price_unit_str);

        const char* l_price_token_str = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-price_token", &l_price_token_str);

        const char* l_ext = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-ext", &l_ext);

        const char *l_order_hash_str = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-hash", &l_order_hash_str);

        const char* l_region_str = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-region", &l_region_str);
        const char* l_continent_str = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-continent", &l_continent_str);

        int8_t l_continent_num = dap_chain_net_srv_order_continent_to_num(l_continent_str);

        char *l_order_hash_hex_str;
        char *l_order_hash_base58_str;
        // datum hash may be in hex or base58 format
        if(!dap_strncmp(l_order_hash_str, "0x", 2) || !dap_strncmp(l_order_hash_str, "0X", 2)) {
            l_order_hash_hex_str = dap_strdup(l_order_hash_str);
            l_order_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_order_hash_str);
        }
        else {
            l_order_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_order_hash_str);
            l_order_hash_base58_str = dap_strdup(l_order_hash_str);
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
            ret = -1;
        }
        // Update order
        else if(dap_strcmp(l_order_str, "update") == 0) {

            if(!l_order_hash_str) {
                ret = -1;
                dap_string_append(l_string_ret, "Can't find option '-hash'\n");
            }
            else {
                dap_chain_net_srv_order_t * l_order = dap_chain_net_srv_order_find_by_hash_str(l_net, l_order_hash_hex_str);
                if(!l_order) {
                    ret = -2;
                    if(!dap_strcmp(l_hash_out_type,"hex"))
                        dap_string_append_printf(l_string_ret, "Can't find order with hash %s\n", l_order_hash_hex_str);
                    else
                        dap_string_append_printf(l_string_ret, "Can't find order with hash %s\n", l_order_hash_base58_str);
                }
                else {
                    if(l_ext) {
                        l_order->ext_size = strlen(l_ext) + 1;
                        l_order = DAP_REALLOC(l_order, sizeof(dap_chain_net_srv_order_t) + l_order->ext_size);
                        memcpy(l_order->ext_n_sign, l_ext, l_order->ext_size);
                    }
                    else
                        dap_chain_net_srv_order_set_continent_region(&l_order, l_continent_num, l_region_str);
                    /*if(l_region_str) {
                        strncpy(l_order->region, l_region_str, min(sizeof(l_order->region) - 1, strlen(l_region_str) + 1));
                    }
                    if(l_continent_num>=0)
                        l_order->continent = l_continent_num;*/
                    char *l_new_order_hash_str = dap_chain_net_srv_order_save(l_net, l_order);
                    if (l_new_order_hash_str) {
                        // delete prev order
                        if(dap_strcmp(l_new_order_hash_str, l_order_hash_hex_str))
                            dap_chain_net_srv_order_delete_by_hash_str(l_net, l_order_hash_hex_str);
                        DAP_DELETE(l_new_order_hash_str);
                        dap_string_append_printf(l_string_ret, "order updated\n");
                    } else
                        dap_string_append_printf(l_string_ret, "Order did not updated\n");
                    DAP_DELETE(l_order);
                }
            }

        }
        else if ( dap_strcmp( l_order_str, "find" ) == 0 ){

            // Order direction
            const char *l_direction_str = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-direction", &l_direction_str);

            // Select with specified service uid
            const char *l_srv_uid_str = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-srv_uid", &l_srv_uid_str);


            // Select with specified price units
            const char*  l_price_unit_str = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-price_unit", &l_price_unit_str);

            // Token ticker
            const char*  l_price_token_str = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-price_token", &l_price_token_str);

            // Select with price not more than price_min
            const char*  l_price_min_str = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-price_min", &l_price_min_str);

            // Select with price not more than price_max
            const char*  l_price_max_str = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-price_max", &l_price_max_str);

            dap_chain_net_srv_order_direction_t l_direction = SERV_DIR_UNDEFINED;
            dap_chain_net_srv_uid_t l_srv_uid={{0}};
            uint256_t l_price_min = {};
            uint256_t l_price_max = {};
            dap_chain_net_srv_price_unit_uid_t l_price_unit={{0}};

            if ( l_direction_str ){
                if (strcmp(l_direction_str, "sell") == 0) {
                    l_direction = SERV_DIR_SELL;
                } else if ( strcmp(l_direction_str, "buy") == 0) {
                    l_direction = SERV_DIR_BUY;
                } else {
                    dap_string_free(l_string_ret, true);
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Wrong direction of the token was "
                                                                   "specified, possible directions: buy, sell.");
                    return -18;
                }
            }

            if ( l_srv_uid_str)
                l_srv_uid.uint64 = (uint64_t) atoll( l_srv_uid_str);

            if ( l_price_min_str )
                l_price_min = dap_chain_balance_scan(l_price_min_str);

            if ( l_price_max_str )
                l_price_max = dap_chain_balance_scan(l_price_max_str);
            if ( l_price_unit_str)
                l_price_unit.uint32 = (uint32_t) atol ( l_price_unit_str );

            dap_chain_net_srv_order_t * l_orders;
            size_t l_orders_num = 0;
            if( dap_chain_net_srv_order_find_all_by( l_net, l_direction,l_srv_uid,l_price_unit,l_price_token_str,l_price_min, l_price_max,&l_orders,&l_orders_num) == 0 ){
                dap_string_append_printf(l_string_ret, "Found %zu orders:\n", l_orders_num);
                size_t l_orders_size = 0;
                for (size_t i = 0; i< l_orders_num; i++){
                    dap_chain_net_srv_order_t *l_order =(dap_chain_net_srv_order_t *) (((byte_t*) l_orders) + l_orders_size);
                    dap_chain_net_srv_order_dump_to_string(l_order, l_string_ret, l_hash_out_type);
                    l_orders_size += dap_chain_net_srv_order_get_size(l_order);
                    dap_string_append(l_string_ret,"\n");
                }
                ret = 0;
                if (l_orders_num)
                    DAP_DELETE(l_orders);
             }else{
                ret = -5 ;
                dap_string_append(l_string_ret,"Can't get orders: some internal error or wrong params\n");
            }
        }else if( dap_strcmp( l_order_str, "dump" ) == 0 ){
            // Select with specified service uid
            if ( l_order_hash_str ){
                dap_chain_net_srv_order_t * l_order = dap_chain_net_srv_order_find_by_hash_str( l_net, l_order_hash_hex_str );
                if (l_order){
                    dap_chain_net_srv_order_dump_to_string(l_order,l_string_ret, l_hash_out_type);
                    ret = 0;
                }else{
                    ret = -7 ;
                    if(!dap_strcmp(l_hash_out_type,"hex"))
                        dap_string_append_printf(l_string_ret,"Can't find order with hash %s\n", l_order_hash_hex_str );
                    else
                        dap_string_append_printf(l_string_ret,"Can't find order with hash %s\n", l_order_hash_base58_str );
                }
            } else{

                dap_chain_net_srv_order_t * l_orders = NULL;
                size_t l_orders_num =0;
                dap_chain_net_srv_uid_t l_srv_uid={{0}};
                uint256_t l_price_min = {};
                uint256_t l_price_max = {};
                dap_chain_net_srv_price_unit_uid_t l_price_unit={{0}};
                dap_chain_net_srv_order_direction_t l_direction = SERV_DIR_UNDEFINED;

                if( dap_chain_net_srv_order_find_all_by( l_net,l_direction,l_srv_uid,l_price_unit, NULL, l_price_min, l_price_max,&l_orders,&l_orders_num) == 0 ){
                    dap_string_append_printf(l_string_ret,"Found %zd orders:\n",l_orders_num);
                    size_t l_orders_size = 0;
                    for(size_t i = 0; i < l_orders_num; i++) {
                        dap_chain_net_srv_order_t *l_order =(dap_chain_net_srv_order_t *) (((byte_t*) l_orders) + l_orders_size);
                        dap_chain_net_srv_order_dump_to_string(l_order, l_string_ret, l_hash_out_type);
                        l_orders_size += dap_chain_net_srv_order_get_size(l_order);
                        dap_string_append(l_string_ret, "\n");
                    }
                    ret = 0;
                }else{
                    ret = -5 ;
                    dap_string_append(l_string_ret,"Can't get orders: some internal error or wrong params\n");
                }
                DAP_DELETE(l_orders);
            }
        }else if( dap_strcmp( l_order_str, "delete" ) == 0 ){
            // Select with specified service uid
            //const char *l_order_hash_str = NULL;
            //dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-hash", &l_order_hash_str);
            if ( l_order_hash_str ){
                dap_chain_net_srv_order_t * l_order = dap_chain_net_srv_order_find_by_hash_str( l_net, l_order_hash_hex_str );
                if (l_order && dap_chain_net_srv_order_delete_by_hash_str(l_net,l_order_hash_hex_str) == 0){
                    ret = 0 ;
                    if(!dap_strcmp(l_hash_out_type,"hex"))
                        dap_string_append_printf(l_string_ret, "Deleted order %s\n", l_order_hash_hex_str);
                    else
                        dap_string_append_printf(l_string_ret, "Deleted order %s\n", l_order_hash_base58_str);
                }else{
                    ret = -8 ;
                    if(!dap_strcmp(l_hash_out_type,"hex"))
                        dap_string_append_printf(l_string_ret, "Can't find order with hash %s\n", l_order_hash_hex_str);
                    else
                        dap_string_append_printf(l_string_ret, "Can't find order with hash %s\n", l_order_hash_base58_str);
                }
                DAP_DELETE(l_order);
            } else{
                ret = -9 ;
                dap_string_append(l_string_ret,"need -hash param to obtain what the order we need to dump\n");
            }
        }else if( dap_strcmp( l_order_str, "create" ) == 0 ){
            const char *l_order_cert_name = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-cert", &l_order_cert_name);
            if ( l_srv_uid_str && l_price_str && l_price_token_str && l_price_unit_str) {
                dap_chain_net_srv_uid_t l_srv_uid={{0}};
                dap_chain_node_addr_t l_node_addr={0};
                dap_chain_hash_fast_t l_tx_cond_hash={{0}};
                dap_time_t l_expires = 0; // TS when the service expires
                uint256_t l_price = {0};
                char l_price_token[DAP_CHAIN_TICKER_SIZE_MAX]={0};
                dap_chain_net_srv_price_unit_uid_t l_price_unit={{0}};
                dap_chain_net_srv_order_direction_t l_direction = SERV_DIR_UNDEFINED;
                if ( l_direction_str ){
                    if (strcmp(l_direction_str, "sell") == 0 ) {
                        l_direction = SERV_DIR_SELL;
                        log_it(L_DEBUG, "Created order to sell");
                    } else if (strcmp(l_direction_str, "buy") == 0){
                        l_direction = SERV_DIR_BUY;
                        log_it(L_DEBUG, "Created order to buy");
                    } else {
                        log_it(L_WARNING, "Undefined order direction");
                        dap_string_free(l_string_ret, true);
                        dap_chain_node_cli_set_reply_text(a_str_reply, "Wrong direction of the token was "
                                                                       "specified, possible directions: buy, sell.");
                        return -18;
                    }
                }


                if (l_expires_str)
                    l_expires = (dap_time_t ) atoll( l_expires_str);
                l_srv_uid.uint64 = (uint64_t) atoll( l_srv_uid_str);
                if (l_node_addr_str){

                    if (dap_chain_node_addr_from_str( &l_node_addr, l_node_addr_str ) == 0 )
                        log_it( L_DEBUG, "node addr " NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(l_node_addr) );
                    else {
                        log_it(L_ERROR, "Can't parse \"%s\" as node addr", l_node_addr_str);
                        dap_chain_node_cli_set_reply_text(a_str_reply, "The order has not been created. "
                                                                       "Failed to convert string representation of '%s' "
                                                                       "to node address.", l_node_addr_str);
                        DAP_DELETE(l_string_ret);
                        return -17;
                    }
                } else {
                    l_node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
                }
                if (l_tx_cond_hash_str)
                    dap_chain_hash_fast_from_str (l_tx_cond_hash_str, &l_tx_cond_hash);
                l_price = dap_chain_balance_scan(l_price_str);
                l_price_unit.uint32 = (uint32_t) atol ( l_price_unit_str );
                strncpy(l_price_token, l_price_token_str, DAP_CHAIN_TICKER_SIZE_MAX - 1);
                size_t l_ext_len = l_ext? strlen(l_ext) + 1 : 0;
                // get cert to order sign
                dap_cert_t *l_cert = NULL;
                dap_enc_key_t *l_key = NULL;
                if(l_order_cert_name) {
                    l_cert = dap_cert_find_by_name(l_order_cert_name);
                    if(l_cert) {
                        l_key = l_cert->enc_key;
                    } else {
                        log_it(L_ERROR, "Can't load cert '%s' for sign order", l_order_cert_name);
                        dap_chain_node_cli_set_reply_text(a_str_reply, "Can't load cert '%s' for sign "
                                                                       "order", l_order_cert_name);
                        dap_string_free(l_string_ret, true);
                        return -19;
                    }
                }
                // create order
                char * l_order_new_hash_str = dap_chain_net_srv_order_create(
                            l_net,l_direction, l_srv_uid, l_node_addr,l_tx_cond_hash, &l_price, l_price_unit,
                            l_price_token, l_expires, (uint8_t *)l_ext, l_ext_len, l_region_str, l_continent_num, l_key);
                if(l_cert)
                    dap_cert_delete(l_cert);
                if (l_order_new_hash_str)
                    dap_string_append_printf( l_string_ret, "Created order %s\n", l_order_new_hash_str);
                else{
                    dap_string_append_printf( l_string_ret, "Error! Can't created order\n");
                    ret = -4;
                }
            } else {
                dap_string_append_printf( l_string_ret, "Missed some required params\n");
                ret=-5;
            }
        }
#ifdef DAP_MODULES_DYNAMIC
        else if( dap_strcmp( l_order_str, "recheck" ) == 0 ){
            int (*dap_chain_net_srv_vpn_cdb_server_list_check_orders)(dap_chain_net_t *a_net);
            dap_chain_net_srv_vpn_cdb_server_list_check_orders = dap_modules_dynamic_get_cdb_func("dap_chain_net_srv_vpn_cdb_server_list_check_orders");
            int l_init_res = dap_chain_net_srv_vpn_cdb_server_list_check_orders ? dap_chain_net_srv_vpn_cdb_server_list_check_orders(l_net) : -5;
            if (l_init_res >= 0) {
                dap_string_append_printf(l_string_ret, "Orders recheck started\n");
                ret = 0;
            } else {
                dap_string_append_printf(l_string_ret, "Orders recheck not started, code %d\n", l_init_res);
                ret = -10;
            }

        }else if( dap_strcmp( l_order_str, "static" ) == 0 ){
            // find the subcommand directly after the 'order' command
            int l_subcmd_save = dap_chain_node_cli_find_option_val(argv, l_order_arg_pos + 1, l_order_arg_pos + 2, "save", NULL);
            int l_subcmd_del = dap_chain_node_cli_find_option_val(argv, l_order_arg_pos + 1, l_order_arg_pos + 2, "delete", NULL) |
                               dap_chain_node_cli_find_option_val(argv, l_order_arg_pos + 1, l_order_arg_pos + 2, "del", NULL);

            int (*dap_chain_net_srv_vpn_cdb_server_list_static_create)(dap_chain_net_t *a_net) = NULL;
            int (*dap_chain_net_srv_vpn_cdb_server_list_static_delete)(dap_chain_net_t *a_net) = NULL;
            //  find func from dinamic library
            if(l_subcmd_save || l_subcmd_del) {
                dap_chain_net_srv_vpn_cdb_server_list_static_create = dap_modules_dynamic_get_cdb_func("dap_chain_net_srv_vpn_cdb_server_list_static_create");
                dap_chain_net_srv_vpn_cdb_server_list_static_delete = dap_modules_dynamic_get_cdb_func("dap_chain_net_srv_vpn_cdb_server_list_static_delete");
            }
            if(l_subcmd_save) {
                int l_init_res = dap_chain_net_srv_vpn_cdb_server_list_static_create ? dap_chain_net_srv_vpn_cdb_server_list_static_create(l_net) : -5;
                if(l_init_res >= 0){
                    dap_string_append_printf(l_string_ret, "Static node list saved, %d orders in list\n", l_init_res);
                    ret = 0;
                }
                else{
                    dap_string_append_printf(l_string_ret, "Static node list not saved, error code %d\n", l_init_res);
                    ret = -11;
                }

            } else if(l_subcmd_del) {
                int l_init_res = dap_chain_net_srv_vpn_cdb_server_list_static_delete ? dap_chain_net_srv_vpn_cdb_server_list_static_delete(l_net) : -5;
                if(!l_init_res){
                    dap_string_append_printf(l_string_ret, "Static node list deleted\n");
                    ret = 0;
                }
                else if(l_init_res > 0){
                    dap_string_append_printf(l_string_ret, "Static node list already deleted\n");
                    ret = -12;
                }
                else
                    dap_string_append_printf(l_string_ret, "Static node list not deleted, error code %d\n", l_init_res);
            } else {
                dap_string_append(l_string_ret, "not found subcommand 'save' or 'delete'\n");
                ret = -13;
            }
        }
#endif
        else if (l_order_str) {
            dap_string_append_printf(l_string_ret, "Unrecognized subcommand '%s'", l_order_str);
            ret = -14;
        } else {
            dap_string_append_printf(l_string_ret, "Command 'net_srv' requires subcommand 'order'");
            ret = -3;
        }
        dap_chain_node_cli_set_reply_text(a_str_reply, l_string_ret->str);
        dap_string_free(l_string_ret, true);
    }

    return ret;
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
static bool s_fee_verificator_callback(dap_ledger_t * a_ledger, dap_hash_fast_t *a_tx_out_hash,dap_chain_tx_out_cond_t *a_cond,
                                       dap_chain_datum_tx_t *a_tx_in, bool a_owner)
{
    return false;
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
static bool s_pay_verificator_callback(dap_ledger_t * a_ledger,dap_hash_fast_t *a_tx_out_hash, dap_chain_tx_out_cond_t *a_cond,
                                       dap_chain_datum_tx_t *a_tx_in, bool a_owner)
{
    UNUSED(a_ledger);
    UNUSED(a_tx_out_hash);
    if (!a_owner)
        return false;
    dap_chain_datum_tx_receipt_t *l_receipt = (dap_chain_datum_tx_receipt_t *)
                                               dap_chain_datum_tx_item_get(a_tx_in, NULL, TX_ITEM_TYPE_RECEIPT, NULL);
    if (!l_receipt)
        return false;
    dap_sign_t *l_sign = dap_chain_datum_tx_receipt_sign_get(l_receipt, l_receipt->size, 1);
    if (!l_sign)
        return false;
    dap_hash_fast_t l_pkey_hash;
    if (!dap_sign_get_pkey_hash(l_sign, &l_pkey_hash))
        return false;
    return dap_hash_fast_compare(&l_pkey_hash, &a_cond->subtype.srv_pay.pkey_hash);
    // TODO add comparision a_tx sign pkey with receipt provider sign pkey
}

int dap_chain_net_srv_parse_pricelist(dap_chain_net_srv_t *a_srv, const char *a_config_section)
{
    int ret = 0;
    if (!a_config_section)
        return ret;
    a_srv->grace_period = dap_config_get_item_uint32_default(g_config, a_config_section, "grace_period", 60);
    //! IMPORTANT ! This fetch is single-action and cannot be further reused, since it modifies the stored config data
    uint16_t l_pricelist_count = 0;
    char **l_pricelist = dap_config_get_array_str(g_config, a_config_section, "pricelist", &l_pricelist_count);
    for (uint16_t i = 0; i < l_pricelist_count; i++) {
        dap_chain_net_srv_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_price_t);
        short l_iter = 0;
        char *l_ctx;
        for (char *l_price_token = strtok_r(l_pricelist[i], ":", &l_ctx); l_price_token || l_iter == 6; l_price_token = strtok_r(NULL, ":", &l_ctx), ++l_iter) {
            //log_it(L_DEBUG, "Tokenizer: %s", l_price_token);
            switch (l_iter) {
            case 0:
                l_price->net_name = l_price_token;
                if (!(l_price->net = dap_chain_net_by_name(l_price->net_name))) {
                    log_it(L_ERROR, "Error parsing pricelist: can't find network \"%s\"", l_price_token);
                    break;
                }
                continue;
            case 1:
                l_price->value_datoshi = dap_chain_coins_to_balance(l_price_token);
                if (IS_ZERO_256(l_price->value_datoshi)) {
                    log_it(L_ERROR, "Error parsing pricelist: text on 2nd position \"%s\" is not floating number", l_price_token);
                    l_iter = 0;
                    break;
                }
                continue;
            case 2:
                dap_stpcpy(l_price->token, l_price_token);
                continue;
            case 3:
                l_price->units = strtoul(l_price_token, NULL, 10);
                if (!l_price->units) {
                    log_it(L_ERROR, "Error parsing pricelist: text on 4th position \"%s\" is not unsigned integer", l_price_token);
                    l_iter = 0;
                    break;
                }
                continue;
            case 4:
                if (!strcmp(l_price_token,      "SEC"))
                    l_price->units_uid.enm = SERV_UNIT_SEC;
                else if (!strcmp(l_price_token, "DAY"))
                    l_price->units_uid.enm = SERV_UNIT_DAY;
                else if (!strcmp(l_price_token, "MB"))
                    l_price->units_uid.enm = SERV_UNIT_MB;
                else if (!strcmp(l_price_token, "KB"))
                    l_price->units_uid.enm = SERV_UNIT_KB;
                else if (!strcmp(l_price_token, "B"))
                    l_price->units_uid.enm = SERV_UNIT_B;
                else if (!strcmp(l_price_token, "PCS"))
                    l_price->units_uid.enm = SERV_UNIT_PCS;
                else {
                    log_it(L_ERROR, "Error parsing pricelist: wrong unit type \"%s\"", l_price_token);
                    l_iter = 0;
                    break;
                }
                continue;
            case 5:
                if (!(l_price->wallet = dap_chain_wallet_open(l_price_token, dap_config_get_item_str_default(g_config, "resources", "wallets_path", NULL)))) {
                    log_it(L_ERROR, "Error parsing pricelist: can't open wallet \"%s\"", l_price_token);
                    l_iter = 0;
                    break;
                }
                continue;
            case 6:
                log_it(L_INFO, "Price item correct, added to service");
                ret++;
                break;
            default:
                break;
            }
            log_it(L_DEBUG, "Done with price item %d", i);
            if (l_iter == 6)
                DL_APPEND(a_srv->pricelist, l_price);
            else
                DAP_DELETE(l_price);
            break; // double break exits tokenizer loop and steps to next price item
        }
    }
    return ret;
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
                                           dap_chain_net_srv_callbacks_t *a_callbacks)

{
    service_list_t *l_sdata = NULL;
    dap_chain_net_srv_t * l_srv = NULL;
    dap_chain_net_srv_uid_t l_uid = {.uint64 = a_uid.uint64 }; // Copy to let then compiler to pass args via registers not stack
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_FIND(hh, s_srv_list, &l_uid, sizeof(l_uid), l_sdata);
    if(l_sdata == NULL) {
        l_srv = DAP_NEW_Z(dap_chain_net_srv_t);
        l_srv->uid.uint64 = a_uid.uint64;
        if(a_callbacks)
            l_srv->callbacks = *a_callbacks;
        pthread_mutex_init(&l_srv->banlist_mutex, NULL);
        l_sdata = DAP_NEW_Z(service_list_t);
        l_sdata->uid = l_uid;
        strncpy(l_sdata->name, a_config_section, sizeof(l_sdata->name));
        l_sdata->srv = l_srv;
        dap_chain_net_srv_parse_pricelist(l_srv, a_config_section);
        HASH_ADD(hh, s_srv_list, uid, sizeof(l_srv->uid), l_sdata);
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
void dap_chain_net_srv_del(dap_chain_net_srv_t * a_srv)
{
    service_list_t *l_sdata;
    if(!a_srv)
        return;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_FIND(hh, s_srv_list, a_srv, sizeof(dap_chain_net_srv_uid_t), l_sdata);
    if(l_sdata) {
        HASH_DEL(s_srv_list, l_sdata);
        pthread_mutex_destroy(&a_srv->banlist_mutex);
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
        if ( l_sdata->srv->callbacks.stream_ch_write)
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
        if ( l_sdata->srv->callbacks.stream_ch_opened)
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
        if ( l_sdata->srv->callbacks.stream_ch_closed)
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
        pthread_mutex_destroy(&l_sdata->srv->banlist_mutex);
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
dap_chain_net_srv_t * dap_chain_net_srv_get(dap_chain_net_srv_uid_t a_uid)
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
            l_srv_uids = DAP_NEW_SIZE(dap_chain_net_srv_uid_t, sizeof(dap_chain_net_srv_uid_t) * l_count_cur);
        }
        for(size_t i = 0; i < l_count_cur; i++) {
            service_list_t *l_sdata = l_list->data;
            memcpy(l_srv_uids + i, &l_sdata->uid, sizeof(dap_chain_net_srv_uid_t));
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
                                                               const void * a_ext, size_t a_ext_size)
{
    dap_chain_datum_tx_receipt_t * l_receipt = dap_chain_datum_tx_receipt_create(
                    a_srv->uid, a_price->units_uid, a_price->units, a_price->value_datoshi, a_ext, a_ext_size);
    // Sign with our wallet
    return dap_chain_datum_tx_receipt_sign_add(l_receipt, dap_chain_wallet_get_key(a_price->wallet, 0));
}


