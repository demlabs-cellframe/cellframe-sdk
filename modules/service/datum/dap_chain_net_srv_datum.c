/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
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

#include <errno.h>
#include "dap_chain_mempool.h"
#include "dap_config.h"
#include "dap_file_utils.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_net_srv_order.h"
#include "dap_chain_net_srv_datum.h"

#define LOG_TAG "chain_net_srv_datum"

static dap_chain_net_srv_t *s_srv_datum = NULL;
static int s_srv_datum_cli(int argc, char ** argv, void **a_str_reply);

void s_order_notficator(dap_store_obj_t *a_obj, void *a_arg);

static bool s_tag_check_datum(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,  dap_chain_datum_tx_item_groups_t *a_items_grp, dap_chain_tx_tag_action_type_t *a_action)
{
    //datum service do not produce transactions for now.
    return false;
}

int dap_chain_net_srv_datum_init()
{
    dap_cli_server_cmd_add("srv_datum", s_srv_datum_cli, "Service Datum commands", 
        "srv_datum -net <net_name> -chain <chain_name> datum save -datum <datum_hash>\n"
            "\tSaving datum from mempool to file.\n\n"
        "srv_datum -net <net_name> -chain <chain_name> datum load -datum <datum_hash>\n"
            "\tLoad datum custum from file to mempool.\n\n");
    s_srv_datum = DAP_NEW_Z(dap_chain_net_srv_t);
    if (!s_srv_datum) {
        log_it(L_CRITICAL, "%s", g_error_memory_alloc);
        return -1;
    }
    s_srv_datum->uid.uint64 = DAP_CHAIN_NET_SRV_DATUM_ID;

    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_DATUM_ID };
    dap_ledger_service_add(l_uid, "datum", s_tag_check_datum);
    
    return 0;
}

void dap_chain_net_srv_datum_deinit()
{

}

uint8_t * dap_chain_net_srv_file_datum_data_read(char * a_path, size_t *a_data_size) {
    uint8_t *l_datum_data = NULL;
    size_t l_datum_data_size = 0;
    FILE * l_file = fopen(a_path, "rb");
    if( l_file ){
        fseek(l_file, 0L, SEEK_END);
        //uint64_t l_file_size = ftell(l_file);
        l_datum_data_size = ftell(l_file);
        rewind(l_file);
        l_datum_data = DAP_NEW_SIZE(uint8_t, l_datum_data_size);
        if ( fread(l_datum_data, 1, l_datum_data_size, l_file ) != l_datum_data_size ){
            log_it(L_ERROR, "Can't read %"DAP_UINT64_FORMAT_U" bytes from the disk!", l_datum_data_size);
            DAP_DELETE(l_datum_data);
            fclose(l_file);
            return NULL;
        }
        fclose(l_file);
    }
    *a_data_size = l_datum_data_size;
    return l_datum_data;
}

char* dap_chain_net_srv_datum_custom_add(dap_chain_t * a_chain, const uint8_t *a_data, size_t a_data_size) {

    dap_chain_datum_t * l_datum = dap_chain_datum_create( DAP_CHAIN_DATUM_CUSTOM, a_data, a_data_size);
    if( l_datum == NULL){
        log_it(L_ERROR, "Failed to create custom datum.");
        return NULL;
    }

    // Finaly add datum to mempool
    char *l_hash_str = dap_chain_mempool_datum_add(l_datum, a_chain, "hex");
    return l_hash_str;
}

static int s_srv_datum_cli(int argc, char ** argv, void **a_str_reply)
{
    int arg_index = 1;
    dap_chain_net_t * l_chain_net = NULL;
    dap_chain_t * l_chain = NULL;

    if (dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index,argc,argv,a_str_reply,&l_chain,&l_chain_net, CHAIN_TYPE_INVALID)) {
        return -3;
    }

    const char * l_datum_hash_str = NULL;
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-datum", &l_datum_hash_str);
    if (!l_datum_hash_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Command srv_datum requires parameter '-datum' <datum hash>");
        return -4;
    }

    const char * l_system_datum_folder = dap_config_get_item_str(g_config, "resources", "datum_folder");
    if (!l_system_datum_folder){
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Configuration wasn't loaded");
        return -6;
    }

    const char * l_datum_cmd_str = NULL;
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "datum", &l_datum_cmd_str);
    if ( l_datum_cmd_str != NULL ) {
        if ( strcmp(l_datum_cmd_str, "save") == 0) {
            char * l_gdb_group = dap_chain_net_get_gdb_group_mempool_new(l_chain);

            size_t l_path_length = strlen(l_system_datum_folder)+8+strlen(l_datum_hash_str);
            char *l_path = DAP_NEW_Z_SIZE(char, l_path_length);
            snprintf(l_path, l_path_length, "%s/%s.datum", l_system_datum_folder, l_datum_hash_str);
            
            char * l_file_dir = dap_path_get_dirname(l_path);
            dap_mkdir_with_parents(l_file_dir);
            DAP_DELETE(l_file_dir);

            FILE * l_file = fopen(l_path,"wb");
            if( l_file ){
                size_t l_data_size = 0;
                dap_chain_datum_t* l_datum = (dap_chain_datum_t*)dap_global_db_get_sync(l_gdb_group, l_datum_hash_str, &l_data_size, NULL, NULL );
                if ( l_datum ){
                    size_t l_retbytes;
                    if ( (l_retbytes = fwrite(l_datum->data, 1, l_datum->header.data_size, l_file)) != l_datum->header.data_size ){
                        log_it(L_ERROR, "Can't write %u bytes on disk (processed only %zu)!", l_datum->header.data_size, l_retbytes);
                        fclose(l_file);
                        return -3;
                    }
                    fclose(l_file);
                    DAP_DELETE(l_datum);
                    return -5;
                }else{
                    log_it(L_ERROR,"Can't serialize certificate in memory");
                    fclose(l_file);
                    return -4;
                }
            }else{
                log_it(L_ERROR, "Can't open file '%s' for write: %s", l_path, strerror(errno));
                return -2;
            }
        }
        if ( strcmp(l_datum_cmd_str, "load") == 0 ) {

            size_t l_path_length = strlen(l_system_datum_folder)+8+strlen(l_datum_hash_str);
            char *l_path = DAP_NEW_Z_SIZE(char, l_path_length);
            snprintf(l_path, l_path_length, "%s/%s.datum", l_system_datum_folder, l_datum_hash_str);

            size_t l_datum_data_size = 0;
            uint8_t *l_datum_data = dap_chain_net_srv_file_datum_data_read(l_path, &l_datum_data_size);

            char *l_ret;
            if ((l_ret = dap_chain_net_srv_datum_custom_add(l_chain, l_datum_data, l_datum_data_size)) == NULL) {
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Can't place datum custom \"%s\" to mempool", l_datum_hash_str);
            }
            else {
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Datum custom %s was successfully placed to mempool", l_datum_hash_str); 
                DAP_DELETE(l_ret);
                return 0;
            }
        }
    }
    return -1;
}


/**
 * @brief s_order_notficator
 * @param a_arg
 * @param a_op_code
 * @param a_group
 * @param a_key
 * @param a_value
 * @param a_value_len
 */
void s_order_notficator(dap_store_obj_t *a_obj, void *a_arg)
{
    if (dap_store_obj_get_type(a_obj) == DAP_GLOBAL_DB_OPTYPE_DEL)
        return;
    const char * a_obj_key_str = a_obj->key ? a_obj->key : "unknow";

    dap_chain_net_t *l_net = (dap_chain_net_t *)a_arg;
    const dap_chain_net_srv_order_t *l_order = dap_chain_net_srv_order_check(a_obj->key, a_obj->value, a_obj->value_len);    // Old format comliance
    if (!l_order) {
        log_it(L_NOTICE, "Order %s is corrupted", a_obj_key_str);
        if (dap_global_db_driver_delete(a_obj, 1) != 0)
            log_it(L_ERROR,"Can't delete order %s", a_obj_key_str);
        return; // order is corrupted
    }

    if (!dap_chain_net_srv_uid_compare(l_order->srv_uid, s_srv_datum->uid))
        return; // order from another service
    dap_chain_net_srv_price_t *l_price = NULL;

    if (!l_price || l_price->net != l_net) {
        log_it(L_DEBUG, "Price for net %s is not set", l_net->pub.name);
        return; // price not set for this network
    }
    if ((l_order->price_unit.uint32 != SERV_UNIT_PCS) || (l_order->direction != SERV_DIR_BUY) ||
            (strncmp(l_order->price_ticker, l_price->token, DAP_CHAIN_TICKER_SIZE_MAX)) ||
            (!compare256(l_order->price, l_price->value_datoshi))) {
        char *l_balance_order = dap_chain_balance_to_coins(l_order->price);
        char *l_balance_service = dap_chain_balance_to_coins(l_price->value_datoshi);
        log_it(L_DEBUG, "Price from order (%s) is not equal to price from service pricelist (%s)", l_balance_order, l_balance_service);
        DAP_DELETE(l_balance_order);
        DAP_DELETE(l_balance_service);
        return; // price from order is not equal with service price
    }
    char l_tx_cond_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&l_order->tx_cond_hash, l_tx_cond_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
    dap_chain_t *l_chain;
    dap_chain_datum_t *l_datum = NULL;
    dap_chain_datum_tx_t *l_tx_cond = NULL;
    DL_FOREACH(l_net->pub.chains, l_chain) {
        size_t l_datum_size;
        char *l_gdb_group = dap_chain_net_get_gdb_group_mempool_new(l_chain);
        l_datum = (dap_chain_datum_t *)dap_global_db_get_sync(l_gdb_group, l_tx_cond_hash_str, &l_datum_size, NULL, NULL);
        if (l_datum)
            break;
    }
    if (l_datum)
        l_tx_cond = (dap_chain_datum_tx_t *)l_datum->data;
    else
        l_tx_cond = dap_ledger_tx_find_by_hash(l_net->pub.ledger, &l_order->tx_cond_hash);
    if (!l_tx_cond) {
        log_it(L_DEBUG, "Invalid tx cond datum hash");
        return;
    }
    int l_tx_out_cond_size;
    dap_chain_tx_out_cond_t *l_cond_out = (dap_chain_tx_out_cond_t *)
            dap_chain_datum_tx_item_get(l_tx_cond, NULL, TX_ITEM_TYPE_OUT_COND, &l_tx_out_cond_size);
    if (!l_cond_out || l_cond_out->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY) {
        log_it(L_DEBUG, "Condition with required subtype SRV_PAY not found in requested tx");
    }
    dap_hash_fast_t l_sign_hash;
    if (!dap_sign_get_pkey_hash((dap_sign_t *)(l_order->ext_n_sign + l_order->ext_size), &l_sign_hash)) {
         log_it(L_DEBUG, "Wrong order sign");
         return;
    }
}
