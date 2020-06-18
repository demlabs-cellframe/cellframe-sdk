/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "utlist.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_enc_http.h"
#include "dap_enc_base64.h"
#include "dap_http.h"

#include "dap_chain.h"
#include "dap_chain_net.h"
#include "dap_chain_ledger.h"
#include "dap_chain_wallet.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_in.h"
#include "dap_chain_datum_tx_in_cond.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_chain_datum_tx_out.h"
#include "dap_chain_datum_tx_pkey.h"
#include "dap_chain_datum_tx_receipt.h"
#include "dap_chain_datum_tx_sig.h"
#include "dap_chain_global_db.h"

#include "dap_chain_node_cli.h"

#include "dap_chain_mempool.h"
#include "dap_pkey.h"

#include "dap_chain_net_srv_vpn.h"
#include "dap_chain_net_srv_vpn_cdb.h"
#include "dap_chain_net_srv_vpn_cdb_auth.h"
#include "dap_chain_net_srv_vpn_cdb_server_list.h"


#define LOG_TAG "dap_chain_net_srv_vpn_cdb"

#define DB_URL "/db"
#define NODELIST_URL "/nodelist"

typedef struct tx_cond_template{
    char * wallet_name;
    dap_chain_wallet_t * wallet;

    long double value_coins;
    uint128_t value_datoshi;

    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    char * net_name;
    dap_chain_net_t * net;
    dap_ledger_t * ledger;
    time_t min_time; // Minimum time between transactions
    struct tx_cond_template *prev, *next;
} tx_cond_template_t;

static tx_cond_template_t *s_tx_cond_templates = NULL;
const char *c_wallets_path = NULL;

static int s_cli_vpn_cdb(int a_argc, char ** a_argv, void *arg_func, char **a_str_reply);

/**
 * @brief dap_chain_net_srv_vpn_cdb_init
 * @return
 */
int dap_chain_net_srv_vpn_cdb_init(dap_http_t * a_http)
{
    int ret=0;
    c_wallets_path = dap_chain_wallet_get_path(g_config);
    if (dap_config_get_item_bool_default( g_config,
                                                                "cdb",
                                                                "servers_list_enabled",
                                                                false)) {

        if (dap_chain_net_srv_vpn_cdb_server_list_init() != 0) {
            log_it(L_CRITICAL,"Can't init vpn servers list");
            return -10;
        }
    }

    dap_chain_node_cli_cmd_item_create ("vpn_cdb", s_cli_vpn_cdb, NULL, "VPN Central DataBase (CDB) commands",
        "vpn_cdb user create --login <Login> --password <Password> [--first_name <First Name] [--last_name <Last Name>] [--email <Email>]"
        "[--acive_days <Setup active day thats left for user >]\n"
            "\tCreate user with login, password and some more optional fields\n\n"
        "vpn_cdb user update --login <Login> [--password <Password>] [--first_name <First Name] [--last_name <Last Name>] [--email <Email>]"
                             "[--active_days <Setup active day thats left for user >]\n"
            "\tUpdate existent user\n"
        "vpn_cdb user delete --login <Login>\n"
            "\tDelete user by login\n"
        "vpn_cdb user show --login <Login>\n"
            "\tShow user fields by login\n"
        "vpn_cdb user check --login <Login> --password <Password>\n"
            "\tCompare <Password> with stored in GDB for <Login>\n"
        "vpn_cdb user list\n"
            "\tShow all users\n"
                                        );

    // Load all chain networks
    if (dap_config_get_item_bool_default( g_config,
                                                        "cdb",
                                                        "servers_list_enabled",
                                                        false)) {
        dap_chain_net_srv_vpn_cdb_server_list_add_proc ( a_http, NODELIST_URL);
    }
    if (dap_config_get_item_bool_default( g_config,"cdb_auth","enabled",false) ){

        dap_chain_net_srv_vpn_cdb_auth_init(  dap_config_get_item_str_default(g_config,"cdb_auth","domain","cdb"),
                                              dap_config_get_item_bool_default(g_config,"cdb_auth","registration_open",false)
                                              );
        dap_chain_net_srv_vpn_cdb_auth_add_proc( a_http , DB_URL );


        // Produce transaction for authorized users
        if (dap_config_get_item_bool_default( g_config,
                                                            "cdb_auth",
                                                            "tx_cond_create",
                                                            false)) {
            // Parse tx cond templates
            uint16_t l_tx_cond_tpls_count = 0;

            /* ! IMPORTANT ! This fetch is single-action and cannot be further reused, since it modifies the stored config data
             * ! it also must NOT be freed within this module !
             */
            char **l_tx_cond_tpls = dap_config_get_array_str(g_config, "cdb_auth", "tx_cond_templates", &l_tx_cond_tpls_count);
            if (l_tx_cond_tpls_count == 0) {
                log_it( L_ERROR, "No condition tpl, can't setup auth callback");
                return -5;
            }

            for (size_t i = 0 ; i < l_tx_cond_tpls_count; i++) {
                tx_cond_template_t *l_tx_cond_template = DAP_NEW_Z(tx_cond_template_t);

                // Parse template entries
                short l_step = 0;
                char *ctx;
                for (char *l_tpl_token = strtok_r(l_tx_cond_tpls[i], ":", &ctx); l_tpl_token || l_step == 5; l_tpl_token = strtok_r(NULL, ":", &ctx), ++l_step) {
                    switch (l_step) {
                    case 0:
                        if(!(l_tx_cond_template->wallet = dap_chain_wallet_open(l_tpl_token, c_wallets_path))) {
                            log_it(L_ERROR, "Can't open wallet \"%s\"", l_tpl_token);
                            DAP_DELETE(l_tx_cond_template);
                            break;
                        }
                        l_tx_cond_template->wallet_name = l_tpl_token;
                        continue;
                    case 1:
                        if (!(l_tx_cond_template->value_coins = strtold(l_tpl_token, NULL))) {
                            log_it(L_ERROR, "Error parsing tpl: text on 2nd position \"%s\" is not a number", l_tpl_token);
                            DAP_DELETE(l_tx_cond_template->wallet);
                            DAP_DELETE(l_tx_cond_template);
                            l_step = 0;
                            break;
                        }
                        l_tx_cond_template->value_datoshi = dap_chain_coins_to_balance(l_tx_cond_template->value_coins);
                        continue;
                    case 2:
                        if (!(l_tx_cond_template->min_time = (time_t)atoll(l_tpl_token))) {
                            log_it(L_ERROR, "Error parsing tpl: text on 3d position \"%s\" is not a number", l_tpl_token);
                            DAP_DELETE(l_tx_cond_template->wallet);
                            DAP_DELETE(l_tx_cond_template);
                            l_step = 0;
                            break;
                        }
                        continue;
                    case 3:
                        dap_stpcpy(l_tx_cond_template->token_ticker, l_tpl_token);
                        continue;
                    case 4:
                        if (!(l_tx_cond_template->net = dap_chain_net_by_name(l_tpl_token))
                                || !(l_tx_cond_template->ledger = dap_chain_ledger_by_net_name(l_tpl_token)))
                        {
                            log_it(L_ERROR, "Can't open network \"%s\" or ledger in it", l_tpl_token);
                            DAP_DELETE(l_tx_cond_template->wallet);
                            DAP_DELETE(l_tx_cond_template);
                            l_step = 0;
                            break;
                        }
                        l_tx_cond_template->net_name = l_tpl_token;
                        continue;
                    case 5:
                        log_it(L_INFO, "Condition template correct, added to list");
                        DL_APPEND(s_tx_cond_templates, l_tx_cond_template);
                        break;
                    default:
                        break;
                    }
                    log_it(L_DEBUG, "Done with tpl item %d", i);
                    break; // double break exits tokenizer loop and steps to next tpl item
                }
            }
            if (!s_tx_cond_templates) ret = -1;
        } else {
            log_it(L_INFO, "No conditional transactions, provide VPN service for free");
        }
    }
    return ret;
}


static int s_cli_vpn_cdb(int a_argc, char ** a_argv, void *arg_func, char **a_str_reply)
{
    const char *l_user_str = NULL;
    int l_arg_index = 1;
    int l_ret = 0;

    dap_chain_node_cli_find_option_val(a_argv, l_arg_index, a_argc, "user", &l_user_str);


    // Selected 'user' subcommand
    if ( l_user_str ){
        return dap_chain_net_srv_vpn_cdb_auth_cli_cmd_user(l_user_str,l_arg_index,  a_argc,  a_argv,a_str_reply);
    }
    return l_ret;
}


/**
 * @brief dap_chain_net_srv_vpn_cdb_deinit
 */
void dap_chain_net_srv_vpn_cdb_deinit()
{

}

/**
 * @brief dap_chain_net_srv_vpn_cdb_auth_after
 * @param a_delegate
 * @param a_login
 * @param a_pkey_b64
 */
void dap_chain_net_srv_vpn_cdb_auth_after(enc_http_delegate_t* a_delegate, const char * a_login, const char * a_pkey_b64 )
{
#ifndef __ANDROID__

    dap_enc_key_t *l_client_key = NULL;
    byte_t *l_pkey_raw = NULL;
    size_t l_pkey_raw_size = 0;
    log_it( L_DEBUG, "Authorized, now need to create conditioned transaction if not present key_len=%d", dap_strlen( a_pkey_b64));
    {
        size_t l_pkey_b64_length = dap_strlen( a_pkey_b64);
        l_pkey_raw = DAP_NEW_Z_SIZE(byte_t,l_pkey_b64_length);
        memset(l_pkey_raw, 0, l_pkey_b64_length);
        l_pkey_raw_size = dap_enc_base64_decode(a_pkey_b64, l_pkey_b64_length, l_pkey_raw, DAP_ENC_DATA_TYPE_B64_URLSAFE);
        char *l_pkey_gdb_group =  dap_strdup_printf( "cdb.%s.pkey", DAP_CHAIN_NET_SRV_VPN_CDB_GDB_PREFIX);
        log_it(L_DEBUG, "Pkey group '%s'", l_pkey_gdb_group);
        dap_chain_global_db_gr_set( dap_strdup(a_login), l_pkey_raw, l_pkey_raw_size, l_pkey_gdb_group);

        l_client_key = dap_enc_key_new(DAP_ENC_KEY_TYPE_SIG_TESLA);
        int l_res = dap_enc_key_deserealize_pub_key(l_client_key, l_pkey_raw, l_pkey_raw_size);
        // bad pkey
        if(l_res){
            log_it(L_WARNING, "dap_enc_key_deserealize_priv_key='%d'", l_res);
            DAP_DELETE(l_pkey_raw);
            l_pkey_raw_size = 0;
            l_pkey_raw = NULL;
        }
        DAP_DELETE(l_pkey_gdb_group);
    }

    tx_cond_template_t *l_tpl;
    DL_FOREACH(s_tx_cond_templates, l_tpl) {
        size_t l_gdb_group_size = 0;

        // Try to load from gdb
        //char *l_tx_cond_gdb_group =  dap_strdup_printf( "%s.%s.tx_cond", l_tpl->net->pub.name, DAP_CHAIN_NET_SRV_VPN_CDB_GDB_PREFIX);
        char *l_tx_cond_gdb_group =  dap_strdup_printf( "cdb.%s.tx_cond", DAP_CHAIN_NET_SRV_VPN_CDB_GDB_PREFIX);
        log_it(L_DEBUG, "Checkout group %s", l_tx_cond_gdb_group);
        // get key for tx_cond
        char *l_user_key;
        {
            dap_chain_hash_fast_t l_hash = { 0 };
            char *l_key_hash_str = NULL;
            if(dap_hash_fast(a_pkey_b64, dap_strlen(a_pkey_b64), &l_hash))
                l_key_hash_str = dap_chain_hash_fast_to_str_new(&l_hash);
            l_user_key = dap_strdup_printf("%s/%s", a_login, l_key_hash_str);
            DAP_DELETE(l_key_hash_str);
        }
        log_it(L_DEBUG, "\ndbg l_user_key=%s\n", l_user_key);
        dap_chain_hash_fast_t *l_tx_cond_hash = (dap_chain_hash_fast_t*) dap_chain_global_db_gr_get(l_user_key, &l_gdb_group_size, l_tx_cond_gdb_group);

        // Check for entry size
        if (l_gdb_group_size && l_gdb_group_size != sizeof(dap_chain_hash_fast_t)) {
            log_it(L_ERROR, "Wrong size of tx condition on database (%zd but expected %zd), may be old entry",
                   l_gdb_group_size, sizeof(dap_chain_hash_fast_t));
        }

        time_t l_tx_cond_ts = 0;
        // If loaded lets check is it spent or not
        if ( l_tx_cond_hash ){
            log_it(L_DEBUG, "2791: Search for unspent tx, net %s", l_tpl->net_name);
            dap_chain_datum_tx_t *l_tx = dap_chain_net_get_tx_by_hash(l_tpl->net, l_tx_cond_hash, TX_SEARCH_TYPE_NET_UNSPENT);
            if ( !l_tx ){ // If not found - all outs are used. Create new one
                // pass all chains
                l_tx = dap_chain_net_get_tx_by_hash(l_tpl->net, l_tx_cond_hash, TX_SEARCH_TYPE_NET);
                DAP_DELETE(l_tx_cond_hash);
                l_tx_cond_hash = NULL;
                if ( l_tx ){
                    l_tx_cond_ts =(time_t) l_tx->header.ts_created;
                    log_it(L_DEBUG, "2791: got some tx, created %d", l_tx->header.ts_created);
                }
            }
        }

        // Try to create condition
        if (! l_tx_cond_hash ) {
            dap_chain_wallet_t *l_wallet_from = l_tpl->wallet;
            log_it(L_DEBUG, "Create tx from wallet %s", l_wallet_from->name);
            dap_enc_key_t *l_key_from = dap_chain_wallet_get_key(l_wallet_from, 0);


            //dap_chain_cell_id_t *xccell = dap_chain_net_get_cur_cell(l_tpl->net);
            //uint64_t uint64 =dap_chain_net_get_cur_cell(l_tpl->net)->uint64;


            // where to take coins for service
            dap_chain_addr_t *l_addr_from = dap_chain_wallet_get_addr(l_wallet_from, l_tpl->net->pub.id);
            dap_chain_net_srv_price_unit_uid_t l_price_unit = { .enm = SERV_UNIT_SEC };
            dap_chain_net_srv_uid_t l_srv_uid = { .uint64 = DAP_CHAIN_NET_SRV_VPN_ID };
            l_tx_cond_hash = dap_chain_proc_tx_create_cond(l_tpl->net, l_key_from, l_client_key, l_addr_from, l_tpl->token_ticker,
                                                       (uint64_t) l_tpl->value_datoshi, 0, l_price_unit, l_srv_uid, 0, l_pkey_raw, l_pkey_raw_size);
            char *l_addr_from_str = dap_chain_addr_to_str( l_addr_from );
            DAP_DELETE( l_addr_from);
            if (!l_tx_cond_hash) {
                log_it(L_ERROR, "Can't create condition for user");
            } else {
                // save transaction for login
                dap_chain_global_db_gr_set(l_user_key, l_tx_cond_hash, sizeof(dap_chain_hash_fast_t), l_tx_cond_gdb_group);
                log_it(L_NOTICE, "User \"%s\": created conditioned transaction from %s(%s) on "
                                , a_login, l_tpl->wallet_name, l_addr_from_str);
            }
            DAP_DELETE( l_addr_from_str );
        }
        DAP_DELETE(l_user_key);
        // dbg
        //dap_ledger_t * l_ledger = dap_chain_ledger_by_net_name( l_tpl->net->pub.name);
        //dap_chain_datum_tx_t *l_tx = dap_chain_ledger_tx_find_by_hash( l_ledger, l_tx_cond_hash);

        // If we loaded or created hash
        if( l_tx_cond_hash ){
            char * l_tx_cond_hash_str = dap_chain_hash_fast_to_str_new(l_tx_cond_hash);
            enc_http_reply_f(a_delegate,"\t<tx_cond_tpl>\n");
            //enc_http_reply_f(a_delegate,"\t\t<net>%s</net>\n",l_tpl->net_name);
            enc_http_reply_f(a_delegate,"\t\t<net>0x%x</net>\n",l_tpl->net->pub.id.uint64);
            enc_http_reply_f(a_delegate,"\t\t<token>%s</token>\n",l_tpl->token_ticker);
            enc_http_reply_f(a_delegate,"\t\t<tx_cond>%s</tx_cond>\n",l_tx_cond_hash_str);
            enc_http_reply_f(a_delegate,"\t</tx_cond_tpl>\n");
            DAP_DELETE(l_tx_cond_hash);
            DAP_DELETE(l_tx_cond_hash_str);
        }

        DAP_DELETE(l_tx_cond_gdb_group);
    }
    if (l_client_key)
        dap_enc_key_delete(l_client_key);
#endif
}
