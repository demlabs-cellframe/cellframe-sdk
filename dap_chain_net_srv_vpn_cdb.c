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

#include "db_core.h"
#include "db_auth.h"
#include "db_http.h"
#include "db_http_file.h"

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

#include "dap_chain_mempool.h"
#include "dap_pkey.h"

#include "dap_chain_net_srv_vpn.h"
#include "dap_chain_net_srv_vpn_cdb.h"
#include "dap_chain_net_srv_vpn_cdb_server_list.h"


#define LOG_TAG "dap_chain_net_srv_vpn_cdb"

#define DB_URL "/db"
#define DB_FILE_URL "/db_file"
#define SLIST_URL "/nodelist"

typedef struct tx_cond_template{
    char * wallet_name;
    dap_chain_wallet_t * wallet;

    long double value_coins;
    uint128_t value_datoshi;

    char * token_ticker;
    char * net_name;
    dap_chain_net_t * net;
    dap_ledger_t * ledger;
    time_t min_time; // Minimum time between transactions

    struct tx_cond_template * prev;
    struct tx_cond_template * next;
} tx_cond_template_t;

static tx_cond_template_t * s_tx_cond_templates = NULL;
const char *c_wallets_path = NULL;

static void s_auth_callback(enc_http_delegate_t* a_delegate, void * a_arg);

/**
 * @brief dap_chain_net_srv_vpn_cdb_init
 * @return
 */
int dap_chain_net_srv_vpn_cdb_init(dap_http_t * a_http)
{
    int rc;
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


    if((rc=db_core_init(dap_config_get_item_str_default(g_config,
                                                        "cdb",
                                                        "db_path",
                                                        "mongodb://localhost/db")))!=0 ){
        log_it(L_CRITICAL,"Can't init CDB module, return code %d",rc);
        return -3;
    }
    db_http_add_proc( a_http , DB_URL );
    db_http_file_proc_add( a_http , DB_FILE_URL );

    // Load all chain networks
    if (dap_config_get_item_bool_default( g_config,
                                                        "cdb",
                                                        "servers_list_enabled",
                                                        false)) {
        dap_chain_net_srv_vpn_cdb_server_list_add_proc ( a_http, SLIST_URL);
    }
    if( dap_config_get_item_bool_default( g_config,"cdb_auth","enabled",false) ){
        db_auth_init( dap_config_get_item_str_default(g_config,"cdb_auth","collection_name","cdb") );
        // Produce transaction for authorized users
        if (dap_config_get_item_bool_default( g_config,
                                                            "cdb_auth",
                                                            "tx_cond_create",
                                                            false)) {

            // Parse tx cond templates
            size_t l_tx_cond_tpls_count=0;
            char ** l_tx_cond_tpls =dap_config_get_array_str( g_config,"cdb_auth", "tx_cond_templates",&l_tx_cond_tpls_count);
            for ( size_t i = 0 ; i< l_tx_cond_tpls_count; i++){
                char * l_wallet_name = NULL;
                long double l_value = 0.0L;
                char * l_token_ticker = NULL;
                char * l_net_name = NULL;
                int l_step = 0;
                time_t l_min_time = 0;
                char * l_tpl_parse_old = l_tx_cond_tpls[i];
                // Parse template entries
                for(char * l_tpl_parse = index(l_tx_cond_tpls[i],':'); l_tpl_parse ;l_tpl_parse = index(l_tpl_parse,':') ){
                    size_t l_tpl_entry_size = l_tpl_parse - l_tpl_parse_old;
                    if (l_tpl_entry_size){ // if not empty entry
                        char *l_tpl_entry = DAP_NEW_Z_SIZE(char,l_tpl_entry_size);
                        strncpy(l_tpl_entry,l_tpl_parse_old,l_tpl_entry_size-1);
                        switch ( l_step) { // Parse entries by order
                            case 0: l_wallet_name = l_tpl_entry; break;
                            case 1: l_value = strtold( l_tpl_entry, NULL); DAP_DELETE( l_tpl_entry); break;
                            case 2: l_min_time =(time_t) atoll(l_tpl_entry); DAP_DELETE( l_tpl_entry); break;
                            case 3: l_token_ticker = l_tpl_entry; break;
                            case 4: l_net_name = l_tpl_entry; break;
                            default: log_it( L_WARNING, "Too many ':' (%d) characters in condition template", l_step);
                        }
                        l_step++;
                        if( l_step > 4)
                            break;
                    }
                    l_tpl_parse_old = l_tpl_parse;
                }
                // If all what we need is present
                if ( l_step >4 ) {
                    if ( l_wallet_name && l_value > 0.0L && l_token_ticker && l_net_name && l_min_time){
                        // we create condition template
                        tx_cond_template_t * l_tx_cond_template = DAP_NEW_Z(tx_cond_template_t);

                        l_tx_cond_template->wallet = dap_chain_wallet_open( l_wallet_name,c_wallets_path );
                        if( l_tx_cond_template->wallet){
                            l_tx_cond_template->wallet_name = l_wallet_name;

                            l_tx_cond_template->net = dap_chain_net_by_name( l_net_name );
                            if ( l_tx_cond_template->net){
                                l_tx_cond_template->net_name = l_net_name;
                                l_tx_cond_template->ledger = dap_chain_ledger_by_net_name( l_net_name );
                                if ( l_tx_cond_template->ledger ){
                                    l_tx_cond_template->min_time = l_min_time;
                                    l_tx_cond_template->value_coins = l_value;
                                    l_tx_cond_template->value_datoshi = dap_chain_coins_to_balance ( l_value );
                                    l_tx_cond_template->token_ticker = l_token_ticker;
                                    // and put it in list
                                    l_tx_cond_template->prev = s_tx_cond_templates;
                                    if ( s_tx_cond_templates)
                                        s_tx_cond_templates->next = l_tx_cond_template;
                                    s_tx_cond_templates = l_tx_cond_template;
                                }else{
                                    log_it(L_ERROR, "Can't open ledger in network \"%s\" for condition transaction template \"%s\"", l_net_name, l_tx_cond_tpls[i]);
                                    DAP_DELETE( l_wallet_name );
                                    DAP_DELETE( l_net_name);
                                    DAP_DELETE( l_token_ticker);
                                    DAP_DELETE( l_tx_cond_template);
                                    l_tx_cond_template = NULL;
                                    ret = -4;
                                }
                            }else{
                                log_it(L_ERROR, "Can't open network \"%s\" for condition transaction template \"%s\"", l_net_name, l_tx_cond_tpls[i]);
                                DAP_DELETE( l_wallet_name );
                                DAP_DELETE( l_net_name);
                                DAP_DELETE( l_token_ticker);
                                DAP_DELETE( l_tx_cond_template);
                                l_tx_cond_template = NULL;
                                ret = -2;
                            }
                        }else{
                            log_it(L_ERROR, "Can't open wallet \"%s\" for condition transaction template \"%s\"", l_wallet_name, l_tx_cond_tpls[i]);
                            DAP_DELETE( l_wallet_name );
                            DAP_DELETE( l_net_name);
                            DAP_DELETE( l_token_ticker);
                            DAP_DELETE( l_tx_cond_template);
                            l_tx_cond_template = NULL;
                            ret = -3;
                        }
                    }
                }
            }
            if ( l_tx_cond_tpls_count )
                db_auth_set_callbacks( s_auth_callback );
            else{
                log_it( L_ERROR, "No condition tpl, can't setup auth callback");
                ret=-1;
            }
        }
    }

    return ret;
}

/**
 * @brief dap_chain_net_srv_vpn_cdb_deinit
 */
void dap_chain_net_srv_vpn_cdb_deinit()
{

}



/**
 * @brief s_auth_callback
 * @param a_delegate
 * @param a_arg
 */
static void s_auth_callback(enc_http_delegate_t* a_delegate, void * a_arg)
{
    db_auth_info_t *l_auth_info = (db_auth_info_t *) a_arg;
    log_it( L_DEBUG, "Authorized, now need to create conditioned transaction if not present");

    size_t l_pkey_b64_length = strlen(l_auth_info->pkey);
    byte_t * l_pkey_raw = DAP_NEW_Z_SIZE(byte_t,l_pkey_b64_length );
    size_t l_pkey_raw_size = dap_enc_base64_decode(l_auth_info->pkey,l_pkey_b64_length,l_pkey_raw, DAP_ENC_DATA_TYPE_B64_URLSAFE );
    char * l_pkey_gdb_group = dap_strdup_printf("%s.pkey", DAP_CHAIN_NET_SRV_VPN_CDB_GDB_PREFIX );
    dap_chain_global_db_gr_set( l_auth_info->user , l_pkey_raw, l_pkey_raw_size,l_pkey_gdb_group);

    dap_enc_key_t *l_client_key = dap_enc_key_deserealize(l_pkey_raw, l_pkey_raw_size);

    for ( tx_cond_template_t * l_tpl = s_tx_cond_templates; l_tpl; l_tpl=l_tpl->next) {

        size_t l_gdb_group_size=0;

        // Try to load from gdb
        char * l_tx_cond_gdb_group = dap_strdup_printf("%s.%s.tx_cond", l_tpl->net->pub.name, DAP_CHAIN_NET_SRV_VPN_CDB_GDB_PREFIX );
        dap_chain_hash_fast_t  * l_tx_cond_hash =  (dap_hash_type_t*) dap_chain_global_db_gr_get(
                    l_auth_info->user,&l_gdb_group_size,  l_tx_cond_gdb_group );

        // Check for entry size
        if (l_gdb_group_size && l_gdb_group_size != sizeof (dap_chain_hash_fast_t) ){
                log_it(L_ERROR, "Wrong size of tx condition on database (%zd but expected %zd), may be old entry",
                                 l_gdb_group_size, sizeof (dap_chain_hash_fast_t));
        }

        time_t l_tx_cond_ts = 0;
        // If loaded lets check is it spent or not
        if ( l_tx_cond_hash ){
            dap_chain_datum_tx_t * l_tx = dap_chain_net_get_tx_by_hash( l_tpl->net, l_tx_cond_hash, TX_SEARCH_TYPE_NET_UNSPENT );
            if ( ! l_tx ){ // If not found - all outs are used. Create new one
                // pass all chains
                l_tx = dap_chain_net_get_tx_by_hash( l_tpl->net, l_tx_cond_hash, TX_SEARCH_TYPE_NET );
                DAP_DELETE(l_tx_cond_hash);
                l_tx_cond_hash = NULL;
                if ( l_tx ){
                    l_tx_cond_ts =(time_t) l_tx->header.ts_created;
                }
            }

        }
        // Try to create condition
        if (! l_tx_cond_hash ) {
            // test
            dap_chain_wallet_t *l_wallet_from = l_tpl->wallet;
            dap_enc_key_t *l_key_from = dap_chain_wallet_get_key(l_wallet_from, 0);

            // where to take coins for service
            dap_chain_addr_t *l_addr_from = dap_chain_wallet_get_addr(l_wallet_from, l_tpl->net->pub.id );
            dap_chain_net_srv_price_unit_uid_t l_price_unit = { .enm = SERV_UNIT_SEC };
            dap_chain_net_srv_uid_t l_srv_uid = { .uint64 = DAP_CHAIN_NET_SRV_VPN_ID };
            l_tx_cond_hash= dap_chain_mempool_tx_create_cond( l_tpl->net, l_key_from,l_client_key, l_addr_from,l_tpl->token_ticker,
                                                       (uint64_t) l_tpl->value_datoshi , 0,l_price_unit,l_srv_uid, 0,NULL, 0);
            char * l_addr_from_str =dap_chain_addr_to_str( l_addr_from );
            DAP_DELETE( l_addr_from);
            if ( l_tx_cond_hash == NULL ){
                log_it( L_ERROR, "Can't create condiftion for user");
            }else
                log_it( L_NOTICE, "User \"%s\": created conditioned transaction from %s(%s) on "
                                , l_auth_info->user, l_tpl->wallet_name, l_addr_from_str
                                       );
            DAP_DELETE( l_addr_from_str );

        }

        // If we loaded or created hash
        if( l_tx_cond_hash ){
            char * l_tx_cond_hash_str = dap_chain_hash_fast_to_str_new(l_tx_cond_hash);
            enc_http_reply_f(a_delegate,"\t<tx_cond_tpl>\n");
            enc_http_reply_f(a_delegate,"\t\t<net>%s</net>\n",l_tpl->net_name);
            enc_http_reply_f(a_delegate,"\t\t<token>%s</token>\n",l_tpl->token_ticker);
            enc_http_reply_f(a_delegate,"\t\t<tx_cond>%s</tx_cond>\n",l_tx_cond_hash_str);
            DAP_DELETE(l_tx_cond_hash);
            DAP_DELETE(l_tx_cond_hash_str);
        }
        enc_http_reply_f(a_delegate,"\t</tx_cond_tpl>\n");
    }

    if (l_client_key)
        DAP_DELETE( l_client_key);
}
