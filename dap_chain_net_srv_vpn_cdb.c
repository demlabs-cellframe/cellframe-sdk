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

#include "dap_common.h"
#include "dap_config.h"
#include "dap_chain.h"
#include "dap_enc_http.h"
#include "dap_http.h"

#include "db_core.h"
#include "db_auth.h"
#include "db_http.h"
#include "db_http_file.h"

#include "dap_chain_net_srv_vpn_cdb.h"
#include "dap_chain_net_srv_vpn_cdb_server_list.h"


#define LOG_TAG "dap_chain_net_srv_vpn_cdb"

#define DB_URL "/db"
#define DB_FILE_URL "/db_file"
#define SLIST_URL "/nodelist"

static void s_auth_callback(enc_http_delegate_t* a_delegate, void * a_arg);

/**
 * @brief dap_chain_net_srv_vpn_cdb_init
 * @return
 */
int dap_chain_net_srv_vpn_cdb_init(dap_http_t * a_http)
{
    int rc;
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
    if( dap_config_get_item_bool_default( g_config,"cdb_auth","enabled",false) ){
        db_auth_init( dap_config_get_item_str_default(g_config,"cdb_auth","collection_name","cdb") );
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

    // Produce transaction for authorized users
    if (dap_config_get_item_bool_default( g_config,
                                                        "cdb",
                                                        "tx_cond_create",
                                                        false)) {
        db_auth_set_callbacks( s_auth_callback );
    }
    return 0;
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
    log_it( L_DEBUG, "Authorized, now need to create conditioned transaction if not present");
}
