/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
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

#include <stddef.h>
#include <string.h>
#include <pthread.h>

#include "uthash.h"
#include "utlist.h"

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_config.h"
#include "dap_chain_utxo.h"
#include "dap_chain_net.h"
#include "dap_chain_node_client.h"
#include "dap_module.h"

#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>

#define LOG_TAG "chain_net"

typedef  enum dap_chain_net_state{
    NET_STATE_BEGIN = 0,
    NET_STATE_LINKS_CONNECTING,
    NET_STATE_LINKS_ESTABLISHED,
} dap_chain_net_state_t;

/**
  * @struct dap_chain_net_pvt
  * @details Private part of chain_net dap object
  */
typedef struct dap_chain_net_pvt{
    pthread_t proc_tid;
    pthread_cond_t proc_cond;
    dap_chain_node_role_t node_role;
    uint8_t padding[4];

    dap_chain_node_client_t * clients_by_node_addr;
    dap_chain_net_state_t state;
} dap_chain_net_pvt_t;

typedef struct dap_chain_net_item{
    char name [DAP_CHAIN_NET_NAME_MAX];
    dap_chain_net_id_t net_id;
    dap_chain_net_t * chain_net;
    UT_hash_handle hh;
} dap_chain_net_item_t;

#define PVT(a) ( (dap_chain_net_pvt_t *) (void*) a->pvt )
#define PVT_S(a) ( (dap_chain_net_pvt_t *) (void*) a.pvt )

static dap_chain_net_item_t * s_net_items = NULL;
static dap_chain_net_item_t * s_net_items_ids = NULL;

static size_t            s_net_configs_count = 0;
static pthread_cond_t    s_net_proc_loop_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t    s_net_proc_loop_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief s_net_proc_thread
 * @details Brings up and check the Dap Chain Network
 * @param a_cfg Network1 configuration
 * @return
 */
static void * s_net_proc_thread ( void * a_net)
{
    dap_chain_net_t * l_net = (dap_chain_net_t *) a_net;
    bool is_looping = true ;
    while( is_looping ) {
        pthread_mutex_lock(&s_net_proc_loop_mutex);
        pthread_cond_wait(&s_net_proc_loop_cond,&s_net_proc_loop_mutex);
        pthread_mutex_unlock(&s_net_proc_loop_mutex);
        log_it( L_DEBUG, "Waked up net proc thread");
    }
    return NULL;
}

/**
 * @brief net_proc_start
 * @param a_cfg
 */
static void s_net_proc_start( dap_chain_net_t * a_net )
{
    if ( pthread_create(& PVT(a_net)->proc_tid ,NULL, s_net_proc_thread, a_net) == 0 ){
        log_it (L_NOTICE,"Network processing thread started");
    }
}

/**
 * @brief s_net_proc_kill
 * @param a_net
 */
static void s_net_proc_kill( dap_chain_net_t * a_net )
{
    if ( PVT(a_net)->proc_tid ) {
        pthread_cond_signal(& PVT(a_net)->proc_cond);
        log_it(L_NOTICE,"Sent KILL signal to the net process thread %d, waiting for shutdown...",PVT(a_net)->proc_tid);
        pthread_join( PVT(a_net)->proc_tid , NULL);
        log_it(L_NOTICE,"Net process thread %d shutted down",PVT(a_net)->proc_tid);
        PVT(a_net)->proc_tid = 0;
    }
}

/**
 * @brief dap_chain_net_new
 * @param a_id
 * @param a_name
 * @param a_node_role
 * @param a_node_name
 * @return
 */
dap_chain_net_t * dap_chain_net_new(const char * a_id, const char * a_name ,
                                    const char * a_node_role)
{
    dap_chain_net_t * ret = DAP_NEW_Z_SIZE (dap_chain_net_t, sizeof (ret->pub)+ sizeof (dap_chain_net_pvt_t) );
    ret->pub.name = strdup( a_name );
    if ( sscanf(a_id,"0x%016lx", &ret->pub.id.uint64 ) == 1 ){
        if (strcmp (a_node_role, "root")==0){
            PVT(ret)->node_role.enums = ROOT;
            log_it (L_NOTICE, "Node role \"root\" selected");
        }
    } else {
        log_it (L_ERROR, "Wrong id format (\"%s\"). Must be like \"0x0123456789ABCDE\"" , a_id );
    }
    return ret;

}

/**
 * @brief dap_chain_net_delete
 * @param a_net
 */
void dap_chain_net_delete( dap_chain_net_t * a_net )
{
    DAP_DELETE( PVT(a_net) );
}


/**
 * @brief dap_chain_net_init
 * @return
 */
int dap_chain_net_init()
{
    static dap_config_t *l_cfg=NULL;
    if((l_cfg = dap_config_open( "network/default" ) ) == NULL) {
        log_it(L_ERROR,"Can't open default network config");
        return -1;
    }else{
        dap_chain_net_t * l_net = dap_chain_net_new(
                                            dap_config_get_item_str(l_cfg , "general" , "id" ),
                                            dap_config_get_item_str(l_cfg , "general" , "name" ),
                                            dap_config_get_item_str(l_cfg , "general" , "node-role" )
                                           );
        l_net->pub.gdb_groups_prefix = dap_strdup (
                    dap_config_get_item_str_default(l_cfg , "general" , "gdb_groups_prefix","" ) );


        // UTXO model
        uint16_t l_utxo_flags = 0;
        switch ( PVT( l_net )->node_role.enums ) {
            case ROOT_MASTER:
            case ROOT:
            case ARCHIVE:
                l_utxo_flags |= DAP_CHAIN_UTXO_CHECK_TOKEN_EMISSION;
            case MASTER:
                l_utxo_flags |= DAP_CHAIN_UTXO_CHECK_CELLS_DS;
            case CELL_MASTER:
                l_utxo_flags |= DAP_CHAIN_UTXO_CHECK_TOKEN_EMISSION;
            case FULL:
            case LIGHT:
                l_utxo_flags |= DAP_CHAIN_UTXO_CHECK_LOCAL_DS;
        }
        dap_chain_utxo_init(l_utxo_flags);



        // Init chains
        size_t l_chains_path_size =strlen(dap_config_path())+1+strlen(l_net->pub.name)+1+strlen("network")+1;
        char * l_chains_path = DAP_NEW_Z_SIZE (char,l_chains_path_size);
        snprintf(l_chains_path,l_chains_path_size,"%s/network/%s",dap_config_path(),l_net->pub.name);
        DIR * l_chains_dir = opendir(l_chains_path);
        DAP_DELETE (l_chains_path);
        if ( l_chains_dir ){
            struct dirent * l_dir_entry;
            while ( (l_dir_entry = readdir(l_chains_dir) )!= NULL ){
                char * l_entry_name = strdup(l_dir_entry->d_name);
                l_chains_path_size = strlen(l_net->pub.name)+1+strlen("network")+1+strlen (l_entry_name)-3;
                l_chains_path = DAP_NEW_Z_SIZE(char, l_chains_path_size);

                if (strlen (l_entry_name) > 4 ){ // It has non zero name excluding file extension
                    if ( strncmp (l_entry_name+ strlen(l_entry_name)-4,".cfg",4) == 0 ) { // its .cfg file
                        l_entry_name [strlen(l_entry_name)-4] = 0;
                        log_it(L_DEBUG,"Open chain config \"%s\"...",l_entry_name);
                        snprintf(l_chains_path,l_chains_path_size,"network/%s/%s",l_net->pub.name,l_entry_name);
                        //dap_config_open(l_chains_path);

                        // Create chain object
                        dap_chain_t * l_chain = dap_chain_load_from_cfg(l_net->pub.name, l_net->pub.id, l_chains_path);
                        if(l_chain)
                            DL_APPEND( l_net->pub.chains, l_chain);
                        free(l_entry_name);
                    }
                }
                DAP_DELETE (l_chains_path);
            }
        } else {
            log_it(L_ERROR,"Can't any chains for network %s",l_net->pub.name);
            return -2;
        }

        // Do specific role actions post-chain created
        switch ( PVT( l_net )->node_role.enums ) {
            case ROOT_MASTER:{
                // Set to process everything in datum pool
                dap_chain_t * l_chain = NULL;
                DL_FOREACH(l_net->pub.chains, l_chain ) l_chain->is_datum_pool_proc = true;
                log_it(L_INFO,"Root master node role established");
            } break;
            case ROOT:{
                // Set to process only zerochain
                dap_chain_id_t l_chain_id = {{0}};
                dap_chain_t * l_chain = dap_chain_find_by_id(l_net->pub.id,l_chain_id);
                l_chain->is_datum_pool_proc = true;
                log_it(L_INFO,"Root node role established");
            } break;
            case CELL_MASTER:
            case MASTER:{
                // Set to process only plasma chain (id 0x0000000000000001 )
                dap_chain_id_t l_chain_id = { .raw = {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x01} };
                dap_chain_t * l_chain = dap_chain_find_by_id(l_net->pub.id, l_chain_id );
                l_chain->is_datum_pool_proc = true;

                log_it(L_INFO,"Master node role established");
            } break;
            case FULL:{
                log_it(L_INFO,"Full node role established");
            } break;
            case LIGHT:
            default:
                log_it(L_INFO,"Light node role established");

        }

        // Add network to the list
        dap_chain_net_item_t * l_net_item = DAP_NEW_Z( dap_chain_net_item_t);
        snprintf(l_net_item->name,sizeof (l_net_item->name),"%s"
                     ,dap_config_get_item_str(l_cfg , "general" , "name" ));
        l_net_item->chain_net = l_net;
        l_net_item->net_id.uint64 = l_net->pub.id.uint64;
        HASH_ADD_STR(s_net_items,name,l_net_item);
        HASH_ADD(hh,s_net_items_ids,net_id,sizeof ( l_net_item->net_id),l_net_item);

        // Start the proc thread
        s_net_proc_start(l_net);
        log_it(L_NOTICE, "Сhain network initialized");
        return 0;
    }
}

/**
 * @brief dap_chain_net_deinit
 */
void dap_chain_net_deinit()
{
}

/**
 * @brief dap_chain_net_load
 * @param a_name
 * @return
 */
dap_chain_net_t * dap_chain_net_load (const char * a_name)
{

}

/**
 * @brief dap_chain_net_by_name
 * @param a_name
 * @return
 */
dap_chain_net_t * dap_chain_net_by_name( const char * a_name)
{
    dap_chain_net_item_t * l_net_item = NULL;
    HASH_FIND_STR(s_net_items,a_name,l_net_item );
    if ( l_net_item )
        return l_net_item->chain_net;
    else
        return NULL;
}

/**
 * @brief dap_chain_net_by_id
 * @param a_id
 * @return
 */
dap_chain_net_t * dap_chain_net_by_id( dap_chain_net_id_t a_id)
{
    dap_chain_net_item_t * l_net_item = NULL;
    HASH_FIND(hh,s_net_items,&a_id,sizeof (a_id), l_net_item );
    if ( l_net_item )
        return l_net_item->chain_net;
    else
        return NULL;

}


/**
 * @brief dap_chain_net_id_by_name
 * @param a_name
 * @return
 */
dap_chain_net_id_t dap_chain_net_id_by_name( const char * a_name)
{
    dap_chain_net_t *l_net = dap_chain_net_by_name( a_name );
    dap_chain_net_id_t l_ret = {0};
    if (l_net)
        l_ret.uint64 = l_net->pub.id.uint64;
    return l_ret;
}

/**
 * @brief dap_chain_net_get_chain_by_name
 * @param l_net
 * @param a_name
 * @return
 */
dap_chain_t * dap_chain_net_get_chain_by_name( dap_chain_net_t * l_net, const char * a_name)
{
   dap_chain_t * l_chain;
   DL_FOREACH(l_net->pub.chains, l_chain){
        if(strcmp(l_chain->name,a_name) == 0)
            return  l_chain;
   }
   return NULL;
}


void dap_chain_net_proc_datapool (dap_chain_net_t * a_net)
{

}
