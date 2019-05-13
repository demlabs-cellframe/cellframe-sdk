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
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_config.h"
#include "dap_chain_utxo.h"
#include "dap_chain_net.h"
#include "dap_chain_node_client.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd.h"

#include "dap_module.h"

#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>

#define LOG_TAG "chain_net"

/**
  * @struct dap_chain_net_pvt
  * @details Private part of chain_net dap object
  */
typedef struct dap_chain_net_pvt{
    pthread_t proc_tid;
    pthread_cond_t state_proc_cond;
    pthread_mutex_t state_mutex;
    dap_chain_node_role_t node_role;
    uint8_t padding[4];

    dap_chain_node_client_t * links_by_node_addr;
    dap_chain_node_client_t * clients_by_ipv4;
    dap_chain_node_client_t * clients_by_ipv6;
    size_t clients_count;

    char ** seed_aliases;
    uint16_t seed_aliases_count;
    uint8_t padding2[6];

    dap_chain_net_state_t state;
    dap_chain_net_state_t state_target;
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


static const char * c_net_states[]={
    [NET_STATE_OFFLINE] = "NET_STATE_OFFLINE",
    [NET_STATE_LINKS_CONNECTING] = "NET_STATE_LINKS_CONNECTING",
    [NET_STATE_LINKS_ESTABLISHED]= "NET_STATE_LINKS_ESTABLISHED",
    [NET_STATE_SYNC_GDB]= "NET_STATE_SYNC_GDB",
    [NET_STATE_SYNC_CHAINS]= "NET_STATE_SYNC_CHAINS",
    [NET_STATE_SYNC_ALL]= "NET_STATE_STAND_BY"
};

static dap_chain_net_t * s_net_new(const char * a_id, const char * a_name , const char * a_node_role);
inline static const char * s_net_state_to_str(dap_chain_net_state_t l_state);
static int s_net_states_proc(dap_chain_net_t * l_net);
static void * s_net_proc_thread ( void * a_net);
static void s_net_proc_thread_start( dap_chain_net_t * a_net );
static void s_net_proc_kill( dap_chain_net_t * a_net );

static int s_cli_net(int argc, const char ** argv, char **str_reply);

static bool s_seed_mode = false;
/**
 * @brief s_net_state_to_str
 * @param l_state
 * @return
 */
inline static const char * s_net_state_to_str(dap_chain_net_state_t l_state)
{
    return c_net_states[l_state];
}

/**
 * @brief dap_chain_net_state_go_to
 * @param a_net
 * @param a_new_state
 */
int dap_chain_net_state_go_to(dap_chain_net_t * a_net, dap_chain_net_state_t a_new_state)
{
    pthread_mutex_lock( &PVT(a_net)->state_mutex);
    if (PVT(a_net)->state_target == a_new_state){
        log_it(L_WARNING,"Already going to state %s",s_net_state_to_str(a_new_state));
    }
    PVT(a_net)->state_target = a_new_state;
    pthread_mutex_unlock( &PVT(a_net)->state_mutex);
    pthread_cond_signal(&PVT(a_net)->state_proc_cond);
    return 0;
}


/**
 * @brief s_net_states_proc
 * @param l_net
 */
static int s_net_states_proc(dap_chain_net_t * l_net)
{
    int ret=0;
    switch ( PVT(l_net)->state ){
        case NET_STATE_OFFLINE:{
            if ( PVT(l_net)->state_target != NET_STATE_OFFLINE ){
                // Check if there are root nodes in list
                switch ( PVT(l_net)->node_role.enums){
                    case NODE_ROLE_ROOT_MASTER:
                    case NODE_ROLE_ROOT:{
                    }break;
                    case NODE_ROLE_ARCHIVE:
                    case NODE_ROLE_CELL_MASTER:
                    case NODE_ROLE_MASTER:
                    case NODE_ROLE_FULL:
                    case NODE_ROLE_LIGHT:
                    default:{};
                };
            }
        }break;
        case NET_STATE_LINKS_PINGING:{
            switch ( PVT(l_net)->node_role.enums){
                case NODE_ROLE_ROOT_MASTER:
                case NODE_ROLE_ROOT:{
                }break;
                case NODE_ROLE_ARCHIVE:
                case NODE_ROLE_CELL_MASTER:
                case NODE_ROLE_MASTER:
                case NODE_ROLE_FULL:
                case NODE_ROLE_LIGHT:
                default:{}
            };

        }break;
        case NET_STATE_LINKS_CONNECTING:{

            log_it(L_DEBUG,"Connected %u/% links", PVT(l_net)->clients_count );
            ret = 1;
        }break;
        case NET_STATE_LINKS_ESTABLISHED:{

        }break;
        case NET_STATE_SYNC_GDB:{

        }break;
        case NET_STATE_SYNC_CHAINS:{

        }break;
        case NET_STATE_SYNC_ALL:{

        } break;
    }
    return ret;
}

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
        s_net_states_proc(l_net);
        pthread_mutex_lock( &PVT(l_net)->state_mutex );
        pthread_cond_wait(&PVT(l_net)->state_proc_cond,&PVT(l_net)->state_mutex);
        pthread_mutex_unlock( &PVT(l_net)->state_mutex );
        log_it( L_DEBUG, "Waked up net proc thread");

    }
    return NULL;
}

/**
 * @brief net_proc_start
 * @param a_cfg
 */
static void s_net_proc_thread_start( dap_chain_net_t * a_net )
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
        pthread_cond_signal(& PVT(a_net)->state_proc_cond);
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
static dap_chain_net_t * s_net_new(const char * a_id, const char * a_name ,
                                    const char * a_node_role)
{
    dap_chain_net_t * ret = DAP_NEW_Z_SIZE (dap_chain_net_t, sizeof (ret->pub)+ sizeof (dap_chain_net_pvt_t) );
    ret->pub.name = strdup( a_name );
    pthread_mutex_init( &PVT(ret)->state_mutex, NULL);
    pthread_cond_init( &PVT(ret)->state_proc_cond, NULL);
    if ( sscanf(a_id,"0x%016lx", &ret->pub.id.uint64 ) == 1 ){
        if (strcmp (a_node_role, "root_master")==0){
            PVT(ret)->node_role.enums = NODE_ROLE_ROOT_MASTER;
            log_it (L_NOTICE, "Node role \"root master\" selected");
        } else if (strcmp( a_node_role,"root") == 0){
            PVT(ret)->node_role.enums = NODE_ROLE_ROOT;
            log_it (L_NOTICE, "Node role \"root\" selected");

        } else if (strcmp( a_node_role,"archive") == 0){
            PVT(ret)->node_role.enums = NODE_ROLE_ARCHIVE;
            log_it (L_NOTICE, "Node role \"archive\" selected");

        } else if (strcmp( a_node_role,"cell_master") == 0){
            PVT(ret)->node_role.enums = NODE_ROLE_CELL_MASTER;
            log_it (L_NOTICE, "Node role \"cell master\" selected");

        }else if (strcmp( a_node_role,"master") == 0){
            PVT(ret)->node_role.enums = NODE_ROLE_MASTER;
            log_it (L_NOTICE, "Node role \"master\" selected");

        }else if (strcmp( a_node_role,"full") == 0){
            PVT(ret)->node_role.enums = NODE_ROLE_FULL;
            log_it (L_NOTICE, "Node role \"full\" selected");

        }else if (strcmp( a_node_role,"light") == 0){
            PVT(ret)->node_role.enums = NODE_ROLE_LIGHT;
            log_it (L_NOTICE, "Node role \"light\" selected");

        }else{
            log_it(L_ERROR,"Unknown node role \"%s\"",a_node_role);
            DAP_DELETE(ret);
            return  NULL;
        }
    } else {
        log_it (L_ERROR, "Wrong id format (\"%s\"). Must be like \"0x0123456789ABCDE\"" , a_id );
        DAP_DELETE(ret);
        return  NULL;
    }
    return ret;

}

/**
 * @brief dap_chain_net_delete
 * @param a_net
 */
void dap_chain_net_delete( dap_chain_net_t * a_net )
{
    if (PVT(a_net)->seed_aliases)
    DAP_DELETE( PVT(a_net) );
}


/**
 * @brief dap_chain_net_init
 * @return
 */
int dap_chain_net_init()
{
    dap_chain_node_cli_cmd_item_create ("net", s_cli_net, "Network commands",
        "net -net <chain net name> sync < all | gdb | chains >\n"
            "\tSyncronyze gdb, chains or everything\n\n"
        "net -net <chain net name> link < list | add | del | info | establish >\n"
            "\tList,add,del, dump or establish links\n\n"
                                        );
    s_seed_mode = dap_config_get_item_bool_default(g_config,"general","seed_mode",false);
    return  0;
}

/**
 * @brief s_cli_net
 * @param argc
 * @param argv
 * @param str_reply
 * @return
 */
static int s_cli_net(int argc, const char ** argv, char **a_str_reply)
{
    int arg_index=1;
    dap_chain_net_t * l_net;
    int ret = dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index,argc,argv,a_str_reply,NULL,&l_net);
    if ( l_net ){
        const char * l_sync_str = NULL;
        const char * l_links_str = NULL;
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "sync", &l_sync_str);
        dap_chain_node_cli_find_option_val(argv, arg_index, argc, "link", &l_links_str);

        if ( l_links_str ){
            if ( strcmp(l_links_str,"list") == 0 ) {

            } else if ( strcmp(l_links_str,"add") == 0 ) {

            } else if ( strcmp(l_links_str,"del") == 0 ) {

            }  else if ( strcmp(l_links_str,"info") == 0 ) {

            } else if ( strcmp (l_links_str,"disconnect_all") == 0 ){
                ret = 0;
                dap_chain_net_stop(l_net);
            }else {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "Subcommand \"link\" requires one of parameter: list\n");
                ret = -3;
            }

        } else if( l_sync_str) {
            if ( strcmp(l_sync_str,"all") == 0 ) {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "SYNC_ALL state requested to state machine. Current state: %s\n",
                                                  c_net_states[ PVT(l_net)->state] );
                dap_chain_net_sync_all(l_net);
            } else if ( strcmp(l_sync_str,"gdb") == 0) {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "SYNC_GDB state requested to state machine. Current state: %s\n",
                                                  c_net_states[ PVT(l_net)->state] );
                dap_chain_net_sync_gdb(l_net);

            }  else if ( strcmp(l_sync_str,"chains") == 0) {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "SYNC_CHAINS state requested to state machine. Current state: %s\n",
                                                  c_net_states[ PVT(l_net)->state] );
                dap_chain_net_sync_chains(l_net);

            } else {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "Subcommand \"sync\" requires one of parameter: all,gdb,chains\n");
                ret = -2;
            }
        } else {
            dap_chain_node_cli_set_reply_text(a_str_reply,"Command requires one of subcomand: sync, links\n");
            ret = -1;
        }

    }
    return  ret;
}


int dap_chain_net_load(const char * a_net_name)
{
    static dap_config_t *l_cfg=NULL;
    dap_string_t *l_cfg_path = dap_string_new("network/");
    dap_string_append(l_cfg_path,a_net_name);

    if( ( l_cfg = dap_config_open ( l_cfg_path->str ) ) == NULL ) {
        log_it(L_ERROR,"Can't open default network config");
        dap_string_free(l_cfg_path,true);
        return -1;
    } else {
        dap_string_free(l_cfg_path,true);
        dap_chain_net_t * l_net = s_net_new(
                                            dap_config_get_item_str(l_cfg , "general" , "id" ),
                                            dap_config_get_item_str(l_cfg , "general" , "name" ),
                                            dap_config_get_item_str(l_cfg , "general" , "node-role" )
                                           );
        l_net->pub.gdb_groups_prefix = dap_strdup (
                    dap_config_get_item_str_default(l_cfg , "general" , "gdb_groups_prefix","" ) );


        // UTXO model
        uint16_t l_utxo_flags = 0;
        switch ( PVT( l_net )->node_role.enums ) {
            case NODE_ROLE_ROOT_MASTER:
            case NODE_ROLE_ROOT:
            case NODE_ROLE_ARCHIVE:
                l_utxo_flags |= DAP_CHAIN_UTXO_CHECK_TOKEN_EMISSION;
            case NODE_ROLE_MASTER:
                l_utxo_flags |= DAP_CHAIN_UTXO_CHECK_CELLS_DS;
            case NODE_ROLE_CELL_MASTER:
                l_utxo_flags |= DAP_CHAIN_UTXO_CHECK_TOKEN_EMISSION;
            case NODE_ROLE_FULL:
            case NODE_ROLE_LIGHT:
                l_utxo_flags |= DAP_CHAIN_UTXO_CHECK_LOCAL_DS;
        }
        dap_chain_utxo_init(l_utxo_flags);

        // Check if seed nodes are present in local db alias
        PVT(l_net)->seed_aliases = dap_config_get_array_str( l_cfg , "general" ,"seed_nodes_aliases"
                                                             ,&PVT(l_net)->seed_aliases_count);

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
                        if(l_chain){
                            DL_APPEND( l_net->pub.chains, l_chain);
                            if(l_chain->callback_created)
                                l_chain->callback_created(l_chain,l_cfg);
                        }
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
            case NODE_ROLE_ROOT_MASTER:{
                // Set to process everything in datum pool
                dap_chain_t * l_chain = NULL;
                DL_FOREACH(l_net->pub.chains, l_chain ) l_chain->is_datum_pool_proc = true;
                log_it(L_INFO,"Root master node role established");
            } // Master root includes root
            case NODE_ROLE_ROOT:{
                // Set to process only zerochain
                dap_chain_id_t l_chain_id = {{0}};
                dap_chain_t * l_chain = dap_chain_find_by_id(l_net->pub.id,l_chain_id);
                if (l_chain )
                   l_chain->is_datum_pool_proc = true;

                PVT(l_net)->state_target = NET_STATE_SYNC_ALL;
                log_it(L_INFO,"Root node role established");
            } break;
            case NODE_ROLE_CELL_MASTER:
            case NODE_ROLE_MASTER:{
                // Set to process only plasma chain (id 0x0000000000000001 )
                dap_chain_id_t l_chain_id = { .raw = {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x01} };
                dap_chain_t * l_chain = dap_chain_find_by_id(l_net->pub.id, l_chain_id );
                l_chain->is_datum_pool_proc = true;
                PVT(l_net)->state_target = NET_STATE_SYNC_ALL;
                log_it(L_INFO,"Master node role established");
            } break;
            case NODE_ROLE_FULL:{
                log_it(L_INFO,"Full node role established");
                PVT(l_net)->state_target = NET_STATE_SYNC_ALL;
            } break;
            case NODE_ROLE_LIGHT:
            default:
                log_it(L_INFO,"Light node role established");

        }

        if (s_seed_mode) { // If we seed we do everything manual. First think - prefil list of node_addrs and its aliases
            PVT(l_net)->state_target = NET_STATE_OFFLINE;
        }
        // Add network to the list
        dap_chain_net_item_t * l_net_item = DAP_NEW_Z( dap_chain_net_item_t);
        dap_chain_net_item_t * l_net_item2 = DAP_NEW_Z( dap_chain_net_item_t);
        snprintf(l_net_item->name,sizeof (l_net_item->name),"%s"
                     ,dap_config_get_item_str(l_cfg , "general" , "name" ));
        l_net_item->chain_net = l_net;
        l_net_item->net_id.uint64 = l_net->pub.id.uint64;
        HASH_ADD_STR(s_net_items,name,l_net_item);

        memcpy( l_net_item2,l_net_item,sizeof (*l_net_item));
        HASH_ADD(hh,s_net_items_ids,net_id,sizeof ( l_net_item2->net_id),l_net_item2);

        // Start the proc thread
        s_net_proc_thread_start(l_net);
        log_it(L_NOTICE, "Сhain network \"%s\" initialized",l_net_item->name);
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
    HASH_FIND(hh,s_net_items_ids,&a_id,sizeof (a_id), l_net_item );
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
