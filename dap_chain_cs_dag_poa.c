/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
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
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <time.h>
#include <wepoll.h>
#include <pthread.h>
#endif

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_chain_net.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_global_db.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_event.h"
#include "dap_chain_cs_dag_poa.h"

#include "dap_chain_cert.h"

#define LOG_TAG "dap_chain_cs_dag_poa"

typedef struct dap_chain_cs_dag_poa_pvt
{
    dap_chain_cert_t * events_sign_cert;
    dap_chain_cert_t ** auth_certs;
    char * auth_certs_prefix;
    uint16_t auth_certs_count;
    uint16_t auth_certs_count_verify; // Number of signatures, needed for event verification
    uint8_t padding[4];
    dap_chain_callback_new_cfg_t prev_callback_created; // global network config init
} dap_chain_cs_dag_poa_pvt_t;

#define PVT(a) ((dap_chain_cs_dag_poa_pvt_t *) a->_pvt )

static void s_callback_delete(dap_chain_cs_dag_t * a_dag);
static int s_callback_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg);
static int s_callback_created(dap_chain_t * a_chain, dap_config_t *a_chain_cfg);
static int s_callback_event_verify(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_dag_event);
static dap_chain_cs_dag_event_t * s_callback_event_create(dap_chain_cs_dag_t * a_dag, dap_chain_datum_t * a_datum,
                                                          dap_chain_hash_fast_t * a_hashes, size_t a_hashes_count);
// CLI commands
static int s_cli_dag_poa(int argc, char ** argv, char **str_reply);

static bool s_seed_mode = false;
/**
 * @brief dap_chain_cs_dag_poa_init
 * @return
 */
int dap_chain_cs_dag_poa_init(void)
{
    // Add consensus constructor
    dap_chain_cs_add ("dag_poa", s_callback_new );
    s_seed_mode = dap_config_get_item_bool_default(g_config,"general","seed_mode",false);
    dap_chain_node_cli_cmd_item_create ("dag_poa", s_cli_dag_poa, "DAG PoA commands",
        "dag_poa -net <chain net name> -chain <chain name> event sign -event <event hash>\n"
            "\tSign event <event hash> in the new round pool with its authorize certificate\n\n");

    return 0;
}

/**
 * @brief dap_chain_cs_dag_poa_deinit
 */
void dap_chain_cs_dag_poa_deinit(void)
{

}



/**
 * @brief s_cli_dag_poa
 * @param argc
 * @param argv
 * @param str_reply
 * @return
 */
static int s_cli_dag_poa(int argc, char ** argv, char **a_str_reply)
{
    int ret = -666;
    int arg_index = 1;
    dap_chain_net_t * l_chain_net = NULL;
    dap_chain_t * l_chain = NULL;
    dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index,argc,argv,a_str_reply,&l_chain,&l_chain_net);

    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG(l_chain);
    dap_chain_cs_dag_poa_t * l_poa = DAP_CHAIN_CS_DAG_POA( l_dag ) ;
    dap_chain_cs_dag_poa_pvt_t * l_poa_pvt = PVT ( DAP_CHAIN_CS_DAG_POA( l_dag ) );

    const char * l_event_cmd_str = NULL;
    const char * l_event_hash_str = NULL;
    if ( l_poa_pvt->events_sign_cert == NULL) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "No certificate to sign events\n");
        return -2;
    }

    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "event", &l_event_cmd_str);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-event", &l_event_hash_str);

    if ( l_event_cmd_str == NULL ){
        if (l_poa_pvt->events_sign_cert )
        ret = -1;
        if ( strcmp(l_event_cmd_str,"sign") == 0) { // Sign event command
            char * l_gdb_group_events = l_dag->gdb_group_events_round_new;
            size_t l_event_size = 0;
            dap_chain_cs_dag_event_t * l_event;
            if ( (l_event = (dap_chain_cs_dag_event_t*) dap_chain_global_db_gr_get(l_event_hash_str ,
                                                       &l_event_size, l_gdb_group_events )) == NULL  ){
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "Can't find event in round.new - only place where could be signed the new event\n",
                                                  l_event_hash_str);
                ret = -30;
            }else {
                dap_chain_cs_dag_event_t *l_event_new = dap_chain_cs_dag_event_copy_with_sign_add(l_event,l_poa_pvt->events_sign_cert->enc_key );
                dap_chain_hash_fast_t l_event_new_hash;
                dap_chain_cs_dag_event_calc_hash(l_event_new,&l_event_new_hash);
                size_t l_event_new_size = dap_chain_cs_dag_event_calc_size(l_event_new);
                char * l_event_new_hash_str = dap_chain_hash_fast_to_str_new(&l_event_new_hash);
                if (dap_chain_global_db_gr_set(l_event_new_hash_str,(uint8_t*) l_event,l_event_size,l_gdb_group_events) ){
                    if ( dap_chain_global_db_gr_del(l_event_hash_str,l_gdb_group_events) ) { // Delete old event
                        dap_chain_node_cli_set_reply_text(a_str_reply, "Added new sign with cert \"%s\", event %s placed back in round.new\n",
                                                          l_poa_pvt->events_sign_cert->name ,l_event_new_hash_str);
                        ret = 0;
                        dap_chain_net_sync_gdb(l_chain_net); // Propagate changes in pool
                    }else {
                        ret = 1;
                        dap_chain_node_cli_set_reply_text(a_str_reply, "Added new sign with cert \"%s\", event %s placed back in round.new\n"
                                                                       "WARNING! Old event %s with same datum is still in round.new, produced DUP!\n"
                                                          ,
                                                          l_poa_pvt->events_sign_cert->name ,l_event_new_hash_str, l_event_hash_str);
                    }
                }else {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "GDB Error: Can't place event %s with new sign back in round.new\n",
                                                      l_event_new_hash_str);
                    ret=-31;
                }
            }
            DAP_DELETE( l_gdb_group_events );
            DAP_DELETE(l_event);
        }
    }
    return ret;
}

/**
 * @brief s_cs_callback
 * @param a_chain
 * @param a_chain_cfg
 */
static int s_callback_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg)
{
    dap_chain_cs_dag_new(a_chain,a_chain_cfg);
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG ( a_chain );
    dap_chain_cs_dag_poa_t * l_poa = DAP_NEW_Z ( dap_chain_cs_dag_poa_t);
    l_dag->_inheritor = l_poa;
    l_dag->callback_delete = s_callback_delete;
    l_dag->callback_cs_verify = s_callback_event_verify;
    l_dag->callback_cs_event_create = s_callback_event_create;
    l_poa->_pvt = DAP_NEW_Z ( dap_chain_cs_dag_poa_pvt_t );

    dap_chain_cs_dag_poa_pvt_t * l_poa_pvt = PVT ( l_poa );
    if (dap_config_get_item_str(a_chain_cfg,"dag-poa","auth_certs_prefix") ) {
        l_poa_pvt->auth_certs_count = dap_config_get_item_uint16_default(a_chain_cfg,"dag-poa","auth_certs_number",0);
        l_poa_pvt->auth_certs_count_verify = dap_config_get_item_uint16_default(a_chain_cfg,"dag-poa","auth_certs_number_verify",0);
        l_poa_pvt->auth_certs_prefix = strdup ( dap_config_get_item_str(a_chain_cfg,"dag-poa","auth_certs_prefix") );
        if (l_poa_pvt->auth_certs_count && l_poa_pvt->auth_certs_count_verify ) {
            l_poa_pvt->auth_certs = DAP_NEW_Z_SIZE ( dap_chain_cert_t *, l_poa_pvt->auth_certs_count * sizeof(dap_chain_cert_t));
            char l_cert_name[512];
            for (size_t i = 0; i < l_poa_pvt->auth_certs_count ; i++ ){
                dap_snprintf(l_cert_name,sizeof(l_cert_name),"%s.%lu",l_poa_pvt->auth_certs_prefix, i);
                if ( (l_poa_pvt->auth_certs[i] = dap_chain_cert_find_by_name( l_cert_name)) != NULL ) {
                    log_it(L_NOTICE, "Initialized auth cert \"%s\"", l_cert_name);
                } else{
                    log_it(L_ERROR, "Can't find cert \"%s\"", l_cert_name);
                    return -1;
                }
            }
        }
    }
    log_it(L_NOTICE,"Initialized DAG-PoA consensus with %u/%u minimum consensus",l_poa_pvt->auth_certs_count,l_poa_pvt->auth_certs_count_verify);
    // Save old callback if present and set the call of its own (chain callbacks)
    l_poa_pvt->prev_callback_created = l_dag->chain->callback_created;
    l_dag->chain->callback_created = s_callback_created;
    return 0;
}

/**
 * @brief s_callback_created
 * @param a_chain
 * @param a_chain_cfg
 * @return
 */
static int s_callback_created(dap_chain_t * a_chain, dap_config_t *a_chain_net_cfg)
{
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG ( a_chain );
    dap_chain_cs_dag_poa_t * l_poa = DAP_CHAIN_CS_DAG_POA( l_dag );

    // Call previous callback if present. So the first called is the first in
    if (PVT(l_poa)->prev_callback_created )
        PVT(l_poa)->prev_callback_created(a_chain,a_chain_net_cfg);

    const char * l_events_sign_cert = NULL;
    if ( ( l_events_sign_cert = dap_config_get_item_str(a_chain_net_cfg,"dag-poa","events-sign--cert") ) != NULL ) {

        if ( ( PVT(l_poa)->events_sign_cert = dap_chain_cert_find_by_name(l_events_sign_cert)) == NULL ){
            log_it(L_ERROR,"Can't load events sign certificate, name \"%s\" is wrong",l_events_sign_cert);
        }else
            log_it(L_NOTICE,"Loaded \"%s\" certificate to sign event");

    }
}

/**
 * @brief s_chain_cs_dag_callback_delete
 * @param a_dag
 */
static void s_callback_delete(dap_chain_cs_dag_t * a_dag)
{
    dap_chain_cs_dag_poa_t * l_poa = DAP_CHAIN_CS_DAG_POA ( a_dag );

    if ( l_poa->_pvt ) {
        dap_chain_cs_dag_poa_pvt_t * l_poa_pvt = PVT ( l_poa );

        if ( l_poa_pvt->auth_certs )
            DAP_DELETE ( l_poa_pvt->auth_certs);

        if ( l_poa_pvt->auth_certs_prefix )
            free ( l_poa_pvt->auth_certs_prefix );

        DAP_DELETE ( l_poa->_pvt);
    }

    if ( l_poa->_inheritor ) {
       DAP_DELETE ( l_poa->_inheritor );
    }
}

/**
 * @brief s_callback_event_create
 * @param a_dag
 * @param a_datum
 * @param a_hashes
 * @param a_hashes_count
 * @return
 */
static dap_chain_cs_dag_event_t * s_callback_event_create(dap_chain_cs_dag_t * a_dag, dap_chain_datum_t * a_datum,
                                                          dap_chain_hash_fast_t * a_hashes, size_t a_hashes_count)
{
    dap_chain_net_t * l_net = dap_chain_net_by_name( a_dag->chain->net_name );
    if ( PVT(a_dag)->events_sign_cert == NULL){
        log_it(L_ERROR, "Can't sign event with events_sign_cert in [dag-poa] section");
        return  NULL;
    }

    if ( s_seed_mode || (a_hashes&& a_hashes_count) ){
        dap_chain_cs_dag_event_t * l_event = dap_chain_cs_dag_event_new( a_dag->chain->id, l_net->pub.cell_id, a_datum,
                                                         PVT(a_dag)->events_sign_cert->enc_key, a_hashes, a_hashes_count);
        return l_event;
    }else
        return NULL;
}



/**
 * @brief s_chain_cs_dag_callback_event_verify
 * @param a_dag
 * @param a_dag_event
 * @return
 */
static int s_callback_event_verify(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_dag_event)
{
    dap_chain_cs_dag_poa_pvt_t * l_poa_pvt = PVT ( DAP_CHAIN_CS_DAG_POA( a_dag ) );
    if ( a_dag_event->header.signs_count >= l_poa_pvt->auth_certs_count_verify ){
        size_t l_verified = 0;
        for ( uint16_t i = 0; i < a_dag_event->header.signs_count; i++ ){
            for ( uint16_t j = 0; j < l_poa_pvt->auth_certs_count; j++){
                if( dap_chain_cert_compare_with_sign ( l_poa_pvt->auth_certs[j],
                            dap_chain_cs_dag_event_get_sign(a_dag_event,i) ) == 0 )
                    l_verified++;
            }
        }
        return l_verified >= l_poa_pvt->auth_certs_count_verify ? 0 : -1;
    }else
       return -2; // Wrong signatures number
}

