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
#include <pthread.h>
#endif

#include "dap_common.h"
#include "dap_timerfd.h"
#include "dap_strfuncs.h"
#include "dap_enc_base58.h"
#include "dap_chain_pvt.h"
#include "dap_chain_net.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_global_db.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_event.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_net_srv_stake.h"
#include "dap_chain_cell.h"

#include "dap_cert.h"

#define LOG_TAG "dap_chain_cs_dag_poa"

typedef struct dap_chain_cs_dag_poa_pvt
{
    dap_cert_t * events_sign_cert;
    dap_cert_t ** auth_certs;
    char * auth_certs_prefix;
    uint16_t auth_certs_count;
    uint16_t auth_certs_count_verify; // Number of signatures, needed for event verification
    uint32_t confirmations_timeout; // wait signs over min value (auth_certs_count_verify)
    bool auto_confirmation;
    bool auto_round_complete;
    uint32_t wait_sync_before_complete;
    uint8_t padding[4];
    dap_chain_callback_new_cfg_t prev_callback_created; // global network config init
} dap_chain_cs_dag_poa_pvt_t;

#define PVT(a) ((dap_chain_cs_dag_poa_pvt_t *) a->_pvt )

typedef struct dap_chain_cs_dag_poa_callback_timer_arg {
    dap_chain_cs_dag_t * dag;
    char * l_event_hash_hex_str;
    dap_chain_cs_dag_event_round_cfg_t event_round_cfg;
} dap_chain_cs_dag_poa_callback_timer_arg_t;

static void s_callback_get_round_cfg(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_round_cfg_t * a_event_round_cfg);
static void s_callback_delete(dap_chain_cs_dag_t * a_dag);
static int s_callback_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg);
static int s_callback_created(dap_chain_t * a_chain, dap_config_t *a_chain_cfg);
static int s_callback_event_verify(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_dag_event, size_t a_dag_event_size);
static dap_chain_cs_dag_event_t * s_callback_event_create(dap_chain_cs_dag_t * a_dag, dap_chain_datum_t * a_datum,
                                                          dap_chain_hash_fast_t * a_hashes, size_t a_hashes_count, size_t* a_event_size);
static bool s_callback_round_event_to_chain(dap_chain_cs_dag_poa_callback_timer_arg_t * a_callback_arg);
static int s_callback_event_round_sync(dap_chain_cs_dag_t * a_dag, const char a_op_code, const char *a_group,
                                        const char *a_key, const void *a_value, const size_t a_value_size);
static bool s_round_event_ready_minimum_check(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_event, 
                                            size_t a_event_size, char * a_event_hash_hex_str, 
                                            dap_chain_cs_dag_event_round_cfg_t * a_event_round_cfg);
static void s_round_event_cs_done(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_event,
                                    char * a_event_hash_hex_str, dap_chain_cs_dag_event_round_cfg_t * a_event_round_cfg);
static void s_round_event_clean_dup(dap_chain_cs_dag_t * a_dag, const char *a_event_hash_hex_str);

// CLI commands
static int s_cli_dag_poa(int argc, char ** argv, char **str_reply);

static bool s_seed_mode = false;

/**
 * @brief
 * init consensus dag_poa
 * read parameters from config and register dag_poa commands to cellframe-node-cli
 * @return
 */
int dap_chain_cs_dag_poa_init(void)
{
    // Add consensus constructor
    dap_chain_cs_add ("dag_poa", s_callback_new );
    s_seed_mode = dap_config_get_item_bool_default(g_config,"general","seed_mode",false);
    dap_chain_node_cli_cmd_item_create ("dag_poa", s_cli_dag_poa, "DAG PoA commands",
        "dag_poa -net <chain net name> -chain <chain name> event sign -event <event hash> [-H hex|base58(default)]\n"
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
 * @brief
 * parse and execute cellframe-node-cli dag-poa commands
 * @param argc arguments count
 * @param argv array with arguments
 * @param arg_func
 * @param str_reply
 * @return
 */
static int s_cli_dag_poa(int argc, char ** argv, char **a_str_reply)
{
    int ret = -666;
    int arg_index = 1;
    dap_chain_net_t * l_chain_net = NULL;
    dap_chain_t * l_chain = NULL;

    const char * l_hash_out_type = NULL;
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type, "hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "Invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    if (dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index,argc,argv,a_str_reply,&l_chain,&l_chain_net)) {
        return -3;
    }

    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG(l_chain);
    //dap_chain_cs_dag_poa_t * l_poa = DAP_CHAIN_CS_DAG_POA( l_dag ) ;
    dap_chain_cs_dag_poa_pvt_t * l_poa_pvt = PVT ( DAP_CHAIN_CS_DAG_POA( l_dag ) );

    const char * l_event_cmd_str = NULL;
    const char * l_event_hash_str = NULL;
    if ( l_poa_pvt->events_sign_cert == NULL) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "No certificate to sign events\n");
        return -2;
    }

    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "event", &l_event_cmd_str);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-event", &l_event_hash_str);
    if (!l_event_hash_str) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "Command dag_poa requires parameter '-event' <event hash>");
        return -4;
    }

    // event hash may be in hex or base58 format
    char *l_event_hash_hex_str;
    char *l_event_hash_base58_str;
    if(!dap_strcmp(l_hash_out_type, "hex")) {
        l_event_hash_hex_str = dap_strdup(l_event_hash_str);
        l_event_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_event_hash_str);
        if (!l_event_hash_base58_str) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Invalid hex hash format");
            return -5;
        }
    }
    else {
        l_event_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_event_hash_str);
        l_event_hash_base58_str = dap_strdup(l_event_hash_str);
        if (!l_event_hash_hex_str) {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Invalid base58 hash format");
        }
        return -6;
    }

    if ( l_event_cmd_str != NULL ){
        if (l_poa_pvt->events_sign_cert )
        ret = -1;
        if ( strcmp(l_event_cmd_str,"sign") == 0) { // Sign event command
            char * l_gdb_group_events = l_dag->gdb_group_events_round_new;
            size_t l_event_size = 0;
            dap_chain_cs_dag_event_t * l_event;
            dap_chain_cs_dag_event_round_cfg_t l_event_round_cfg;

            if ( (l_event = dap_chain_cs_dag_event_gdb_get( l_event_hash_hex_str, &l_event_size,
                                                            l_gdb_group_events, &l_event_round_cfg )) == NULL  ){
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "Can't find event in round.new - only place where could be signed the new event\n",
                                                  l_event_hash_str);
                ret = -30;
            }else {
                size_t l_event_size_new = 0;
                dap_chain_cs_dag_event_t *l_event_new = dap_chain_cs_dag_event_copy_with_sign_add(l_event, l_event_size, 
                                                        &l_event_size_new,
                                                        l_chain_net, l_poa_pvt->events_sign_cert->enc_key);
                if ( l_event_new ) {
                    dap_chain_hash_fast_t l_event_new_hash;
                    dap_chain_cs_dag_event_calc_hash(l_event_new, l_event_size_new, &l_event_new_hash);
                    //size_t l_event_new_size = dap_chain_cs_dag_event_calc_size(l_event_new);
                    char * l_event_new_hash_hex_str = dap_chain_hash_fast_to_str_new(&l_event_new_hash);
                    char * l_event_new_hash_base58_str = dap_enc_base58_encode_hash_to_str(&l_event_new_hash);
                    //char * l_event_new_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_event_new_hash_hex_str);
                    bool l_event_is_ready = s_round_event_ready_minimum_check(l_dag, l_event_new, l_event_size_new,
                                                                        l_event_new_hash_hex_str, &l_event_round_cfg);
                    if (dap_chain_cs_dag_event_gdb_set(l_event_new_hash_hex_str, l_event_new,
                                                        l_event_size_new, l_gdb_group_events, &l_event_round_cfg) ){
                        if ( !dap_chain_global_db_gr_del(dap_strdup(l_event_hash_hex_str), l_gdb_group_events) ) { // Delete old event
                            ret = 1;
                            dap_chain_node_cli_set_reply_text(a_str_reply, "Added new sign with cert \"%s\", event %s placed back in round.new\n"
                                                                           "WARNING! Old event %s with same datum is still in round.new, produced DUP!\n",
                                                                           l_poa_pvt->events_sign_cert->name ,l_event_new_hash_hex_str, l_event_hash_str);
                        }

                        if(!dap_strcmp(l_hash_out_type, "hex")) {
                            dap_chain_node_cli_set_reply_text(a_str_reply,
                                    "Added new sign with cert \"%s\", event %s placed back in round.new\n",
                                    l_poa_pvt->events_sign_cert->name, l_event_new_hash_hex_str);
                        }
                        else {
                            dap_chain_node_cli_set_reply_text(a_str_reply,
                                    "Added new sign with cert \"%s\", event %s placed back in round.new\n",
                                    l_poa_pvt->events_sign_cert->name, l_event_new_hash_base58_str);
                        }
                        ret = 0;
                        // dap_chain_net_sync_gdb(l_chain_net); // Propagate changes in pool
                        if (l_event_is_ready && l_poa_pvt->auto_round_complete) { // cs done (minimum signs & verify passed)
                            s_round_event_cs_done(l_dag, l_event_new, l_event_new_hash_hex_str, &l_event_round_cfg);
                        }

                    }else {
                        if(!dap_strcmp(l_hash_out_type, "hex")) {
                            dap_chain_node_cli_set_reply_text(a_str_reply,
                                    "GDB Error: Can't place event %s with new sign back in round.new\n",
                                    l_event_new_hash_hex_str);
                        }
                        else {
                            dap_chain_node_cli_set_reply_text(a_str_reply,
                                    "GDB Error: Can't place event %s with new sign back in round.new\n",
                                    l_event_new_hash_base58_str);
                        }
                        ret=-31;

                    }
                    DAP_DELETE(l_event_new);
                    DAP_DELETE(l_event_new_hash_hex_str);
                    DAP_DELETE(l_event_new_hash_base58_str);
                } else {
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "Can't sign event in round.new\n",
                                                  l_event_hash_str);
                    ret=-1;        
                }
            }
            // DAP_DELETE( l_gdb_group_events );
            // DAP_DELETE(l_event_round_cfg);
            DAP_DELETE(l_event);
        } else {
            dap_chain_node_cli_set_reply_text(a_str_reply, "Command dag_poa requires subcommand 'sign'");
        }
    } else {
        dap_chain_node_cli_set_reply_text(a_str_reply, "Command dag_poa requires subcommand 'event'");
    }
    return ret;
}

/**
 * @brief s_cs_callback
 * dap_chain_callback_new_cfg_item_t->callback_init function.
 * get dag-poa consensus parameters from config
 * and set dap_chain_cs_dag_t l_dag->chain->callback_created = s_callback_new
 * @param a_chain dap_chain_t chain object
 * @param a_chain_cfg chain config object
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
    l_dag->callback_cs_get_round_cfg = s_callback_get_round_cfg;
    l_dag->callback_cs_event_round_sync = s_callback_event_round_sync;
    l_poa->_pvt = DAP_NEW_Z ( dap_chain_cs_dag_poa_pvt_t );

    dap_chain_cs_dag_poa_pvt_t * l_poa_pvt = PVT ( l_poa );
    if (dap_config_get_item_str(a_chain_cfg,"dag-poa","auth_certs_prefix") ) {
        l_poa_pvt->auth_certs_count = dap_config_get_item_uint16_default(a_chain_cfg,"dag-poa","auth_certs_number",0);
        l_poa_pvt->auth_certs_count_verify = dap_config_get_item_uint16_default(a_chain_cfg,"dag-poa","auth_certs_number_verify",0);
        l_poa_pvt->confirmations_timeout = dap_config_get_item_uint32_default(a_chain_cfg,"dag-poa","confirmations_timeout",600);
        l_poa_pvt->auto_confirmation = dap_config_get_item_bool_default(a_chain_cfg,"dag-poa","auto_confirmation",true);
        l_poa_pvt->auto_round_complete = dap_config_get_item_bool_default(a_chain_cfg,"dag-poa","auto_round_complete",true);
        l_poa_pvt->wait_sync_before_complete = dap_config_get_item_uint32_default(a_chain_cfg,"dag-poa","wait_sync_before_complete",180);
        l_poa_pvt->auth_certs_prefix = strdup ( dap_config_get_item_str(a_chain_cfg,"dag-poa","auth_certs_prefix") );
        if (l_poa_pvt->auth_certs_count && l_poa_pvt->auth_certs_count_verify ) {
            l_poa_pvt->auth_certs = DAP_NEW_Z_SIZE ( dap_cert_t *, l_poa_pvt->auth_certs_count * sizeof(dap_cert_t));
            char l_cert_name[512];
            for (size_t i = 0; i < l_poa_pvt->auth_certs_count ; i++ ){
                dap_snprintf(l_cert_name,sizeof(l_cert_name),"%s.%zu",l_poa_pvt->auth_certs_prefix, i);
                if ((l_poa_pvt->auth_certs[i] = dap_cert_find_by_name( l_cert_name)) == NULL) {
                    dap_snprintf(l_cert_name,sizeof(l_cert_name),"%s.%zu.pub",l_poa_pvt->auth_certs_prefix, i);
                    if ((l_poa_pvt->auth_certs[i] = dap_cert_find_by_name( l_cert_name)) == NULL) {
                        log_it(L_ERROR, "Can't find cert \"%s\"", l_cert_name);
                        return -1;
                    }
                }
                log_it(L_NOTICE, "Initialized auth cert \"%s\"", l_cert_name);
            }
        }
    }
    log_it(L_NOTICE,"Initialized DAG-PoA consensus with %u/%u minimum consensus",l_poa_pvt->auth_certs_count,l_poa_pvt->auth_certs_count_verify);
    // Save old callback if present and set the call of its own (chain callbacks)
    l_poa_pvt->prev_callback_created = l_dag->chain->callback_created;
    l_dag->chain->callback_created = s_callback_created;
    return 0;
}


typedef struct event_clean_dup_items {
    uint16_t signs_count;
    uint64_t ts_update;
    char * hash_str;
    UT_hash_handle hh;
} event_clean_dup_items_t;

static event_clean_dup_items_t *s_event_clean_dup_items = NULL;

static void s_round_event_clean_dup(dap_chain_cs_dag_t * a_dag, const char *a_event_hash_hex_str) {
    char * l_gdb_group_events = a_dag->gdb_group_events_round_new;
    size_t l_event_size = 0;
    dap_chain_cs_dag_event_t * l_event;
    dap_chain_cs_dag_event_round_cfg_t l_event_round_cfg;
    if ( (l_event = dap_chain_cs_dag_event_gdb_get( a_event_hash_hex_str, &l_event_size,
                                                    l_gdb_group_events, &l_event_round_cfg )) == NULL  ) {
        return;
    }

    //char * l_event_first_hash_str = dap_chain_hash_fast_to_str_new(&l_event_round_cfg.first_event_hash);
    size_t l_events_round_size = 0;
    // dap_global_db_obj_t * l_events_round = dap_chain_global_db_gr_load(a_dag->gdb_group_events_round_new, &l_events_round_size );
    dap_store_obj_t *l_events_round = dap_chain_global_db_driver_read(a_dag->gdb_group_events_round_new, NULL, &l_events_round_size);
    uint16_t l_max_signs_count = 0;
    //char * l_max_signs_hash;
    for (size_t l_index = 0; l_index<l_events_round_size; l_index++) {
        // dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *)
        //         ((dap_chain_cs_dag_event_round_item_t *)l_events_round[l_index].value)->event;
        // size_t l_event_size = ((dap_chain_cs_dag_event_round_item_t *)l_events_round[l_index].value)->event_size;
        dap_chain_cs_dag_event_round_item_t *l_event_round_item = (dap_chain_cs_dag_event_round_item_t *)l_events_round[l_index].value;
        dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *)l_event_round_item->event;
        if ( memcmp(&l_event_round_cfg.first_event_hash, 
                        &l_event_round_item->cfg.first_event_hash, sizeof(dap_chain_hash_fast_t)) == 0 ) {
            event_clean_dup_items_t * l_item = DAP_NEW_Z(event_clean_dup_items_t);
            l_item->signs_count = l_event->header.signs_count;
            // l_item->ts_update = l_events_round[l_index].timestamp;
            l_item->ts_update = l_event_round_item->cfg.ts_update;
            l_item->hash_str = l_events_round[l_index].key;
            HASH_ADD_STR(s_event_clean_dup_items, hash_str, l_item);
            if ( l_event->header.signs_count > l_max_signs_count ) {
                l_max_signs_count = l_event->header.signs_count;
            }
        }
    }

    uint64_t l_max_ts_update = 0;
    char * l_max_ts_update_hash;
    event_clean_dup_items_t *l_clean_item=NULL, *l_clean_tmp=NULL;
    HASH_ITER(hh, s_event_clean_dup_items, l_clean_item, l_clean_tmp) {
        if ( l_clean_item->signs_count < l_max_signs_count ) {
            // delete dup by min signatures 
            dap_chain_global_db_gr_del(dap_strdup(l_clean_item->hash_str), l_gdb_group_events);
            HASH_DEL(s_event_clean_dup_items, l_clean_item);
            DAP_DELETE(l_clean_item);
        } else if ( l_clean_item->ts_update > l_max_ts_update ) {
            l_max_ts_update = l_clean_item->ts_update;
            l_max_ts_update_hash = l_clean_item->hash_str;
        }
    }
    HASH_ITER(hh, s_event_clean_dup_items, l_clean_item, l_clean_tmp) {
        if ( dap_strcmp(l_max_ts_update_hash, l_clean_item->hash_str) != 0 ) {
            // delete dup by older
            dap_chain_global_db_gr_del(dap_strdup(l_clean_item->hash_str), l_gdb_group_events);
        }
        HASH_DEL(s_event_clean_dup_items, l_clean_item);
        DAP_DELETE(l_clean_item);
    }
    //HASH_CLEAR(hh, s_event_clean_dup_items);
    dap_store_obj_free(l_events_round, l_events_round_size);
}

static bool s_round_event_ready_minimum_check(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_event, 
                                            size_t a_event_size, char * a_event_hash_hex_str,
                                            dap_chain_cs_dag_event_round_cfg_t * a_event_round_cfg) {
    if ( a_event->header.signs_count < a_event_round_cfg->confirmations_minimum ) {
        return false;
    }
    a_dag->callback_cs_set_event_round_cfg(a_dag, a_event_round_cfg);
    int l_ret_event_verify = a_dag->callback_cs_verify(a_dag, a_event, a_event_size);
    if ( l_ret_event_verify == 0 ) {
        if (a_event_round_cfg->ts_confirmations_minimum_completed == (uint64_t)0) {
            a_event_round_cfg->ts_confirmations_minimum_completed = (uint64_t)time(NULL);
        }
        return true;
    }
    log_it(L_ERROR,"Round auto-complete error! Event %s is not passing consensus verification, ret code %d\n",
                          a_event_hash_hex_str, l_ret_event_verify );
    return false;
}

static void s_round_event_cs_done(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_event,
                                    char * a_event_hash_hex_str, dap_chain_cs_dag_event_round_cfg_t * a_event_round_cfg) {
    dap_chain_cs_dag_poa_t * l_poa = DAP_CHAIN_CS_DAG_POA( a_dag );
    dap_chain_cs_dag_poa_callback_timer_arg_t * l_callback_arg = DAP_NEW_Z(dap_chain_cs_dag_poa_callback_timer_arg_t);
    l_callback_arg->dag = a_dag;
    l_callback_arg->l_event_hash_hex_str = dap_strdup(a_event_hash_hex_str);
    memcpy(&l_callback_arg->event_round_cfg, a_event_round_cfg, sizeof(dap_chain_cs_dag_event_round_cfg_t));
    uint32_t l_timeout = a_event_round_cfg->confirmations_timeout;

    if (a_event_round_cfg->ts_confirmations_minimum_completed == (uint64_t)0) {
        a_event_round_cfg->ts_confirmations_minimum_completed = (uint64_t)time(NULL);
    }

    if ( a_event->header.signs_count >= PVT(l_poa)->auth_certs_count) {
        // placement in chain now if max signs
        if (dap_timerfd_start(PVT(l_poa)->wait_sync_before_complete*1000, 
                            (dap_timerfd_callback_t)s_callback_round_event_to_chain, 
                            l_callback_arg) == NULL) {
            log_it(L_ERROR,"Can't run timer for Event %s", a_event_hash_hex_str);
        } else {
            log_it(L_NOTICE,"Run timer %dsec. for Event %s", PVT(l_poa)->wait_sync_before_complete, a_event_hash_hex_str);
        }
    }
    else if ( l_timeout > ((uint64_t)time(NULL) - a_event_round_cfg->ts_confirmations_minimum_completed) ) {
        l_timeout = l_timeout - ((uint64_t)time(NULL) - a_event_round_cfg->ts_confirmations_minimum_completed);
        // placement in chain by timer
        l_timeout += PVT(l_poa)->wait_sync_before_complete;
        if (dap_timerfd_start(l_timeout*1000, 
                            (dap_timerfd_callback_t)s_callback_round_event_to_chain, 
                            l_callback_arg) == NULL) {
            log_it(L_ERROR,"Can't run timer for Event %s", a_event_hash_hex_str);
        } else {
            log_it(L_NOTICE,"Run timer %dsec. for Event %s", l_timeout, a_event_hash_hex_str);
        }
    } else { // placement in chain now if timer out
        if (dap_timerfd_start(PVT(l_poa)->wait_sync_before_complete*1000, 
                            (dap_timerfd_callback_t)s_callback_round_event_to_chain, 
                            l_callback_arg) == NULL) {
            log_it(L_ERROR,"Can't run timer for Event %s", a_event_hash_hex_str);
        } else {
            log_it(L_NOTICE,"Run timer %dsec. for Event %s", PVT(l_poa)->wait_sync_before_complete, a_event_hash_hex_str);
        }
    }
}

static void s_callback_get_round_cfg(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_round_cfg_t * a_event_round_cfg) {
    dap_chain_cs_dag_poa_t * l_poa = DAP_CHAIN_CS_DAG_POA(a_dag);
    dap_chain_cs_dag_poa_pvt_t * l_poa_pvt = PVT (l_poa);
    a_event_round_cfg->confirmations_minimum = l_poa_pvt->auth_certs_count_verify;
    a_event_round_cfg->confirmations_timeout = l_poa_pvt->confirmations_timeout;
    a_event_round_cfg->ts_confirmations_minimum_completed = 0;
}

static bool s_callback_round_event_to_chain(dap_chain_cs_dag_poa_callback_timer_arg_t * a_callback_arg) {
    dap_chain_cs_dag_t * l_dag = a_callback_arg->dag;
    dap_chain_net_t *l_net = dap_chain_net_by_id(l_dag->chain->net_id);
    char * l_gdb_group_events = l_dag->gdb_group_events_round_new;
    dap_chain_cs_dag_event_t * l_event;
    size_t l_event_size = 0;
    dap_chain_cs_dag_event_round_cfg_t l_event_round_cfg;

    if ( (l_event = dap_chain_cs_dag_event_gdb_get( a_callback_arg->l_event_hash_hex_str, &l_event_size,
                                                    l_gdb_group_events, &l_event_round_cfg )) == NULL  ){
        log_it(L_NOTICE,"Can't find event %s in round.new. The hash may have changed by reason the addition of a new signature.", 
                        a_callback_arg->l_event_hash_hex_str);
    } 
    else {
        dap_chain_atom_ptr_t l_new_atom = (dap_chain_atom_ptr_t)dap_chain_cs_dag_event_copy(l_event, l_event_size);
        memcpy(l_new_atom, l_event, l_event_size);

        if(l_dag->chain->callback_atom_add(l_dag->chain, l_new_atom, l_event_size) < 0) { // Add new atom in chain
            DAP_DELETE(l_new_atom);
            log_it(L_NOTICE, "Event %s not added in chain", a_callback_arg->l_event_hash_hex_str);
        }
        else {
            log_it(L_NOTICE, "Event %s added in chain successfully",
                    a_callback_arg->l_event_hash_hex_str);
            // event delete from round
            dap_chain_cell_id_t l_cell_id = {
                .uint64 = l_net ? l_net->pub.cell_id.uint64 : 0
            };
            dap_chain_cell_t *l_cell = dap_chain_cell_find_by_id(l_dag->chain, l_cell_id);
            if (!l_cell)
                l_cell = dap_chain_cell_create_fill(l_dag->chain, l_cell_id);
            if(l_cell) {
                if(dap_chain_cell_file_update(l_cell) > 0) {
                    // delete events from db
                    dap_chain_global_db_gr_del(dap_strdup(a_callback_arg->l_event_hash_hex_str), l_dag->gdb_group_events_round_new);
                }
            }
            dap_chain_cell_close(l_cell);
            // dap_chain_net_sync_all(l_net);
        }
    }

    DAP_DELETE(a_callback_arg->l_event_hash_hex_str);
    DAP_DELETE(a_callback_arg);
    return false;
}

/**
 * @brief create callback load certificate for event signing for specific chain
 * path to certificate iw written to chain config file in dag_poa section
 * @param a_chain chain object (for example, a_chain.name = zerochain, a_chain.network = kelvin-testnet)
 * @param a_chain_net_cfg dap_config_t network config object
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
    if ( ( l_events_sign_cert = dap_config_get_item_str(a_chain_net_cfg,"dag-poa","events-sign-cert") ) != NULL ) {

        if ( ( PVT(l_poa)->events_sign_cert = dap_cert_find_by_name(l_events_sign_cert)) == NULL ){
            log_it(L_ERROR,"Can't load events sign certificate, name \"%s\" is wrong",l_events_sign_cert);
        }else
            log_it(L_NOTICE,"Loaded \"%s\" certificate to sign poa event", l_events_sign_cert);

    }
    return 0;
}

/**
 * @brief 
 * delete dap_chain_cs_dag_poa_pvt_t callback
 * @param a_dag dap_chain_cs_dag_t object
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
 * @brief 
 * callback for create event operation
 * @param a_dag dap_chain_cs_dag_t DAG object
 * @param a_datum dap_chain_datum_t
 * @param a_hashes  dap_chain_hash_fast_t 
 * @param a_hashes_count size_t
 * @param a_dag_event_size size_t
 * @return dap_chain_cs_dag_event_t* 
 */
static dap_chain_cs_dag_event_t * s_callback_event_create(dap_chain_cs_dag_t * a_dag, dap_chain_datum_t * a_datum,
                                                          dap_chain_hash_fast_t * a_hashes, size_t a_hashes_count, size_t* a_event_size)
{
    dap_return_val_if_fail(a_dag && a_dag->chain && DAP_CHAIN_CS_DAG_POA(a_dag), NULL);
    dap_chain_net_t * l_net = dap_chain_net_by_name( a_dag->chain->net_name );
    dap_chain_cs_dag_poa_t * l_poa = DAP_CHAIN_CS_DAG_POA(a_dag);
    if ( PVT(l_poa)->events_sign_cert == NULL){
        log_it(L_ERROR, "Can't sign event with events_sign_cert in [dag-poa] section");
        return  NULL;
    }
    if ( s_seed_mode || (a_hashes && a_hashes_count) ){
        dap_chain_cs_dag_event_t * l_event = dap_chain_cs_dag_event_new( a_dag->chain->id, l_net->pub.cell_id, a_datum,
                                                         PVT(l_poa)->events_sign_cert->enc_key, a_hashes, a_hashes_count,a_event_size);
        return l_event;
    }else
        return NULL;
}


static int s_callback_event_round_sync(dap_chain_cs_dag_t * a_dag, const char a_op_code, const char *a_group,
                                        const char *a_key, const void *a_value, const size_t a_value_size)
{

    dap_chain_net_t *l_net = dap_chain_net_by_id( a_dag->chain->net_id);

    if ( a_value == NULL || a_op_code != 'a' ) {
        return 0;
    }

    dap_chain_cs_dag_poa_t * l_poa = DAP_CHAIN_CS_DAG_POA(a_dag);
    if ( !PVT(l_poa)->auto_confirmation ) {
        return 0;
    }
    dap_chain_cs_dag_event_round_item_t *l_event_round_item = (dap_chain_cs_dag_event_round_item_t *)a_value;
    size_t l_event_size = l_event_round_item->event_size;
    dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *)l_event_round_item->event;
    // dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *)DAP_DUP_SIZE(l_event_round_item->event, l_event_size);
    size_t l_event_size_new = 0;
    dap_chain_cs_dag_event_t *l_event_new = dap_chain_cs_dag_event_copy_with_sign_add(l_event, l_event_size, 
                                            &l_event_size_new, l_net,
                                            PVT(l_poa)->events_sign_cert->enc_key);
    
    if ( l_event_new ) {
        char * l_gdb_group_events = a_dag->gdb_group_events_round_new;
        dap_chain_hash_fast_t l_event_new_hash;
        dap_chain_cs_dag_event_calc_hash(l_event_new, l_event_size_new, &l_event_new_hash);
        char * l_event_new_hash_hex_str = dap_chain_hash_fast_to_str_new(&l_event_new_hash);
        bool l_event_is_ready = s_round_event_ready_minimum_check(a_dag, l_event_new, l_event_size_new, 
                                                                    l_event_new_hash_hex_str,  &l_event_round_item->cfg);
        if (dap_chain_cs_dag_event_gdb_set(l_event_new_hash_hex_str, l_event_new,
                                            l_event_size_new, l_gdb_group_events, &l_event_round_item->cfg) ){
            dap_chain_global_db_gr_del(dap_strdup(a_key), l_gdb_group_events); // Delete old event
            if (l_event_is_ready && PVT(l_poa)->auto_round_complete) { // cs done (minimum signs & verify passed)
                s_round_event_cs_done(a_dag, l_event_new, l_event_new_hash_hex_str, &l_event_round_item->cfg);
            }
        }
        s_round_event_clean_dup(a_dag, l_event_new_hash_hex_str); // Delete dup
        DAP_DELETE(l_event_new);
    } else {
        // if (PVT(l_poa)->auto_round_complete) {
        //     if (s_round_event_ready_minimum_check(a_dag, l_event, l_event_size, &l_event_round_item->cfg)){
        //         s_round_event_cs_done(a_dag, l_event, a_key, &l_event_round_item->cfg);
        //     }
        // }
        s_round_event_clean_dup(a_dag, a_key); // Delete dup
    }

    return 0;
}

/**
 * @brief 
 * function makes event singing verification
 * @param a_dag dag object
 * @param a_dag_event dap_chain_cs_dag_event_t
 * @param a_dag_event_size size_t size of event object
 * @return int 
 */
static int s_callback_event_verify(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_dag_event, size_t a_dag_event_size)
{
    dap_chain_cs_dag_poa_pvt_t * l_poa_pvt = PVT ( DAP_CHAIN_CS_DAG_POA( a_dag ) );
    size_t l_offset_from_beginning = dap_chain_cs_dag_event_calc_size_excl_signs(a_dag_event,a_dag_event_size);
    if( l_offset_from_beginning >= a_dag_event_size){
        log_it(L_WARNING,"Incorrect size with event %p: caled size excl signs %zd is bigger or equal then event size %zd",
               a_dag_event, l_offset_from_beginning, a_dag_event_size);
        return -7; // Incorrest size
    }
    uint16_t l_certs_count_verify = a_dag->use_event_round_cfg ? a_dag->event_round_cfg.confirmations_minimum
                                                                : l_poa_pvt->auth_certs_count_verify;
    a_dag->use_event_round_cfg = false;
    // if ( a_dag_event->header.signs_count >= l_poa_pvt->auth_certs_count_verify ){
    if ( a_dag_event->header.signs_count >= l_certs_count_verify ){

        size_t l_verified = 0;
        for ( uint16_t i = 0; i < a_dag_event->header.signs_count; i++ ) {
            if (l_offset_from_beginning == a_dag_event_size)
                break;
            dap_sign_t * l_sign = dap_chain_cs_dag_event_get_sign(a_dag_event,a_dag_event_size , 0);
            if ( l_sign == NULL){
                log_it(L_WARNING, "Event is NOT signed with anything");
                return -4;
            }
            l_offset_from_beginning += dap_sign_get_size( l_sign);
            if (l_offset_from_beginning > a_dag_event_size){
                log_it(L_WARNING,"Incorrect size with event %p", a_dag_event);
                return -7;
            }
            for (uint16_t j = 0; j < l_poa_pvt->auth_certs_count; j++) {
                if (dap_cert_compare_with_sign ( l_poa_pvt->auth_certs[j], l_sign) == 0)
                    l_verified++;
            }
        }
        //return l_verified >= l_poa_pvt->auth_certs_count_verify ? 0 : -1;
        return l_verified >= l_certs_count_verify ? 0 : -1;
    }else if (a_dag_event->header.hash_count == 0){
        dap_chain_hash_fast_t l_event_hash;
        dap_chain_cs_dag_event_calc_hash(a_dag_event,a_dag_event_size, &l_event_hash);
        if ( memcmp( &l_event_hash, &a_dag->static_genesis_event_hash, sizeof(l_event_hash) ) == 0 ){
            return 0;
        }else{
            log_it(L_WARNING,"Wrong genesis event %p: hash is not equels to what in config", a_dag_event);
            return -20; // Wrong signatures number
        }
    }else{
        log_it(L_WARNING,"Wrong signatures number with event %p", a_dag_event);
        return -2; // Wrong signatures number
    }
}

dap_cert_t **dap_chain_cs_dag_poa_get_auth_certs(dap_chain_t *a_chain, size_t *a_auth_certs_count)
{
    dap_chain_pvt_t *l_chain_pvt = DAP_CHAIN_PVT(a_chain);
    if (strcmp(l_chain_pvt->cs_name, "dag_poa"))
        return NULL;
    dap_chain_cs_dag_poa_pvt_t *l_poa_pvt = PVT(DAP_CHAIN_CS_DAG_POA(DAP_CHAIN_CS_DAG(a_chain)));
    if (a_auth_certs_count)
        *a_auth_certs_count = l_poa_pvt->auth_certs_count;
    return l_poa_pvt->auth_certs;
}
