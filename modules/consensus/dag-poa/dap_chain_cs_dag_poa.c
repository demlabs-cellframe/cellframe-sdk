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
#include "dap_global_db.h"
#include "dap_global_db_driver.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_event.h"
#include "dap_chain_cs_dag_poa.h"
//#include "dap_chain_net_srv_stake.h"
#include "dap_chain_cell.h"
#include "dap_global_db.h"
#include "dap_cert.h"

#define LOG_TAG "dap_chain_cs_dag_poa"

typedef struct dap_chain_cs_dag_poa_presign_callback{
    dap_chain_cs_dag_poa_callback_t callback;
    void *arg;
} dap_chain_cs_dag_poa_presign_callback_t;

struct round_timer_arg {
    dap_chain_cs_dag_t *dag;
    uint64_t round_id;
    UT_hash_handle hh;
};

typedef struct dap_chain_cs_dag_poa_pvt {
    pthread_rwlock_t rounds_rwlock;
    struct round_timer_arg *active_rounds;
    dap_cert_t * events_sign_cert;
    dap_cert_t ** auth_certs;
    char * auth_certs_prefix;
    uint16_t auth_certs_count;
    uint16_t auth_certs_count_verify; // Number of signatures, needed for event verification
    bool auto_confirmation;
    bool auto_round_complete;
    uint32_t confirmations_timeout; // wait signs over min value (auth_certs_count_verify)
    uint32_t wait_sync_before_complete;
    dap_chain_cs_dag_poa_presign_callback_t *callback_pre_sign;
} dap_chain_cs_dag_poa_pvt_t;

#define PVT(a) ((dap_chain_cs_dag_poa_pvt_t *) a->_pvt )

static void s_callback_delete(dap_chain_cs_dag_t * a_dag);
static int s_callback_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg);
static void s_poa_round_clean(void *a_arg);
static int s_callback_created(dap_chain_t * a_chain, dap_config_t *a_chain_cfg);
static int s_callback_event_verify(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_dag_event, size_t a_dag_event_size);
static dap_chain_cs_dag_event_t * s_callback_event_create(dap_chain_cs_dag_t * a_dag, dap_chain_datum_t * a_datum,
                                                          dap_chain_hash_fast_t * a_hashes, size_t a_hashes_count, size_t* a_event_size);
static bool s_callback_round_event_to_chain(struct round_timer_arg *a_arg);
static int s_callback_event_round_sync(dap_chain_cs_dag_t * a_dag, const char a_op_code, const char *a_group,
                                        const char *a_key, const void *a_value, const size_t a_value_size);
static bool s_round_event_ready_minimum_check(dap_chain_cs_dag_t *a_dag, dap_chain_cs_dag_event_t *a_event,
                                              size_t a_event_size, char *a_event_hash_hex_str);
static void s_round_event_cs_done(dap_chain_cs_dag_t * a_dag, uint64_t a_round_id);

// CLI commands
static int s_cli_dag_poa(int argc, char ** argv, char **str_reply);

static bool s_seed_mode = false;
static dap_interval_timer_t s_poa_round_timer = NULL;

/**
 * @brief
 * init consensus dag_poa
 * read parameters from config and register dag_poa commands to cellframe-node-cli
 * @return
 */
int dap_chain_cs_dag_poa_init()
{
    // Add consensus constructor
    dap_chain_cs_add ("dag_poa", s_callback_new );
    s_seed_mode = dap_config_get_item_bool_default(g_config,"general","seed_mode",false);
    dap_cli_server_cmd_add ("dag_poa", s_cli_dag_poa, "DAG PoA commands",
        "dag_poa event sign -net <net_name> -chain <chain_name> -event <event_hash> [-H {hex | base58(default)}]\n"
            "\tSign event <event hash> in the new round pool with its authorize certificate\n\n");

    return 0;
}

/**
 * @brief dap_chain_cs_dag_poa_deinit
 */
void dap_chain_cs_dag_poa_deinit(void)
{

}

/*
// example
static int s_callback_presign_test(dap_chain_t *a_chain,
                    dap_chain_cs_dag_event_t* a_event, size_t a_event_size, void *a_arg) {
    dap_chain_hash_fast_t l_event_hash;
    dap_chain_cs_dag_event_calc_hash(a_event, a_event_size, &l_event_hash);
    char * l_event_hash_str = dap_chain_hash_fast_to_str_new(&l_event_hash);
    log_it(L_NOTICE,"Callback: %s, net_name:%s, event_hash:%s", (char*)a_arg, a_chain->net_name, l_event_hash_str);
    return -1; // return 0 if passed
}

// add callback
// dap_chain_cs_dag_poa_presign_callback_set(l_dag->chain,
//            (dap_chain_cs_dag_poa_callback_t)s_callback_presign_test, "Presign callback test");
*/
void dap_chain_cs_dag_poa_presign_callback_set(dap_chain_t *a_chain, dap_chain_cs_dag_poa_callback_t a_callback, void *a_arg)
{
    if (!a_chain) {
        log_it(L_ERROR, "NULL with chain argument for setting presign callback");
        return;
    }
    if (!a_callback) {
        log_it(L_ERROR, "Trying to set NULL presign callback");
        return;
    }
    dap_chain_cs_dag_t *l_dag = DAP_CHAIN_CS_DAG(a_chain);
    dap_chain_cs_dag_poa_pvt_t * l_poa_pvt = PVT(DAP_CHAIN_CS_DAG_POA(l_dag));
    l_poa_pvt->callback_pre_sign =
            (dap_chain_cs_dag_poa_presign_callback_t*)DAP_NEW_Z(dap_chain_cs_dag_poa_presign_callback_t);
    if (!l_poa_pvt->callback_pre_sign) {
        log_it(L_CRITICAL, "Memory allocation error");
        return;
    }
    l_poa_pvt->callback_pre_sign->callback = a_callback;
    l_poa_pvt->callback_pre_sign->arg = a_arg;
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
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type, "hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    if (dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index,argc,argv,a_str_reply,&l_chain,&l_chain_net)) {
        return -3;
    }

    const char *l_chain_type = dap_chain_net_get_type(l_chain);

    if (strcmp(l_chain_type, "dag_poa")){
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Type of chain %s is not dag_poa. This chain with type %s is not supported by this command",
                        l_chain->name, l_chain_type);
            return -42;
    }

    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG(l_chain);
    dap_chain_cs_dag_poa_pvt_t * l_poa_pvt = PVT ( DAP_CHAIN_CS_DAG_POA( l_dag ) );

    const char * l_event_cmd_str = NULL;
    const char * l_event_hash_str = NULL;
    if ( l_poa_pvt->events_sign_cert == NULL) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "No certificate to sign events\n");
        return -2;
    }

    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "event", &l_event_cmd_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-event", &l_event_hash_str);
    if (!l_event_hash_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Command dag_poa requires parameter '-event' <event hash>");
        return -4;
    }

    // event hash may be in hex or base58 format
    char *l_event_hash_hex_str;
    char *l_event_hash_base58_str;

    if(!dap_strcmp(l_hash_out_type, "hex")) {
        l_event_hash_hex_str = dap_strdup(l_event_hash_str);
        l_event_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_event_hash_str);

        if (!l_event_hash_base58_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Invalid hex hash format");
            DAP_DELETE(l_event_hash_hex_str);
            return -5;
        }
    }
    else {
        l_event_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_event_hash_str);
        l_event_hash_base58_str = dap_strdup(l_event_hash_str);

        if (!l_event_hash_hex_str) {
            DAP_DELETE(l_event_hash_base58_str);
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Invalid base58 hash format");
            return -6;
        }

        DAP_DELETE(l_event_hash_hex_str);
        DAP_DELETE(l_event_hash_base58_str);
        return -6;
    }


    if ( l_event_cmd_str != NULL ){
        if (l_poa_pvt->events_sign_cert )
        ret = -1;
        if ( strcmp(l_event_cmd_str,"sign") == 0) { // Sign event command
            char * l_gdb_group_events = l_dag->gdb_group_events_round_new;
            size_t l_round_item_size = 0;
            dap_chain_cs_dag_event_round_item_t *l_round_item =
                                (dap_chain_cs_dag_event_round_item_t *)dap_global_db_get_sync(l_gdb_group_events,
                                                    l_event_hash_hex_str, &l_round_item_size, NULL, NULL );
            if ( l_round_item == NULL ) {
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                  "Can't find event %s in round.new - only place where could be signed the new event\n",
                                                  l_event_hash_str);
                ret = -30;
            } else {
                size_t l_event_size = l_round_item->event_size;
                dap_chain_cs_dag_event_t *l_event = (dap_chain_cs_dag_event_t*)DAP_DUP_SIZE(l_round_item->event_n_signs, l_event_size);
                size_t l_event_size_new = dap_chain_cs_dag_event_sign_add(&l_event, l_event_size, l_poa_pvt->events_sign_cert->enc_key);

                if ( l_event_size_new ) {
                    dap_chain_hash_fast_t l_event_new_hash;
                    dap_chain_cs_dag_event_calc_hash(l_event, l_event_size_new, &l_event_new_hash);
                    char l_event_new_hash_hex_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                    dap_chain_hash_fast_to_str(&l_event_new_hash, l_event_new_hash_hex_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
                    char *l_event_new_hash_base58_str = dap_enc_base58_encode_hash_to_str(&l_event_new_hash);

                    bool l_event_is_ready = s_round_event_ready_minimum_check(l_dag, l_event, l_event_size_new,
                                                                        l_event_new_hash_hex_str);

                    if (dap_chain_cs_dag_event_gdb_set(l_dag, l_event_new_hash_hex_str, l_event, l_event_size_new, l_round_item)) {
                        if(!dap_strcmp(l_hash_out_type, "hex")) {
                            dap_cli_server_cmd_set_reply_text(a_str_reply,
                                    "Added new sign with cert \"%s\", event %s placed back in round.new\n",
                                    l_poa_pvt->events_sign_cert->name, l_event_new_hash_hex_str);
                        } else {
                            dap_cli_server_cmd_set_reply_text(a_str_reply,
                                    "Added new sign with cert \"%s\", event %s placed back in round.new\n",
                                    l_poa_pvt->events_sign_cert->name, l_event_new_hash_base58_str);
                        }
                        ret = 0;
                        if (l_event_is_ready && l_poa_pvt->auto_round_complete) // cs done (minimum signs & verify passed)
                            s_round_event_cs_done(l_dag, l_event->header.round_id);
                    } else {
                        if(!dap_strcmp(l_hash_out_type, "hex")) {
                            dap_cli_server_cmd_set_reply_text(a_str_reply,
                                    "GDB Error: Can't place event %s with new sign back in round.new\n",
                                    l_event_new_hash_hex_str);
                        }
                        else {
                            dap_cli_server_cmd_set_reply_text(a_str_reply,
                                    "GDB Error: Can't place event %s with new sign back in round.new\n",
                                    l_event_new_hash_base58_str);
                        }
                        ret=-31;

                    }
                    DAP_DELETE(l_event_new_hash_base58_str);
                } else {
                    dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                  "Can't sign event %s in round.new\n",
                                                  l_event_hash_str);
                }
                DAP_DELETE(l_event);
                DAP_DELETE(l_round_item);
            }
        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Command dag_poa requires subcommand 'sign'");
        }
    } else {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Command dag_poa requires subcommand 'event'");
    }

    DAP_DELETE(l_event_hash_hex_str);
    DAP_DELETE(l_event_hash_base58_str);

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
    dap_chain_cs_dag_t *l_dag = DAP_CHAIN_CS_DAG ( a_chain );
    dap_chain_cs_dag_poa_t *l_poa = DAP_NEW_Z ( dap_chain_cs_dag_poa_t);
    if (!l_poa) {
        log_it(L_CRITICAL, "Memory allocation error");
        return -1;
    }
    l_dag->_inheritor = l_poa;
    l_dag->callback_delete = s_callback_delete;
    l_dag->callback_cs_verify = s_callback_event_verify;
    l_dag->callback_cs_event_create = s_callback_event_create;
    l_dag->chain->callback_get_poa_certs = dap_chain_cs_dag_poa_get_auth_certs;
    l_poa->_pvt = DAP_NEW_Z ( dap_chain_cs_dag_poa_pvt_t );
    if (!l_poa->_pvt) {
        log_it(L_CRITICAL, "Memory allocation error");
        return -1;
    }
    dap_chain_cs_dag_poa_pvt_t *l_poa_pvt = PVT(l_poa);
    pthread_rwlock_init(&l_poa_pvt->rounds_rwlock, NULL);
    // PoA rounds
    l_poa_pvt->confirmations_timeout = dap_config_get_item_uint32_default(a_chain_cfg,"dag-poa","confirmations_timeout",600);
    l_poa_pvt->auto_confirmation = dap_config_get_item_bool_default(a_chain_cfg,"dag-poa","auto_confirmation",true);
    l_poa_pvt->auto_round_complete = dap_config_get_item_bool_default(a_chain_cfg,"dag-poa","auto_round_complete",true);
    l_poa_pvt->wait_sync_before_complete = dap_config_get_item_uint32_default(a_chain_cfg,"dag-poa","wait_sync_before_complete",180);
    l_poa_pvt->auth_certs_prefix = dap_strdup(dap_config_get_item_str(a_chain_cfg,"dag-poa","auth_certs_prefix"));
    if (l_poa_pvt->auth_certs_prefix) {
        l_poa_pvt->auth_certs_count = dap_config_get_item_uint16_default(a_chain_cfg,"dag-poa","auth_certs_number",0);
        l_poa_pvt->auth_certs_count_verify = dap_config_get_item_uint16_default(a_chain_cfg,"dag-poa","auth_certs_number_verify",0);
        if (l_poa_pvt->auth_certs_count && l_poa_pvt->auth_certs_count_verify) {
            l_poa_pvt->auth_certs = DAP_NEW_Z_SIZE ( dap_cert_t *, l_poa_pvt->auth_certs_count * sizeof(dap_cert_t *));
            if (!l_poa_pvt->auth_certs) {
                log_it(L_CRITICAL, "Memory allocation error");
                return -1;
            }
            char l_cert_name[512];
            for (size_t i = 0; i < l_poa_pvt->auth_certs_count ; i++ ){
                snprintf(l_cert_name,sizeof(l_cert_name),"%s.%zu",l_poa_pvt->auth_certs_prefix, i);
                if ((l_poa_pvt->auth_certs[i] = dap_cert_find_by_name( l_cert_name)) == NULL) {
                    snprintf(l_cert_name,sizeof(l_cert_name),"%s.%zu.pub",l_poa_pvt->auth_certs_prefix, i);
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
    l_dag->chain->callback_created = s_callback_created;

    if (!l_dag->is_add_directly && l_poa_pvt->auto_round_complete) {
        dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
        dap_chain_node_role_t l_role = dap_chain_net_get_role(l_net);
        if (l_role.enums == NODE_ROLE_ROOT_MASTER || l_role.enums == NODE_ROLE_ROOT) {
            if (!s_poa_round_timer) {
                s_poa_round_timer = dap_interval_timer_create(600 * 1000, s_poa_round_clean, a_chain);
                log_it(L_MSG, "DAG-PoA: Round timer is started");
            }
        }
    }

    return 0;
}

/**
 * @brief s_poa_round_check_callback_load_round
 * @param a_global_db_context
 * @param a_rc
 * @param a_group
 * @param a_key
 * @param a_values_total
 * @param a_values_shift
 * @param a_values_count
 * @param a_values
 * @param a_arg
 */
static void s_poa_round_check_callback_round_clean(dap_global_db_context_t *a_global_db_context,
                                                   int a_rc, const char *a_group,
                                                   const size_t a_values_total, const size_t a_values_count,
                                                   dap_global_db_obj_t *a_values, void *a_arg)
{
    dap_chain_cs_dag_t *l_dag = (dap_chain_cs_dag_t *)a_arg;
    dap_chain_cs_dag_poa_t *l_poa = DAP_CHAIN_CS_DAG_POA(l_dag);
    dap_chain_cs_dag_poa_pvt_t *l_poa_pvt = PVT(l_poa);

    if (a_values_count) {
        for (size_t i = 0; i < a_values_count; i++) {
            if (!strcmp(DAG_ROUND_CURRENT_KEY, a_values[i].key))
                continue;
            if (a_values[i].value_len <= sizeof(dap_chain_cs_dag_event_round_item_t) + sizeof(dap_chain_cs_dag_event_t)) {
                log_it(L_WARNING, "Too small round item in DAG PoA rounds GDB group");
                dap_global_db_del_unsafe(a_global_db_context, a_group, a_values[i].key);
                continue;
            }
            dap_chain_cs_dag_event_round_item_t *l_event_round_item = (dap_chain_cs_dag_event_round_item_t *)a_values[i].value;
            uint64_t l_time_diff = dap_nanotime_now() - l_event_round_item->round_info.ts_update;
            uint64_t l_timeuot = dap_nanotime_from_sec(l_poa_pvt->confirmations_timeout + l_poa_pvt->wait_sync_before_complete + 10);
            uint64_t l_round_id = ((dap_chain_cs_dag_event_t *)l_event_round_item->event_n_signs)->header.round_id;
            if (((int64_t)l_time_diff > 0 && l_time_diff > l_timeuot) || l_round_id <= l_dag->round_completed) {
                pthread_rwlock_rdlock(&l_poa_pvt->rounds_rwlock);
                struct round_timer_arg *l_arg = NULL;
                HASH_FIND(hh, l_poa_pvt->active_rounds, &l_round_id, sizeof(uint64_t), l_arg);
                pthread_rwlock_unlock(&l_poa_pvt->rounds_rwlock);
                if (l_arg) {
                    log_it(L_INFO, "Event %s is from currently active round [id %"DAP_UINT64_FORMAT_U"]", a_values[i].key, l_round_id);
                    continue;
                }
                dap_global_db_del_unsafe(a_global_db_context, a_group, a_values[i].key);
                log_it(L_DEBUG, "DAG-PoA: Remove event %s from round %"DAP_UINT64_FORMAT_U" %s.",
                       a_values[i].key, l_round_id, l_time_diff > l_timeuot ? "by timer" : "owing to round completion");
            }
        }
    }
}

/**
 * @brief Timer callback for round check
 * @param a_chain Chain object
 * @return Always true
 */
static void s_poa_round_clean(void *a_arg)
{
    dap_chain_cs_dag_t *l_dag = DAP_CHAIN_CS_DAG((dap_chain_t *)a_arg);
    dap_global_db_get_all(l_dag->gdb_group_events_round_new,0,s_poa_round_check_callback_round_clean, l_dag);
}

static bool s_round_event_ready_minimum_check(dap_chain_cs_dag_t *a_dag, dap_chain_cs_dag_event_t *a_event,
                                              size_t a_event_size, char * a_event_hash_hex_str)
{
    dap_chain_cs_dag_poa_t *l_poa = DAP_CHAIN_CS_DAG_POA(a_dag);
    dap_chain_cs_dag_poa_pvt_t *l_poa_pvt = PVT(l_poa);
    if ( a_event->header.signs_count < l_poa_pvt->auth_certs_count_verify) {
        log_it(L_INFO, "Round event %s hasn't got enough signs yet: %u < %u",
               a_event_hash_hex_str, a_event->header.signs_count, l_poa_pvt->auth_certs_count_verify);
        return false;
    }
    int l_ret_event_verify = s_callback_event_verify(a_dag, a_event, a_event_size);
    if (l_ret_event_verify == 0)
        return true;
    log_it(L_ERROR, "Round auto-complete error! Event %s is not passing consensus verification, ret code %d\n",
                          a_event_hash_hex_str, l_ret_event_verify );
    return false;
}

enum dap_chain_poa_round_filter_stage {
    DAP_CHAIN_POA_ROUND_FILTER_STAGE_START,
    DAP_CHAIN_POA_ROUND_FILTER_STAGE_SIGNS,
    DAP_CHAIN_POA_ROUND_FILTER_STAGE_TS,
    DAP_CHAIN_POA_ROUND_FILTER_STAGE_MEM,
    DAP_CHAIN_POA_ROUND_FILTER_STAGE_MAX
};

#define DAP_CHAIN_POA_ROUND_FILTER_MEM_SIZE 1024

static void s_event_get_unique_mem_region(dap_chain_cs_dag_event_round_item_t *a_round_item, byte_t *a_mem_region)
{
    memset(a_mem_region, 0, DAP_CHAIN_POA_ROUND_FILTER_MEM_SIZE);
    dap_chain_cs_dag_event_t *l_event = (dap_chain_cs_dag_event_t *)a_round_item->event_n_signs;
    for (int n = 0; n < l_event->header.signs_count; n++) {
        dap_sign_t *l_sign = dap_chain_cs_dag_event_get_sign(l_event, a_round_item->event_size, n);
        size_t l_sign_size = 0;
        byte_t *l_sign_mem = dap_sign_get_sign(l_sign, &l_sign_size);
        size_t l_mem_size = MIN(l_sign_size, DAP_CHAIN_POA_ROUND_FILTER_MEM_SIZE);
        for (size_t i = 0; i < l_mem_size; i++)
            a_mem_region[i] ^= l_sign_mem[i];
    }
}

static dap_chain_cs_dag_event_round_item_t *s_round_event_choose_dup(dap_list_t *a_dups, uint16_t a_max_signs_counts)
{
    dap_chain_cs_dag_event_round_item_t *l_round_item;
    dap_chain_cs_dag_event_t *l_event;
    if (!a_dups)
        return NULL;
    dap_list_t *l_dups = dap_list_copy(a_dups);
    uint64_t l_min_ts_update = (uint64_t)-1;
    byte_t l_event_mem_region[DAP_CHAIN_POA_ROUND_FILTER_MEM_SIZE] = { },
           l_winner_mem_region[DAP_CHAIN_POA_ROUND_FILTER_MEM_SIZE] = { };
    enum dap_chain_poa_round_filter_stage l_stage = DAP_CHAIN_POA_ROUND_FILTER_STAGE_START;
    while (l_stage++ < DAP_CHAIN_POA_ROUND_FILTER_STAGE_MAX) {
        dap_list_t *it, *tmp;
        for (it = l_dups, tmp = l_dups ? l_dups->next : NULL; it; it = tmp, tmp = tmp ? tmp->next : NULL) {
            l_round_item = (dap_chain_cs_dag_event_round_item_t *)it->data;
            l_event = (dap_chain_cs_dag_event_t *)l_round_item->event_n_signs;
            switch (l_stage) {
            case DAP_CHAIN_POA_ROUND_FILTER_STAGE_SIGNS:
                if (l_event->header.signs_count != a_max_signs_counts)
                    l_dups = dap_list_remove_link(l_dups, it);
                else if (l_round_item->round_info.ts_update < l_min_ts_update)
                    l_min_ts_update = l_round_item->round_info.ts_update;
                break;
            case DAP_CHAIN_POA_ROUND_FILTER_STAGE_TS:
                if (l_round_item->round_info.ts_update != l_min_ts_update)
                    l_dups = dap_list_remove_link(l_dups, it);
                else {
                    s_event_get_unique_mem_region(l_round_item, l_event_mem_region);
                    if (memcmp(l_winner_mem_region, l_event_mem_region, DAP_CHAIN_POA_ROUND_FILTER_MEM_SIZE))
                        memcpy(l_winner_mem_region, l_event_mem_region, DAP_CHAIN_POA_ROUND_FILTER_MEM_SIZE);
                }
                break;
            case DAP_CHAIN_POA_ROUND_FILTER_STAGE_MEM:
                s_event_get_unique_mem_region(l_round_item, l_event_mem_region);
                if (memcmp(l_winner_mem_region, l_event_mem_region, DAP_CHAIN_POA_ROUND_FILTER_MEM_SIZE))
                    l_dups = dap_list_remove_link(l_dups, it);
            default: break;
            }
        }
        unsigned int l_dups_count = dap_list_length(l_dups);
        if (!l_dups_count)
            return NULL;
        if (l_dups_count == 1) {
            l_round_item = (dap_chain_cs_dag_event_round_item_t *)l_dups->data;
            DAP_DELETE(l_dups);
            return l_round_item;
        }
    }
    log_it(L_ERROR, "POA rounds filtering: Can't choose only one item with current filters, need to increase it's number");
    l_round_item = (dap_chain_cs_dag_event_round_item_t *)l_dups->data;
    dap_list_free(l_dups);
    return l_round_item;
}

/**
 * @brief s_callback_round_event_to_chain_callback_get_round_item
 * @param a_global_db_context
 * @param a_rc
 * @param a_group
 * @param a_key
 * @param a_value
 * @param a_value_size
 * @param a_value_ts
 * @param a_is_pinned
 * @param a_arg
 */
static void s_callback_round_event_to_chain_callback_get_round_item(dap_global_db_context_t *a_global_db_context,
                                                                    int a_rc, const char *a_group,
                                                                    const size_t a_values_total, const size_t a_values_count,
                                                                    dap_store_obj_t *a_values, void *a_arg)
{
    if (a_rc != DAP_GLOBAL_DB_RC_SUCCESS)
        return;
    struct round_timer_arg *l_arg = (struct round_timer_arg *)a_arg;
    dap_chain_cs_dag_t *l_dag = l_arg->dag;
    uint64_t l_round_id = l_arg->round_id;
    dap_chain_cs_dag_poa_pvt_t *l_poa_pvt = PVT(DAP_CHAIN_CS_DAG_POA(l_dag));
    pthread_rwlock_wrlock(&l_poa_pvt->rounds_rwlock);
    HASH_DEL(l_poa_pvt->active_rounds, l_arg);
    pthread_rwlock_unlock(&l_poa_pvt->rounds_rwlock);
    DAP_DELETE(a_arg);
    size_t l_events_round_size = a_values_count;
    dap_store_obj_t *l_events_round = a_values;
    uint16_t l_max_signs_count = 0;
    dap_list_t *l_dups_list = NULL;
    for (size_t l_index = 0; l_index < l_events_round_size; l_index++) {
        dap_chain_cs_dag_event_round_item_t *l_round_item = (dap_chain_cs_dag_event_round_item_t *)l_events_round[l_index].value;
        dap_chain_cs_dag_event_t *l_event = (dap_chain_cs_dag_event_t *)l_round_item->event_n_signs;
        if (l_event->header.round_id == l_round_id &&
                l_round_item->round_info.reject_count < l_poa_pvt->auth_certs_count_verify) {
            l_dups_list = dap_list_append(l_dups_list, l_round_item);
            if (l_event->header.signs_count > l_max_signs_count)
                l_max_signs_count = l_event->header.signs_count;
        }
    }
    dap_chain_cs_dag_event_round_item_t *l_chosen_item = s_round_event_choose_dup(l_dups_list, l_max_signs_count);
    if (l_chosen_item) {
        size_t l_event_size = l_chosen_item->event_size;
        dap_chain_cs_dag_event_t *l_new_atom = (dap_chain_cs_dag_event_t *)DAP_DUP_SIZE(l_chosen_item->event_n_signs, l_event_size);
        char *l_event_hash_hex_str;
        dap_get_data_hash_str_static(l_new_atom, l_event_size, l_event_hash_hex_str);
        dap_chain_datum_t *l_datum = dap_chain_cs_dag_event_get_datum(l_new_atom, l_event_size);
        l_dag->round_completed = MAX(l_new_atom->header.round_id, l_dag->round_current);
        int l_verify_datum = dap_chain_net_verify_datum_for_add(l_dag->chain, l_datum, &l_chosen_item->round_info.datum_hash);
        if (!l_verify_datum) {
            dap_chain_atom_verify_res_t l_res = l_dag->chain->callback_atom_add(l_dag->chain, l_new_atom, l_event_size);
            if (l_res == ATOM_ACCEPT) {
                dap_chain_atom_save(l_dag->chain, (dap_chain_atom_ptr_t)l_new_atom, l_event_size, l_dag->chain->cells->id);
                s_poa_round_clean(l_dag->chain);
            } else if (l_res != ATOM_MOVE_TO_THRESHOLD)
                DAP_DELETE(l_new_atom);
            log_it(L_INFO, "Event %s from round %"DAP_UINT64_FORMAT_U" %s",
                   l_event_hash_hex_str, l_round_id, dap_chain_atom_verify_res_str[l_res]);
        } else {
            DAP_DELETE(l_new_atom);
            char l_datum_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(&l_chosen_item->round_info.datum_hash, l_datum_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
            log_it(L_INFO, "Event %s from round %"DAP_UINT64_FORMAT_U" not added into chain, because the inner datum %s doesn't pass verification (%s)",
                   l_event_hash_hex_str, l_round_id, l_datum_hash_str, dap_chain_net_verify_datum_err_code_to_str(l_datum, l_verify_datum));
        }
    } else { /* !l_chosen_item */
        l_dag->round_completed = l_dag->round_current;
        log_it(L_WARNING, "No candidates for round id %"DAP_UINT64_FORMAT_U, l_round_id);

    }
    dap_list_free(l_dups_list);
}

/**
 * @brief s_callback_round_event_to_chain
 * @param a_callback_arg
 * @return
 */
static bool s_callback_round_event_to_chain(struct round_timer_arg *a_callback_arg)
{
    dap_chain_cs_dag_t * l_dag = a_callback_arg->dag;
    char * l_gdb_group_events = l_dag->gdb_group_events_round_new;
    dap_global_db_get_all_raw(l_gdb_group_events, 0, 0, s_callback_round_event_to_chain_callback_get_round_item, a_callback_arg);
    return false;
}

static void s_round_event_cs_done(dap_chain_cs_dag_t * a_dag, uint64_t a_round_id)
{
    dap_chain_cs_dag_poa_t *l_poa = DAP_CHAIN_CS_DAG_POA(a_dag);
    dap_chain_cs_dag_poa_pvt_t *l_poa_pvt = PVT(l_poa);
    struct round_timer_arg *l_callback_arg = NULL;
    pthread_rwlock_wrlock(&l_poa_pvt->rounds_rwlock);
    HASH_FIND(hh, l_poa_pvt->active_rounds, &a_round_id, sizeof(uint64_t), l_callback_arg);
    if (!l_callback_arg) {
        l_callback_arg = DAP_NEW_Z(struct round_timer_arg);
        if (!l_callback_arg) {
            pthread_rwlock_unlock(&l_poa_pvt->rounds_rwlock);
            log_it(L_CRITICAL, "Memory allocation error");
            return;
        }
        l_callback_arg->dag = a_dag;
        l_callback_arg->round_id = a_round_id;
        HASH_ADD(hh, l_poa_pvt->active_rounds, round_id, sizeof(uint64_t), l_callback_arg);
        // Placement into chain by confirmation timer
        if (!dap_timerfd_start(PVT(l_poa)->confirmations_timeout * 1000, (dap_timerfd_callback_t)s_callback_round_event_to_chain, l_callback_arg)) {
            HASH_DEL(l_poa_pvt->active_rounds, l_callback_arg);
            pthread_rwlock_unlock(&l_poa_pvt->rounds_rwlock);
            DAP_DELETE(l_callback_arg);
            log_it(L_ERROR,"Can't run timer for round ID %"DAP_UINT64_FORMAT_U, a_round_id);
            return;
        }
        log_it(L_NOTICE,"Run timer for %d sec for round ID %"DAP_UINT64_FORMAT_U, PVT(l_poa)->confirmations_timeout, a_round_id);
    }
    pthread_rwlock_unlock(&l_poa_pvt->rounds_rwlock);
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

    const char * l_events_sign_cert = NULL;
    if ( ( l_events_sign_cert = dap_config_get_item_str(a_chain_net_cfg,"dag-poa","events-sign-cert") ) != NULL ) {
        if ( ( PVT(l_poa)->events_sign_cert = dap_cert_find_by_name(l_events_sign_cert)) == NULL ){
            log_it(L_ERROR,"Can't load events sign certificate, name \"%s\" is wrong",l_events_sign_cert);
        }else
            log_it(L_NOTICE,"Loaded \"%s\" certificate to sign poa event", l_events_sign_cert);

    }
    dap_chain_net_t *l_cur_net = dap_chain_net_by_name(a_chain->net_name);
    dap_chain_node_role_t l_role = dap_chain_net_get_role(l_cur_net);
    if (l_role.enums == NODE_ROLE_ROOT_MASTER || l_role.enums == NODE_ROLE_ROOT) {
        l_dag->callback_cs_event_round_sync = s_callback_event_round_sync;
        l_dag->round_completed = l_dag->round_current++;
        log_it(L_MSG, "Round complete ID %"DAP_UINT64_FORMAT_U", current ID %"DAP_UINT64_FORMAT_U, l_dag->round_completed, l_dag->round_current);
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
    dap_interval_timer_delete(s_poa_round_timer);
    dap_chain_cs_dag_poa_t * l_poa = DAP_CHAIN_CS_DAG_POA ( a_dag );

    if ( l_poa->_pvt ) {
        dap_chain_cs_dag_poa_pvt_t * l_poa_pvt = PVT ( l_poa );

        if ( l_poa_pvt->auth_certs )
            DAP_DELETE ( l_poa_pvt->auth_certs);

        if ( l_poa_pvt->auth_certs_prefix )
            free ( l_poa_pvt->auth_certs_prefix );

        if ( l_poa_pvt->callback_pre_sign )
            DAP_DELETE( l_poa_pvt->callback_pre_sign );
        pthread_rwlock_destroy(&l_poa_pvt->rounds_rwlock);
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
    dap_chain_cs_dag_poa_t * l_poa = DAP_CHAIN_CS_DAG_POA(a_dag);
    if ( PVT(l_poa)->events_sign_cert == NULL){
        log_it(L_ERROR, "Can't sign event with events_sign_cert in [dag-poa] section");
        return  NULL;
    }
    if ( s_seed_mode || (a_hashes && a_hashes_count) ){
        if ( !PVT(l_poa)->callback_pre_sign || !PVT(l_poa)->callback_pre_sign->callback) {
            dap_chain_cs_dag_event_t * l_event = dap_chain_cs_dag_event_new(a_dag->chain->id, a_dag->chain->cells->id, a_dag->round_current,
                                                                            a_datum, PVT(l_poa)->events_sign_cert->enc_key,
                                                                            a_hashes, a_hashes_count, a_event_size);
            return l_event;
        } else {
            dap_chain_cs_dag_event_t *l_event = dap_chain_cs_dag_event_new(a_dag->chain->id, a_dag->chain->cells->id, a_dag->round_current,
                                                                           a_datum, NULL,
                                                                           a_hashes, a_hashes_count, a_event_size);
            int ret = PVT(l_poa)->callback_pre_sign->callback(a_dag->chain, l_event, *a_event_size, PVT(l_poa)->callback_pre_sign->arg);
            if (ret) {
                DAP_DELETE(l_event);
                return NULL;
            }
            *a_event_size = dap_chain_cs_dag_event_sign_add(&l_event, *a_event_size, PVT(l_poa)->events_sign_cert->enc_key);
            return l_event;
        }
    }
    return NULL;
}

static int s_callback_event_round_sync(dap_chain_cs_dag_t * a_dag, const char a_op_code, const char *a_group,
                                        const char *a_key, const void *a_value, const size_t a_value_size)
{
    if (a_op_code != DAP_DB$K_OPTYPE_ADD || !a_key || !a_value || !a_value_size)
        return 0;

    dap_chain_cs_dag_poa_t * l_poa = DAP_CHAIN_CS_DAG_POA(a_dag);
    dap_chain_cs_dag_poa_pvt_t *l_poa_pvt = PVT(l_poa);

    if (!l_poa_pvt->events_sign_cert)
        return -1;

    if (!l_poa_pvt->auto_confirmation)
        return 0;

    dap_chain_cs_dag_event_round_item_t *l_round_item = (dap_chain_cs_dag_event_round_item_t *)a_value;
    size_t l_event_size = l_round_item->event_size;
    dap_chain_cs_dag_event_t *l_event = (dap_chain_cs_dag_event_t*)DAP_DUP_SIZE(l_round_item->event_n_signs, l_event_size);
    if (!l_event) {
        log_it(L_CRITICAL, "Memory allocation failed");
        return -1;
    }
    if (l_event->header.round_id < a_dag->round_completed) {
        struct round_timer_arg *l_round_active;
        uint64_t l_round_id = l_event->header.round_id;
        pthread_rwlock_wrlock(&l_poa_pvt->rounds_rwlock);
        HASH_FIND(hh, l_poa_pvt->active_rounds, &l_round_id, sizeof(uint64_t), l_round_active);
        pthread_rwlock_unlock(&l_poa_pvt->rounds_rwlock);
        if (!l_round_active) {
            log_it(L_DEBUG, "DAG event came from too old round [last complete id %"DAP_UINT64_FORMAT_U" > %"DAP_UINT64_FORMAT_U"], skip it",
                   a_dag->round_completed, l_event->header.round_id);
            DAP_DELETE(l_event);
            return -2;
        }
    }
    if (dap_chain_cs_dag_event_sign_exists(l_event, l_event_size, l_poa_pvt->events_sign_cert->enc_key)
            || dap_chain_cs_dag_event_round_sign_exists(l_round_item, l_poa_pvt->events_sign_cert->enc_key)) {
        // if my sign exists
        if (l_poa_pvt->auto_round_complete &&
                s_round_event_ready_minimum_check(a_dag, l_event, l_event_size, (char *)a_key))
            // cs done (minimum signs & verify passed)
            s_round_event_cs_done(a_dag, l_event->header.round_id);
        DAP_DELETE(l_event);
        return 0;
    }

    size_t l_event_size_new = 0;
    int ret = 0;
    if (l_event->header.round_id > a_dag->round_current) {
        log_it(L_DEBUG, "Refresh current round ID [%lu -> %lu]", a_dag->round_current, l_event->header.round_id);
        a_dag->round_current = l_event->header.round_id;
    }
    if (!l_poa_pvt->callback_pre_sign || !l_poa_pvt->callback_pre_sign->callback ||
             !(ret = l_poa_pvt->callback_pre_sign->callback(a_dag->chain, l_event, l_event_size,
                                                      l_poa_pvt->callback_pre_sign->arg))) {
        l_event_size_new = dap_chain_cs_dag_event_sign_add(&l_event, l_event_size, l_poa_pvt->events_sign_cert->enc_key);
        //char *l_event_new_hash_hex_str;
        //dap_get_data_hash_str_static(l_event, l_event_size_new, l_event_new_hash_hex_str);
        dap_chain_cs_dag_event_gdb_set(a_dag, /*l_event_new_hash_hex_str*/ (char*)a_key, l_event, l_event_size_new, l_round_item);
    } else { // set sign for reject
        l_round_item = DAP_DUP_SIZE(a_value, a_value_size);
        if (dap_chain_cs_dag_event_round_sign_add(&l_round_item, a_value_size, l_poa_pvt->events_sign_cert->enc_key)) {
            log_it(L_NOTICE,"Can't sign event %s, because sign rejected by pre_sign callback, ret code=%d", a_key, ret);
            l_round_item->round_info.reject_count++;
            dap_chain_cs_dag_event_gdb_set(a_dag, (char *)a_key, l_event, l_event_size, l_round_item);
        }
        DAP_DELETE(l_round_item);
    }
    DAP_DELETE(l_event);
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
static int s_callback_event_verify(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_event, size_t a_event_size)
{

    dap_chain_cs_dag_poa_pvt_t * l_poa_pvt = PVT ( DAP_CHAIN_CS_DAG_POA( a_dag ) );
    size_t l_offset_from_beginning = dap_chain_cs_dag_event_calc_size_excl_signs(a_event, a_event_size);
    if( l_offset_from_beginning >= a_event_size){
        log_it(L_WARNING,"Incorrect size with event %p: caled size excl signs %zd is bigger or equal then event size %zd",
               a_event, l_offset_from_beginning, a_event_size);
        return -7; // Incorrest size
    }
    uint16_t l_certs_count_verify = l_poa_pvt->auth_certs_count_verify;
    if (a_event->header.signs_count >= l_certs_count_verify) {
        size_t l_signs_count = 0;
        dap_sign_t **l_signs = dap_sign_get_unique_signs(((uint8_t*)a_event)+l_offset_from_beginning,
                                                a_event_size-l_offset_from_beginning, &l_signs_count);

        if (!l_signs_count){
            log_it(L_ERROR, "No any signatures at all for event");
            DAP_DELETE(l_signs);
            return -2;
        }

        if ( l_signs_count < l_certs_count_verify ) {
            log_it(L_ERROR, "Corrupted event: not enough signs: %zu of %hu", l_signs_count, l_certs_count_verify);
            DAP_DELETE(l_signs);
            return -1;
        }

        uint16_t l_signs_verified_count = 0;
        int l_ret = 0;
        uint16_t l_event_signs_count = a_event->header.signs_count;
        for (size_t i=0; i<l_signs_count; i++) {
            dap_sign_t *l_sign = (dap_sign_t *)l_signs[i];
            if (!dap_sign_verify_size(l_sign, a_event_size - l_offset_from_beginning)) {
                log_it(L_WARNING,"Incorrect size with event %p", a_event);
                l_ret = -3;
                break;
            }

            // Compare signature with auth_certs
            a_event->header.signs_count = i;
            for (uint16_t j = 0; j < l_poa_pvt->auth_certs_count; j++) {
                if (dap_cert_compare_with_sign( l_poa_pvt->auth_certs[j], l_sign) == 0
                            && dap_sign_verify(l_sign, a_event, l_offset_from_beginning) == 1 ){
                    l_signs_verified_count++;
                    break;
                }
            }
        }
        a_event->header.signs_count = l_event_signs_count;
        DAP_DELETE(l_signs);
        if (l_signs_verified_count < l_certs_count_verify) {
            dap_hash_fast_t l_event_hash;
            dap_hash_fast(a_event, a_event_size, &l_event_hash);
            char l_event_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(&l_event_hash, l_event_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
            log_it(L_ERROR, "Corrupted event %s, not enough signs %hu from %hu",
                            l_event_hash_str, l_signs_verified_count, l_certs_count_verify);
            return l_ret ? l_ret : -4;
        }
        return 0;
    }
    else if (a_event->header.hash_count == 0){
        dap_chain_hash_fast_t l_event_hash;
        dap_chain_cs_dag_event_calc_hash(a_event,a_event_size, &l_event_hash);
        if ( memcmp( &l_event_hash, &a_dag->static_genesis_event_hash, sizeof(l_event_hash) ) == 0 ){
            return 0;
        }else{
            log_it(L_WARNING,"Wrong genesis event %p: hash is not equels to what in config", a_event);
            return -20; // Wrong signatures number
        }
    }
    else{
        log_it(L_WARNING,"Wrong signatures number with event %p", a_event);
        return -2; // Wrong signatures number
    }
}

dap_list_t *dap_chain_cs_dag_poa_get_auth_certs(dap_chain_t *a_chain, size_t *a_auth_certs_count, uint16_t *a_count_verify)
{
    dap_chain_pvt_t *l_chain_pvt = DAP_CHAIN_PVT(a_chain);
    if (strcmp(l_chain_pvt->cs_name, "dag_poa"))
        return NULL;

    dap_chain_cs_dag_poa_pvt_t *l_poa_pvt = PVT(DAP_CHAIN_CS_DAG_POA(DAP_CHAIN_CS_DAG(a_chain)));
    if (a_auth_certs_count)
        *a_auth_certs_count = l_poa_pvt->auth_certs_count;

    if (a_count_verify)
        *a_count_verify = l_poa_pvt->auth_certs_count_verify;


    dap_list_t *l_keys_list = NULL;
    for(size_t i = 0; i < l_poa_pvt->auth_certs_count; i++)
    {
        dap_pkey_t *l_pkey = dap_cert_to_pkey(l_poa_pvt->auth_certs[i]);
        l_keys_list = dap_list_append(l_keys_list, l_pkey);
    }

    return l_keys_list;
}
