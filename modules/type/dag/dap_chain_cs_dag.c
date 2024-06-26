/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Demlabs Application Protocol) the open source project

    DAP (Demlabs Application Protocol) is free software: you can redistribute it and/or modify
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
#include <time.h>
#include <pthread.h>
#include "errno.h"
#include "uthash.h"
#include "utlist.h"

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <time.h>
#include <pthread.h>
#endif

#include "dap_cert.h"
#include "dap_common.h"
#include "dap_enc_base58.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_hash.h"
#include "dap_chain_datum.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_global_db.h"
#include "dap_global_db_driver.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_cell.h"
#include "dap_chain_net.h"
#include "dap_chain_ledger.h"

#define LOG_TAG "dap_chain_cs_dag"

typedef struct dap_chain_cs_dag_event_item {
    dap_chain_hash_fast_t hash;
    dap_chain_hash_fast_t datum_hash;
    dap_nanotime_t ts_added;
    dap_chain_cs_dag_event_t *event;
    size_t event_size;
    int ret_code;
    char *mapped_region;
    UT_hash_handle hh, hh_select, hh_datums;
} dap_chain_cs_dag_event_item_t;

typedef struct dap_chain_cs_dag_blocked {
    dap_chain_hash_fast_t hash;
    UT_hash_handle hh;
}dap_chain_cs_dag_blocked_t;


typedef struct dap_chain_cs_dag_pvt {
    pthread_mutex_t events_mutex;
    dap_chain_cs_dag_event_item_t * events;
    dap_chain_cs_dag_event_item_t * datums;
    dap_chain_cs_dag_event_item_t * events_treshold;
    dap_chain_cs_dag_event_item_t * events_treshold_conflicted;
    dap_chain_cs_dag_event_item_t * events_lasts_unlinked;
    dap_chain_cs_dag_blocked_t *removed_events_from_treshold;
    dap_interval_timer_t mempool_timer;
    dap_interval_timer_t treshold_fee_timer;
    size_t tx_count;
} dap_chain_cs_dag_pvt_t;

#define PVT(a) ((dap_chain_cs_dag_pvt_t *) a->_pvt )

static void s_dap_chain_cs_dag_purge(dap_chain_t *a_chain);
static void s_dap_chain_cs_dag_threshold_free(dap_chain_cs_dag_t *a_dag);
static dap_chain_cs_dag_event_item_t *s_dag_proc_treshold(dap_chain_cs_dag_t *a_dag);

// Atomic element organization callbacks
static dap_chain_atom_verify_res_t s_chain_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t , size_t);                      //    Accept new event in dag
static dap_chain_atom_ptr_t s_chain_callback_atom_add_from_treshold(dap_chain_t * a_chain, size_t *a_event_size_out);                    //    Accept new event in dag from treshold
static dap_chain_atom_verify_res_t s_chain_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_ptr_t , size_t);                   //    Verify new event in dag
static size_t s_chain_callback_atom_get_static_hdr_size(void);                               //    Get dag event header size

static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create(dap_chain_t * a_chain, dap_chain_cell_id_t a_cell_id, bool a_with_treshold);
static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create_from(dap_chain_t *  ,
                                                                     dap_chain_atom_ptr_t , size_t);


static dap_chain_atom_ptr_t s_chain_callback_atom_iter_find_by_hash(dap_chain_atom_iter_t * a_atom_iter ,
                                                                       dap_chain_hash_fast_t * a_atom_hash, size_t * a_atom_size);
static dap_chain_datum_t *s_chain_callback_atom_find_by_datum_hash(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_datum_hash,
                                                                   dap_chain_hash_fast_t *a_event_hash, int *a_ret_code);
static dap_chain_datum_t** s_chain_callback_atom_get_datum(dap_chain_atom_ptr_t a_event, size_t a_atom_size, size_t *a_datums_count);
static dap_time_t s_chain_callback_atom_get_timestamp(dap_chain_atom_ptr_t a_atom) { return ((dap_chain_cs_dag_event_t *)a_atom)->header.ts_created; }
//    Get event(s) from dag
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_first( dap_chain_atom_iter_t * a_atom_iter, size_t *a_atom_size ); //    Get the fisrt event from dag
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_next( dap_chain_atom_iter_t * a_atom_iter,size_t *a_atom_size );  //    Get the next event from dag
static dap_chain_atom_ptr_t *s_chain_callback_atom_iter_get_links( dap_chain_atom_iter_t * a_atom_iter , size_t *a_links_size,
                                                                  size_t ** a_links_size_ptr );  //    Get list of linked events
static dap_chain_atom_ptr_t *s_chain_callback_atom_iter_get_lasts( dap_chain_atom_iter_t * a_atom_iter ,size_t *a_links_size,
                                                                  size_t ** a_lasts_size_ptr );  //    Get list of linked events

// Delete iterator
static void s_chain_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter );                  //    Get the fisrt event from dag

static bool s_chain_callback_datums_pool_proc(dap_chain_t * a_chain, dap_chain_datum_t *a_datum);
static size_t s_callback_add_datums(dap_chain_t *a_chain, dap_chain_datum_t **a_datums, size_t a_datums_count);

// Datum ops
static dap_chain_datum_iter_t *s_chain_callback_datum_iter_create(dap_chain_t *a_chain);
static void s_chain_callback_datum_iter_delete(dap_chain_datum_iter_t *a_datum_iter);
static dap_chain_datum_t *s_chain_callback_datum_iter_get_first(dap_chain_datum_iter_t *a_datum_iter); // Get the fisrt datum from dag
static dap_chain_datum_t *s_chain_callback_datum_iter_get_next(dap_chain_datum_iter_t *a_datum_iter); // Get the next datum from dag

static int s_cli_dag(int argc, char ** argv, void **reply);
void s_dag_events_lasts_process_new_last_event(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_item_t * a_event_item);

static size_t s_dap_chain_callback_get_count_tx(dap_chain_t *a_chain);
static dap_list_t *s_dap_chain_callback_get_txs(dap_chain_t *a_chain, size_t a_count, size_t a_page, bool a_reverse);

static size_t s_dap_chain_callback_get_count_atom(dap_chain_t *a_chain);
static dap_list_t *s_callback_get_atoms(dap_chain_t *a_chain, size_t a_count, size_t a_page, bool a_reverse);

static bool s_seed_mode = false, s_debug_more = false, s_threshold_enabled = false;

/**
 * @brief dap_chain_cs_dag_init
 * @return always 0
 */
int dap_chain_cs_dag_init()
{
    srand((unsigned int) time(NULL));
    dap_chain_cs_type_add( "dag", dap_chain_cs_dag_new );
    s_seed_mode         = dap_config_get_item_bool_default(g_config, "general", "seed_mode",        false);
    s_debug_more        = dap_config_get_item_bool_default(g_config, "dag",     "debug_more",       false);
    s_threshold_enabled = dap_config_get_item_bool_default(g_config, "dag",     "threshold_enabled",false);
    debug_if(s_debug_more, L_DEBUG, "Thresholding %s", s_threshold_enabled ? "enabled" : "disabled");
    dap_cli_server_cmd_add ("dag", s_cli_dag, "DAG commands",
        "dag event create -net <net_name> -chain <chain_name> -datum <datum_hash> [-H {hex | base58(default)}]\n"
            "\tCreate event from datum mempool element\n\n"
        "dag event cancel -net <net_name> -chain <chain_name> -event <event_hash>\n"
            "\tRemove event from forming new round and put back its datum to mempool\n\n"
        "dag event sign -net <net_name> -chain <chain_name> -event <event_hash>\n"
            "\tAdd sign to event <event hash> in round.new. Hash doesn't include other signs so event hash\n"
            "\tdoesn't changes after sign add to event. \n\n"
        "dag event dump -net <net_name> -chain <chain_name> -event <event_hash> -from {events | events_lasts | threshold | round.new  | round.<round_id_in_hex>} [-H {hex | base58(default)}]\n"
            "\tDump event info\n\n"
        "dag event list -net <net_name> -chain <chain_name> -from {events | events_lasts | threshold | round.new | round.<round_id_in_hex>}\n\n"
            "\tShow event list \n\n"
        "dag event count -net <net_name> -chain <chain_name>\n"
            "\tShow count event \n\n"
        "dag round complete -net <net_name> -chain <chain_name> \n"
                                        "\tComplete the current new round, verify it and if everything is ok - publish new events in chain\n"
        "dag round find -net <net_name> -chain <chain_name> -datum <datum_hash> \n"
            "\tSearches for rounds that have events that contain the specified datum.\n\n"
                                        );
    log_it(L_NOTICE,"Initialized DAG chain items organization class");
    return 0;
}

/**
 * @brief dap_chain_cs_dag_deinit
 */
void dap_chain_cs_dag_deinit(void)
{

}

static void s_history_callback_round_notify(dap_global_db_context_t *a_context, dap_store_obj_t *a_obj, void *a_arg)
{
    dap_chain_cs_dag_t *l_dag = (dap_chain_cs_dag_t *)a_arg;
    assert(l_dag);
    dap_chain_net_t *l_net = dap_chain_net_by_id(l_dag->chain->net_id);
    debug_if(s_debug_more, L_DEBUG, "%s.%s: op_code='%c' group=\"%s\" key=\"%s\" value_size=%zu",
        l_net->pub.name, l_dag->chain->name, a_obj->type, a_obj->group, a_obj->key, a_obj->value_len);
    if (a_obj->type == DAP_DB$K_OPTYPE_ADD && l_dag->callback_cs_event_round_sync) {
        if (!l_dag->broadcast_disable)
            dap_chain_cs_dag_event_broadcast(l_dag, a_obj, a_context);
        if (dap_strcmp(a_obj->key, DAG_ROUND_CURRENT_KEY)) {  // check key for round increment, if no than process event
            l_dag->callback_cs_event_round_sync(l_dag, a_obj->type, a_obj->group, a_obj->key, a_obj->value, a_obj->value_len);
        } else {
            log_it(L_INFO, "Global round ID: %lu", *(uint64_t*)a_obj->value);
        }
    }
}

static void s_dag_rounds_events_iter(dap_global_db_context_t *a_context,
                                     int a_rc, const char *a_group,
                                     const size_t a_values_current, const size_t a_values_count,
                                     dap_store_obj_t *a_values, void *a_arg)
{
    UNUSED(a_group);
    UNUSED(a_values_current);
    if (a_rc != DAP_GLOBAL_DB_RC_SUCCESS)
        return;
    for (size_t i = 0; i < a_values_count; i++) {
        dap_store_obj_t *l_obj_cur = a_values + i;
        l_obj_cur->type = DAP_DB$K_OPTYPE_ADD;
        s_history_callback_round_notify(a_context, a_values + i, a_arg);
    }
}

static void s_timer_process_callback(void *a_arg)
{
    dap_chain_node_mempool_process_all((dap_chain_t *)a_arg, false);
}

/**
 * @brief dap_chain_cs_dag_new
 * @param a_chain
 * @param a_chain_cfg
 */
int dap_chain_cs_dag_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg)
{
    dap_chain_cs_dag_t * l_dag = DAP_NEW_Z(dap_chain_cs_dag_t);
    if (!l_dag){
        log_it(L_CRITICAL, "Memory allocation error");
        return -1;
    }
    l_dag->_pvt = DAP_NEW_Z(dap_chain_cs_dag_pvt_t);
    if (!l_dag->_pvt){
        log_it(L_CRITICAL, "Memory allocation error");
        DAP_DELETE(l_dag);
        return -1;
    }
    l_dag->chain = a_chain;

    pthread_mutexattr_t l_mutex_attr;
    pthread_mutexattr_init(&l_mutex_attr);
    pthread_mutexattr_settype(&l_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&PVT(l_dag)->events_mutex, &l_mutex_attr);
    pthread_mutexattr_destroy(&l_mutex_attr);

    a_chain->callback_delete = dap_chain_cs_dag_delete;
    a_chain->callback_purge = s_dap_chain_cs_dag_purge;

    // Atom element callbacks
    a_chain->callback_atom_add = s_chain_callback_atom_add ;  // Accept new element in chain
    a_chain->callback_atom_add_from_treshold = s_chain_callback_atom_add_from_treshold;  // Accept new elements in chain from treshold
    a_chain->callback_atom_verify = s_chain_callback_atom_verify ;  // Verify new element in chain
    a_chain->callback_atom_get_hdr_static_size = s_chain_callback_atom_get_static_hdr_size; // Get dag event hdr size

    a_chain->callback_atom_iter_create = s_chain_callback_atom_iter_create;
    a_chain->callback_atom_iter_create_from = s_chain_callback_atom_iter_create_from;
    a_chain->callback_atom_iter_delete = s_chain_callback_atom_iter_delete;
    // Linear pass through
    a_chain->callback_atom_iter_get_first = s_chain_callback_atom_iter_get_first; // Get the fisrt element from chain
    a_chain->callback_atom_iter_get_next = s_chain_callback_atom_iter_get_next; // Get the next element from chain from the current one
    a_chain->callback_atom_iter_get_links = s_chain_callback_atom_iter_get_links; // Get the next element from chain from the current one
    a_chain->callback_atom_iter_get_lasts = s_chain_callback_atom_iter_get_lasts;

    a_chain->callback_atom_get_datums = s_chain_callback_atom_get_datum;
    a_chain->callback_atom_get_timestamp = s_chain_callback_atom_get_timestamp;

    a_chain->callback_atom_find_by_hash = s_chain_callback_atom_iter_find_by_hash;
    a_chain->callback_datum_find_by_hash = s_chain_callback_atom_find_by_datum_hash;

    a_chain->callback_add_datums = s_callback_add_datums;

    // Datum operations callbacks
    a_chain->callback_datum_iter_create = s_chain_callback_datum_iter_create; // Datum iterator create
    a_chain->callback_datum_iter_delete = s_chain_callback_datum_iter_delete; // Datum iterator delete
    a_chain->callback_datum_iter_get_first = s_chain_callback_datum_iter_get_first; // Get the fisrt datum from chain
    a_chain->callback_datum_iter_get_next = s_chain_callback_datum_iter_get_next; // Get the next datum from chain from the current one

    // Get tx list
    a_chain->callback_get_txs = s_dap_chain_callback_get_txs;
    // Get tx count
    a_chain->callback_count_tx = s_dap_chain_callback_get_count_tx;

    // Get atom count in chain
    a_chain->callback_count_atom = s_dap_chain_callback_get_count_atom;
    // Get atom list in chain
    a_chain->callback_get_atoms = s_callback_get_atoms;

    // Others
    a_chain->_inheritor = l_dag;

    const char * l_static_genesis_event_hash_str = dap_config_get_item_str_default(a_chain_cfg,"dag","static_genesis_event",NULL);
    if ( l_static_genesis_event_hash_str ){
        int lhr;
        if ( (lhr= dap_chain_hash_fast_from_str(l_static_genesis_event_hash_str,&l_dag->static_genesis_event_hash) )!= 0 ){
            log_it( L_ERROR, "Can't read hash from static_genesis_event \"%s\", ret code %d ", l_static_genesis_event_hash_str, lhr);
        }
    }
    uint16_t l_list_len = 0;
    char **l_hard_accept_list = dap_config_get_array_str(a_chain_cfg, "dag-poa", "hard_accept_list", &l_list_len);
    log_it(L_MSG, "HAL contains %d whitelisted events", l_list_len);
    for (uint16_t i = 0; i < l_list_len; i++) {
        dap_chain_cs_dag_hal_item_t *l_hal_item = DAP_NEW_Z(dap_chain_cs_dag_hal_item_t);
        if (!l_hal_item){
        log_it(L_CRITICAL, "Memory allocation error");
            DAP_DEL_Z(l_dag->_pvt);
            DAP_DELETE(l_dag);
            return -1;
        }
        dap_chain_hash_fast_from_str(l_hard_accept_list[i], &l_hal_item->hash);
        HASH_ADD(hh, l_dag->hal, hash, sizeof(l_hal_item->hash), l_hal_item);
    }

    l_dag->is_static_genesis_event = (l_static_genesis_event_hash_str != NULL) && dap_config_get_item_bool_default(a_chain_cfg,"dag","is_static_genesis_event",false);

    l_dag->is_single_line = dap_config_get_item_bool_default(a_chain_cfg,"dag","is_single_line",false);
    l_dag->is_celled = dap_config_get_item_bool_default(a_chain_cfg,"dag","is_celled",false);
    l_dag->is_add_directly = dap_config_get_item_bool_default(a_chain_cfg,"dag","is_add_directly",false);
    l_dag->datum_add_hashes_count = dap_config_get_item_uint16_default(a_chain_cfg,"dag","datum_add_hashes_count",1);
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    l_dag->gdb_group_events_round_new = dap_strdup_printf(l_dag->is_celled ? "dag-%s-%s-%016llx-round.new" : "dag-%s-%s-round.new",
                                          l_net->pub.gdb_groups_prefix, a_chain->name, 0LLU);
    dap_global_db_add_sync_extra_group(l_net->pub.name, l_dag->gdb_group_events_round_new, s_history_callback_round_notify, l_dag);
    byte_t *l_current_round = dap_global_db_get_sync(l_dag->gdb_group_events_round_new, DAG_ROUND_CURRENT_KEY, NULL, NULL, NULL);
    l_dag->round_current = l_current_round ? *(uint64_t*)l_current_round : 0;
    DAP_DELETE(l_current_round);
    debug_if(s_debug_more, L_INFO, "Current round id %"DAP_UINT64_FORMAT_U, l_dag->round_current);
    dap_global_db_get_all_raw(l_dag->gdb_group_events_round_new, 0, 0, s_dag_rounds_events_iter, l_dag);
    PVT(l_dag)->mempool_timer = dap_interval_timer_create(15000, s_timer_process_callback, a_chain);
    PVT(l_dag)->events_treshold = NULL;
    PVT(l_dag)->events_treshold_conflicted = NULL;
    PVT(l_dag)->treshold_fee_timer = dap_interval_timer_create(900000, (dap_timer_callback_t)s_dap_chain_cs_dag_threshold_free, l_dag);
    if (l_dag->is_single_line)
        log_it (L_NOTICE, "DAG chain initialized (single line)");
    else
        log_it (L_NOTICE, "DAG chain initialized (multichain)");

    return 0;
}

static void s_dap_chain_cs_dag_threshold_free(dap_chain_cs_dag_t *a_dag) {
    dap_chain_cs_dag_pvt_t *l_pvt = PVT(a_dag);
    dap_chain_cs_dag_event_item_t *l_current = NULL, *l_tmp = NULL;
    dap_nanotime_t  l_time_cut_off = dap_nanotime_now() - dap_nanotime_from_sec(7200); //7200 sec = 2 hours.
    pthread_mutex_lock(&l_pvt->events_mutex);
    //Fee treshold
    HASH_ITER(hh, l_pvt->events_treshold, l_current, l_tmp) {
        if (l_current->ts_added < l_time_cut_off) {
            dap_chain_cs_dag_blocked_t *l_el = DAP_NEW(dap_chain_cs_dag_blocked_t);
            if (!l_el) {
        log_it(L_CRITICAL, "Memory allocation error");
                pthread_mutex_unlock(&l_pvt->events_mutex);
                return;
            }
            l_el->hash = l_current->hash;
            HASH_ADD(hh, l_pvt->removed_events_from_treshold, hash, sizeof(dap_chain_hash_fast_t), l_el);
            char *l_hash_dag = dap_hash_fast_to_str_new(&l_current->hash);
            if (!l_current->mapped_region)
                DAP_DELETE(l_current->event);
            HASH_DEL(l_pvt->events_treshold, l_current);
            DAP_DELETE(l_current);
            log_it(L_NOTICE, "Removed DAG event with %s hash from trashold.", l_hash_dag);
            DAP_DELETE(l_hash_dag);
        }
    }
    //Fee treshold conflicted
    HASH_ITER(hh, l_pvt->events_treshold_conflicted, l_current, l_tmp) {
        if (l_current->ts_added < l_time_cut_off) {
            char *l_hash_dag = dap_hash_fast_to_str_new(&l_current->hash);
            if (!l_current->mapped_region)
                DAP_DELETE(l_current->event);
            HASH_DEL(l_pvt->events_treshold_conflicted, l_current);
            DAP_DELETE(l_current);
            log_it(L_NOTICE, "Removed DAG event with %s hash from trashold.", l_hash_dag);
            DAP_DELETE(l_hash_dag);
        }
    }
    pthread_mutex_unlock(&l_pvt->events_mutex);
}

static void s_dap_chain_cs_dag_purge(dap_chain_t *a_chain)
{
    dap_chain_cs_dag_pvt_t *l_dag_pvt = PVT(DAP_CHAIN_CS_DAG(a_chain));
    pthread_mutex_lock(&l_dag_pvt->events_mutex);
    HASH_CLEAR(hh_datums, l_dag_pvt->datums);
    dap_chain_cs_dag_event_item_t *l_event_current, *l_event_tmp;
    HASH_ITER(hh, l_dag_pvt->events, l_event_current, l_event_tmp) {
        HASH_DEL(l_dag_pvt->events, l_event_current);
        if (!a_chain->is_mapped && !l_event_current->mapped_region)
            DAP_DELETE(l_event_current->event);
        DAP_DELETE(l_event_current);
    }
    HASH_ITER(hh, l_dag_pvt->events_lasts_unlinked, l_event_current, l_event_tmp) {
        HASH_DEL(l_dag_pvt->events_lasts_unlinked, l_event_current);
        if (!a_chain->is_mapped && !l_event_current->mapped_region)
            DAP_DELETE(l_event_current->event);
        DAP_DELETE(l_event_current);
    }
    HASH_ITER(hh, l_dag_pvt->events_treshold, l_event_current, l_event_tmp) {
        HASH_DEL(l_dag_pvt->events_treshold, l_event_current);
        if (!a_chain->is_mapped && !l_event_current->mapped_region)
            DAP_DELETE(l_event_current->event);
        DAP_DELETE(l_event_current);
    }
    HASH_ITER(hh, l_dag_pvt->events_treshold_conflicted, l_event_current, l_event_tmp) {
        HASH_DEL(l_dag_pvt->events_treshold_conflicted, l_event_current);
        if (!a_chain->is_mapped && !l_event_current->mapped_region)
            DAP_DELETE(l_event_current->event);
        DAP_DELETE(l_event_current);
    }
    pthread_mutex_unlock(&l_dag_pvt->events_mutex);
    dap_chain_cell_delete_all(a_chain);
}

/**
 * @brief dap_chain_cs_dag_delete
 * @param a_dag
 * @return
 */
void dap_chain_cs_dag_delete(dap_chain_t * a_chain)
{
    s_dap_chain_cs_dag_purge(a_chain);
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG ( a_chain );
    pthread_mutex_destroy(& PVT(l_dag)->events_mutex);
    dap_interval_timer_delete(PVT(l_dag)->mempool_timer);
    if(l_dag->callback_delete )
        l_dag->callback_delete(l_dag);
    if(l_dag->_inheritor)
        DAP_DELETE(l_dag->_inheritor);
    if(l_dag->_pvt)
        DAP_DELETE(l_dag->_pvt);
}


static int s_dap_chain_add_atom_to_events_table(dap_chain_cs_dag_t *a_dag, dap_chain_cs_dag_event_item_t *a_event_item)
{
    dap_chain_datum_t *l_datum = (dap_chain_datum_t*) dap_chain_cs_dag_event_get_datum(a_event_item->event, a_event_item->event_size);
    if(a_event_item->event_size< sizeof(l_datum->header) ){
        log_it(L_WARNING, "Corrupted event, too small to fit datum in it");
        return -1;
    }
    size_t l_datum_size = dap_chain_datum_size(l_datum);
    size_t l_datum_size_max = dap_chain_cs_dag_event_get_datum_size_maximum(a_event_item->event, a_event_item->event_size);
    if(l_datum_size >l_datum_size_max ){
        log_it(L_WARNING, "Corrupted event, too big size %zd in header when event's size max is only %zd", l_datum_size, l_datum_size_max);
        return -1;
    }
    dap_hash_fast_t l_datum_hash;
    dap_hash_fast(l_datum->data, l_datum->header.data_size, &l_datum_hash);
    int l_ret = dap_chain_datum_add(a_dag->chain, l_datum, l_datum_size, &l_datum_hash);
    if (l_datum->header.type_id == DAP_CHAIN_DATUM_TX)  // && l_ret == 0
        PVT(a_dag)->tx_count++;
    a_event_item->datum_hash = l_datum_hash;
    a_event_item->ret_code = l_ret;
    unsigned l_hash_item_hashv;
    HASH_VALUE(&l_datum_hash, sizeof(l_datum_hash), l_hash_item_hashv);
    pthread_mutex_lock(&PVT(a_dag)->events_mutex);
    dap_chain_cs_dag_event_item_t *l_datum_present = NULL;
    HASH_FIND_BYHASHVALUE(hh_datums, PVT(a_dag)->datums, &l_datum_hash, sizeof(l_datum_hash),
                          l_hash_item_hashv, l_datum_present);
    if (!l_datum_present)
        HASH_ADD_BYHASHVALUE(hh_datums, PVT(a_dag)->datums, datum_hash, sizeof(l_datum_hash),
                             l_hash_item_hashv, a_event_item);
    pthread_mutex_unlock(&PVT(a_dag)->events_mutex);
    if (s_debug_more) {
        char l_buf_hash[DAP_CHAIN_HASH_FAST_STR_SIZE] = {'\0'};
        dap_chain_hash_fast_to_str(&a_event_item->hash, l_buf_hash, sizeof(l_buf_hash));
        log_it(L_INFO, "Dag event %s checked, ret code %d : %s", l_buf_hash, l_ret,
               l_ret ? dap_chain_net_verify_datum_err_code_to_str(l_datum, l_ret) : "Ok");
    }
    return l_ret;
}

static bool s_dap_chain_check_if_event_is_present(dap_chain_cs_dag_event_item_t * a_hash_table, const dap_chain_hash_fast_t * hash) {
    if(!a_hash_table)
        return false;
    dap_chain_cs_dag_event_item_t * l_event_search = NULL;
    HASH_FIND(hh, a_hash_table, hash, sizeof(*hash), l_event_search);
    return (l_event_search != NULL);
}

static int s_sort_event_item(dap_chain_cs_dag_event_item_t* a, dap_chain_cs_dag_event_item_t* b)
{
    return a->event->header.ts_created == b->event->header.ts_created ? 0 :
                a->event->header.ts_created < b->event->header.ts_created ? -1 : 1;
}

/**
 * @brief s_chain_callback_atom_add Accept new event in dag
 * @param a_chain DAG object
 * @param a_atom
 * @param a_atom_size
 * @return 0 if verified and added well, otherwise if not
 */
static dap_chain_atom_verify_res_t s_chain_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t a_atom, size_t a_atom_size)
{
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG(a_chain);
    dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *) a_atom;
    dap_chain_hash_fast_t l_event_hash;
    dap_chain_cs_dag_event_calc_hash(l_event, a_atom_size, &l_event_hash);
    pthread_mutex_t *l_events_mutex = &PVT(l_dag)->events_mutex;
    
    if(s_debug_more) {
        char l_event_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' };
        dap_chain_hash_fast_to_str(&l_event_hash, l_event_hash_str, sizeof(l_event_hash_str));
        log_it(L_DEBUG, "Processing event: %s ... (size %zd)", l_event_hash_str, a_atom_size);
    }

    pthread_mutex_lock(l_events_mutex);
    // check if we already have this event
    dap_chain_atom_verify_res_t ret = s_dap_chain_check_if_event_is_present(PVT(l_dag)->events, &l_event_hash) ||
            s_dap_chain_check_if_event_is_present(PVT(l_dag)->events_treshold, &l_event_hash) ? ATOM_PASS : ATOM_ACCEPT;

    // verify hashes and consensus
    switch (ret) {
    case ATOM_ACCEPT:
        ret = s_chain_callback_atom_verify(a_chain, a_atom, a_atom_size);
        if (ret == ATOM_MOVE_TO_THRESHOLD) {
            if ( !s_threshold_enabled /*&& !dap_chain_net_get_load_mode(dap_chain_net_by_id(a_chain->net_id))*/ )
                ret = ATOM_REJECT;
        }
        debug_if(s_debug_more, L_DEBUG, "Verified atom %p: %s", a_atom, dap_chain_atom_verify_res_str[ret]);
        break;
    case ATOM_PASS:
        debug_if(s_debug_more, L_DEBUG, "Atom already present");
        pthread_mutex_unlock(l_events_mutex);
        return ret;
    default:
        break;
    }
    dap_chain_cs_dag_event_item_t *l_event_item = DAP_NEW_Z(dap_chain_cs_dag_event_item_t);
    if (!l_event_item) {
        log_it(L_CRITICAL, "Memory allocation error");
        ret = ATOM_REJECT;
    }
    *l_event_item = (dap_chain_cs_dag_event_item_t) {
        .hash       = l_event_hash,
        .ts_added   = dap_time_now(),
        .event      = l_event,
        .event_size = a_atom_size
    };
    switch (ret) {
    case ATOM_MOVE_TO_THRESHOLD: {
        dap_chain_cs_dag_blocked_t *el = NULL;
        HASH_FIND(hh, PVT(l_dag)->removed_events_from_treshold, &l_event_hash, sizeof(dap_chain_hash_fast_t), el);
        if (!el) {
            if ( a_chain->is_mapped && dap_chain_net_get_load_mode(dap_chain_net_by_id(a_chain->net_id)) )
                l_event_item->mapped_region = (char*)l_event;
            HASH_ADD(hh, PVT(l_dag)->events_treshold, hash, sizeof(l_event_hash), l_event_item);
            debug_if(s_debug_more, L_DEBUG, "... added to threshold");
        } else {
            ret = ATOM_REJECT;
            debug_if(s_debug_more, L_DEBUG, "... rejected because the atom was removed from the threshold.");
        }
        break;
    }
    case ATOM_ACCEPT: {
        if ( !dap_chain_net_get_load_mode( dap_chain_net_by_id(a_chain->net_id)) ) {
            if ( dap_chain_atom_save(a_chain, a_atom, a_atom_size, l_event->header.cell_id) < 0 ) {
                log_it(L_ERROR, "Can't save atom to file");
                ret = ATOM_REJECT;
                break;
            } else if (a_chain->is_mapped) {
                dap_chain_cell_t *l_cell = dap_chain_cell_find_by_id(a_chain, l_event->header.cell_id);
                l_event_item->event = (dap_chain_cs_dag_event_t*)( l_cell->map_pos += sizeof(uint64_t) );
                l_cell->map_pos += a_atom_size;
            }
        }
        int l_consensus_check = s_dap_chain_add_atom_to_events_table(l_dag, l_event_item);
        switch (l_consensus_check) {
        case 0:
            debug_if(s_debug_more, L_DEBUG, "... added");
            break;
        case DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS:
        case DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION:
            debug_if(s_debug_more, L_DEBUG, "... ledger tresholded");
            break;
        case DAP_CHAIN_DATUM_CA:
            debug_if(s_debug_more, L_DEBUG, "... DATUM_CA");
            break;
        case DAP_CHAIN_DATUM_CUSTOM:
            debug_if(s_debug_more, L_DEBUG, "... DATUM_CUSTOM");
            break;
        default:
            debug_if(s_debug_more, L_WARNING, "... added with ledger code %d", l_consensus_check);
            break;
        }
        dap_chain_cs_dag_event_item_t *l_tail = PVT(l_dag)->events ? PVT(l_dag)->events->hh.tbl->tail->prev : NULL;
        if (!l_tail)
            l_tail = PVT(l_dag)->events;
        else
            l_tail = l_tail->hh.next;
        if (l_tail && l_tail->event->header.ts_created > l_event->header.ts_created)
            DAP_CHAIN_PVT(a_chain)->need_reorder = true;
        if (DAP_CHAIN_PVT(a_chain)->need_reorder)
            HASH_ADD_INORDER(hh, PVT(l_dag)->events, hash, sizeof(l_event_item->hash), l_event_item, s_sort_event_item);
        else
            HASH_ADD(hh, PVT(l_dag)->events, hash, sizeof(l_event_item->hash), l_event_item);

        s_dag_events_lasts_process_new_last_event(l_dag, l_event_item);
        if (a_chain->atom_notifiers) {
            dap_list_t *l_iter;
            DL_FOREACH(a_chain->atom_notifiers, l_iter) {
                dap_chain_atom_notifier_t *l_notifier = (dap_chain_atom_notifier_t*)l_iter->data;
                l_notifier->callback(l_notifier->arg, a_chain, l_event->header.cell_id, l_event, a_atom_size);
            }
        }
        if (a_chain->callback_atom_add_from_treshold) {
            size_t l_atom_treshold_size = 0;
            while ( a_chain->callback_atom_add_from_treshold(a_chain, &l_atom_treshold_size) ) {
                log_it(L_DEBUG, "Added atom with size %lu from threshold", l_atom_treshold_size);
            }
        }
    } break;
    default:
        DAP_DELETE(l_event_item); // Neither added, nor freed
        break;
    }
    pthread_mutex_unlock(l_events_mutex);
    return ret;
}

/**
 * @brief s_chain_callback_atom_add_from_treshold Accept new event in dag
 * @param a_chain DAG object
 * @return true if added one item, otherwise false
 */
static dap_chain_atom_ptr_t s_chain_callback_atom_add_from_treshold(dap_chain_t * a_chain, size_t *a_event_size_out)
{
    dap_chain_cs_dag_t *l_dag = DAP_CHAIN_CS_DAG(a_chain);
    dap_chain_cs_dag_event_item_t *l_item = s_dag_proc_treshold(l_dag);
    if (l_item) {
        if(a_event_size_out)
            *a_event_size_out = l_item->event_size;
        return l_item->event;
    }
    return NULL;
}

/**
 * @brief s_chain_callback_datums_add
 * @param a_chain
 * @param a_datums
 * @param a_datums_size
 */
static size_t s_callback_add_datums(dap_chain_t *a_chain, dap_chain_datum_t **a_datums, size_t a_datums_count)
{
    size_t l_datum_processed = 0;
    for (size_t i = 0; i < a_datums_count; i++) {
        dap_chain_datum_t *l_datum = *(a_datums + i);
        size_t l_datum_size = dap_chain_datum_size(l_datum);
        if (!l_datum_size || !l_datum)
            continue;
        if (s_chain_callback_datums_pool_proc(a_chain, l_datum))
            ++l_datum_processed;
    }
    return l_datum_processed;
}

static bool s_chain_callback_datums_pool_proc(dap_chain_t *a_chain, dap_chain_datum_t *a_datum) {
    if (!a_datum || !a_chain){
        log_it(L_ERROR, "Datum or chain in mempool processing comes NULL in s_chain_callback_datums_pool_proc");
        return false;
    }

    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG(a_chain);
    /* If datum passes thru rounds, let's check if it wasn't added before */
    dap_chain_hash_fast_t l_datum_hash;
    dap_hash_fast(a_datum, dap_chain_datum_size(a_datum), &l_datum_hash);
    if (!l_dag->is_add_directly) {
        bool l_dup_found = false;
        size_t l_objs_count = 0;
        dap_global_db_obj_t * l_objs = dap_global_db_get_all_sync(l_dag->gdb_group_events_round_new, &l_objs_count);
        for (size_t i = 0; i < l_objs_count; ++i) {
            dap_chain_cs_dag_event_round_item_t *l_round_item = (dap_chain_cs_dag_event_round_item_t*)l_objs[i].value;
            if (!memcmp(&l_datum_hash, &(l_round_item->round_info.datum_hash), sizeof(dap_chain_hash_fast_t))) {
                l_dup_found = true;
                break;
            }
        }
        dap_global_db_objs_delete(l_objs, l_objs_count);
        if (l_dup_found) {
            char l_datum_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(&l_datum_hash, l_datum_hash_str, sizeof(l_datum_hash_str));
            log_it(L_ERROR, "Datum %s was already added to round, drop it", l_datum_hash_str);
            return false;
        }
    }

    size_t  l_hashes_size   = l_dag->is_single_line ? 1 : l_dag->datum_add_hashes_count,
            l_hashes_linked = 0;
    if (!l_hashes_size) {
        log_it(L_ERROR, "Configuration mismatch, no hashed to be linked");
        return false;
    }
    dap_chain_hash_fast_t *l_hashes = l_hashes_size
            ? DAP_NEW_STACK_SIZE(dap_chain_hash_fast_t, l_hashes_size * sizeof(dap_chain_hash_fast_t))
            : NULL;
    if (!l_hashes) {
        log_it(L_CRITICAL, "Stack limit reached");
        return false;
    }

    /* Prepare round */
    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
    if (!HASH_COUNT(PVT(l_dag)->events_lasts_unlinked)) {
        pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
        log_it(L_INFO, "Nothing to link");
        if (!s_seed_mode)
            return false;
    } else {
        /* We'll use modification-safe iteration thru the additional hashtable thus the chosen events will not repeat */
#define always_true(ev) true
        dap_chain_cs_dag_event_item_t *l_tmp = NULL, *l_cur_ev, *l_tmp_ev;
        HASH_SELECT(hh_select, l_tmp, hh, PVT(l_dag)->events_lasts_unlinked, always_true); /* Always true predicate */
        pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
        while ((l_hashes_linked < l_hashes_size) && (HASH_CNT(hh_select, l_tmp) > 0)) {
            int l_random_id = rand() % HASH_CNT(hh_select, l_tmp), l_hash_id = 0;
            HASH_ITER(hh_select, l_tmp, l_cur_ev, l_tmp_ev) {
                if (l_hash_id++ == l_random_id) {
                    l_hashes[l_hashes_linked++] = l_cur_ev->hash;
                    HASH_DELETE(hh_select, l_tmp, l_cur_ev);
                    break;
                }
            }
        }
        HASH_CLEAR(hh_select, l_tmp);
        if (l_hashes_linked < l_hashes_size) {
            log_it(L_ERROR, "No enough unlinked events present (only %lu of %lu), a dummy round?", l_hashes_linked, l_hashes_size);
            return false;
        }
    }

    /*
     * Either we're in seed mode ==> the new event will be not linked to anything
     * or we have successfully chosen the hash(es) to link with.
     * No additional conditions required.
    */
    byte_t *l_current_round_bytes = dap_global_db_get_sync(l_dag->gdb_group_events_round_new, DAG_ROUND_CURRENT_KEY, NULL, NULL, NULL);
    uint64_t l_current_round = l_current_round_bytes ? *(uint64_t*)l_current_round_bytes : 0;
    DAP_DEL_Z(l_current_round_bytes);
    l_dag->round_completed = l_current_round++;
    l_dag->round_current = l_current_round;
    uint64_t l_event_size = 0;
    dap_chain_cs_dag_event_t * l_event = l_dag->callback_cs_event_create
            ? l_dag->callback_cs_event_create(l_dag, a_datum, l_hashes, l_hashes_linked, &l_event_size)
            : NULL;
    if (!l_event || !l_event_size) {
        log_it(L_ERROR,"Can't create new event!");
        return false;
    }

    if (l_dag->is_add_directly) {
        dap_chain_atom_verify_res_t l_verify_res;
        switch (l_verify_res = s_chain_callback_atom_add(a_chain, l_event, l_event_size)) {
        case ATOM_ACCEPT:
            if ( !a_chain->is_mapped )
                l_event = NULL;
            break;
        case ATOM_MOVE_TO_THRESHOLD:
            l_event = NULL;
            log_it(L_ERROR, "Event thresholded");
            break;
        default:
            log_it(L_ERROR, "Can't add new event to the file, atom verification result %d", l_verify_res);
        }
        DAP_DELETE(l_event);
        return l_verify_res == ATOM_ACCEPT;
    }

    dap_global_db_set_sync(l_dag->gdb_group_events_round_new, DAG_ROUND_CURRENT_KEY,
                      &l_current_round, sizeof(uint64_t), false);
    dap_chain_cs_dag_event_round_item_t l_round_item = { .round_info.datum_hash = l_datum_hash };
    char *l_event_hash_str;
    dap_get_data_hash_str_static(l_event, l_event_size, l_event_hash_str);
    bool l_res = dap_chain_cs_dag_event_gdb_set(l_dag, l_event_hash_str, l_event, l_event_size, &l_round_item);
    log_it(l_res ? L_INFO : L_ERROR,
           l_res ? "Event %s placed in the new forming round [id %"DAP_UINT64_FORMAT_U"]"
                 : "Can't add new event [%s] to the new events round [id %"DAP_UINT64_FORMAT_U"]",
           l_event_hash_str, l_current_round);
    return l_res;
}



/**
 * @brief dap_chain_cs_dag_find_event_by_hash
 * @param a_dag
 * @param a_hash
 * @return
 */
dap_chain_cs_dag_event_t* dap_chain_cs_dag_find_event_by_hash(dap_chain_cs_dag_t * a_dag, dap_chain_hash_fast_t * a_hash)
{
    dap_chain_cs_dag_event_item_t* l_event_item = NULL;
    pthread_mutex_lock(&PVT(a_dag)->events_mutex);
    HASH_FIND(hh, PVT(a_dag)->events ,a_hash,sizeof(*a_hash), l_event_item);
    pthread_mutex_unlock(&PVT(a_dag)->events_mutex);
    dap_chain_cs_dag_event_t * l_event = l_event_item? l_event_item->event: NULL;
    return l_event;
}

static bool s_event_verify_size(dap_chain_cs_dag_event_t *a_event, size_t a_event_size)
{
    if (sizeof(a_event->header) >= a_event_size) {
        log_it(L_WARNING, "Size of atom is %zd that is equal or less then header %zd", a_event_size, sizeof(a_event->header));
        return false;
    }
    size_t l_sign_offset = dap_chain_cs_dag_event_calc_size_excl_signs(a_event, a_event_size);
    if (l_sign_offset >= a_event_size)
        return false;
    if (a_event->header.signs_count > UINT8_MAX)
        return false;
    uint8_t i;
    for (i = 0; i < a_event->header.signs_count && l_sign_offset < a_event_size; ++i) {
        dap_sign_t *l_sign = (dap_sign_t*)((uint8_t*)a_event + l_sign_offset);
        l_sign_offset += dap_sign_get_size(l_sign);
    }
    if (i != a_event->header.signs_count) {
        log_it(L_WARNING, "Malformed event! Only %d of claimed %d signs fit data size%s",
               i, a_event->header.signs_count, l_sign_offset == a_event_size ? "" : ", incomplete sequence");

    }
    return l_sign_offset == a_event_size;
}



/**
 * @brief s_chain_callback_atom_verify Verify atomic element
 * @param a_chain
 * @param a_atom
 * @return
 */
static dap_chain_atom_verify_res_t s_chain_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_ptr_t  a_atom,size_t a_atom_size)
{
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG(a_chain);
    dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *) a_atom;
    dap_chain_atom_verify_res_t res = ATOM_ACCEPT;
    pthread_mutex_t *l_events_mutex = &PVT(l_dag)->events_mutex;
    if (l_event->header.version) {
        debug_if(s_debug_more, L_WARNING, "Unsupported event version, possible corrupted event");
        return ATOM_REJECT;
    }
    if (l_event->header.chain_id.uint64 != a_chain->id.uint64) {
        debug_if(s_debug_more, L_WARNING, "Event from another chain, possible corrupted event");
        return ATOM_REJECT;
    }

    // Hard accept list
    if (l_dag->hal) {
        dap_chain_hash_fast_t l_event_hash = { };
        dap_chain_cs_dag_event_calc_hash(l_event,a_atom_size, &l_event_hash);
        dap_chain_cs_dag_hal_item_t *l_hash_found = NULL;
        pthread_mutex_lock(l_events_mutex);
        HASH_FIND(hh, l_dag->hal, &l_event_hash, sizeof(l_event_hash), l_hash_found);
        pthread_mutex_unlock(l_events_mutex);
        if (l_hash_found) {
            return ATOM_ACCEPT;
        }
    }
    if (!s_event_verify_size(l_event, a_atom_size)) {
        debug_if(s_debug_more, L_WARNING,"Event size not equal to expected");
        return  ATOM_REJECT;
    }

    // genesis or seed mode
    if (l_event->header.hash_count == 0){
        if(s_seed_mode && !PVT(l_dag)->events){
            log_it(L_NOTICE,"Accepting genesis event");
            return ATOM_ACCEPT;
        }else if(s_seed_mode){
            log_it(L_WARNING,"Cant accept genesis event: already present data in DAG, ->events is not NULL");
            return  ATOM_REJECT;
        }

        if (l_dag->is_static_genesis_event ){
            dap_chain_hash_fast_t l_event_hash;
            dap_chain_cs_dag_event_calc_hash(l_event,a_atom_size, &l_event_hash);
            if ( memcmp( &l_event_hash, &l_dag->static_genesis_event_hash, sizeof(l_event_hash) ) != 0 ){
                char l_event_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE], l_genesis_event_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_chain_hash_fast_to_str(&l_event_hash, l_event_hash_str, sizeof(l_event_hash_str));
                dap_chain_hash_fast_to_str(&l_dag->static_genesis_event_hash, l_genesis_event_hash_str, sizeof(l_genesis_event_hash_str));
                log_it(L_WARNING, "Wrong genesis event %s (staticly predefined %s)",l_event_hash_str, l_genesis_event_hash_str);
                return ATOM_REJECT;
            } else {
                debug_if(s_debug_more, L_INFO, "Accepting static genesis event");
                return ATOM_ACCEPT;
            }
        }
    }

    //chain coherence
    if (! PVT(l_dag)->events ){
        res = ATOM_MOVE_TO_THRESHOLD;
        //log_it(L_DEBUG, "*** event %p goes to threshold", l_event);
    } else {
        //log_it(L_DEBUG, "*** event %p hash count %d",l_event, l_event->header.hash_count);
        for (size_t i = 0; i< l_event->header.hash_count; i++) {
            dap_chain_hash_fast_t * l_hash =  ((dap_chain_hash_fast_t *) l_event->hashes_n_datum_n_signs) + i;
            dap_chain_cs_dag_event_item_t * l_event_search = NULL;
            pthread_mutex_lock(l_events_mutex);
            HASH_FIND(hh, PVT(l_dag)->events ,l_hash ,sizeof (*l_hash),  l_event_search);
            pthread_mutex_unlock(l_events_mutex);
            if (l_event_search == NULL) {
                if(s_debug_more) {
                    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                    dap_chain_hash_fast_to_str(l_hash, l_hash_str, sizeof(l_hash_str));
                    log_it(L_WARNING, "Hash %s wasn't in hashtable of previously parsed", l_hash_str);
                }
                res = ATOM_MOVE_TO_THRESHOLD;
                break;
            }
        }
    }

    //consensus
    if(res == ATOM_ACCEPT)
        if(l_dag->callback_cs_verify ( l_dag, l_event,a_atom_size ))
            res = ATOM_REJECT;

    return res;
}

/**
 * @brief dap_chain_cs_dag_proc_event_round_new
 * @param a_dag
 */
void dap_chain_cs_dag_proc_event_round_new(dap_chain_cs_dag_t *a_dag)
{
    (void) a_dag;
    log_it(L_WARNING,"No proc event algorythm, use manual commands for round aproving");
}


/**
 * @brief s_dag_events_lasts_delete_linked_with_event
 * @param a_dag
 * @param a_event
 */
void s_dag_events_lasts_delete_linked_with_event(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_event)
{
    for (size_t i = 0; i< a_event->header.hash_count; i++) {
        dap_chain_hash_fast_t * l_hash =  ((dap_chain_hash_fast_t *) a_event->hashes_n_datum_n_signs) + i;
        dap_chain_cs_dag_event_item_t * l_event_item = NULL;
        dap_chain_cs_dag_pvt_t * l_dag_pvt =  PVT(a_dag);
        HASH_FIND(hh, l_dag_pvt->events_lasts_unlinked ,l_hash ,sizeof (*l_hash),  l_event_item);
        if ( l_event_item ){
            HASH_DEL(PVT(a_dag)->events_lasts_unlinked,l_event_item);
            DAP_DEL_Z(l_event_item);
        }
    }
}

void s_dag_events_lasts_process_new_last_event(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_item_t * a_event_item){
    //delete linked with event
    s_dag_events_lasts_delete_linked_with_event(a_dag, a_event_item->event);

    //add self
    dap_chain_cs_dag_event_item_t * l_event_last= DAP_NEW_Z(dap_chain_cs_dag_event_item_t);
    if (!l_event_last) {
        log_it(L_CRITICAL, "Memory allocation error");
        return;
    }
    l_event_last->ts_added = a_event_item->ts_added;
    l_event_last->event = a_event_item->event;
    l_event_last->event_size = a_event_item->event_size;
    dap_hash_fast(l_event_last->event, a_event_item->event_size,&l_event_last->hash );
    HASH_ADD(hh,PVT(a_dag)->events_lasts_unlinked,hash, sizeof(l_event_last->hash),l_event_last);
}


typedef enum{
  DAP_THRESHOLD_OK = 0,
  DAP_THRESHOLD_NO_HASHES,
  DAP_THRESHOLD_NO_HASHES_IN_MAIN,
  DAP_THRESHOLD_CONFLICTING
} dap_dag_threshold_verification_res_t;

int dap_chain_cs_dag_event_verify_hashes_with_treshold(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_event)
{
    bool l_is_events_all_hashes = true;
    bool l_is_events_main_hashes = true;

    if (a_event->header.hash_count == 0) {
        //looks like an alternative genesis event
        return DAP_THRESHOLD_CONFLICTING;
    }
    dap_dag_threshold_verification_res_t ret = DAP_THRESHOLD_OK;
    for (size_t i = 0; i< a_event->header.hash_count; i++) {
        dap_chain_hash_fast_t * l_hash =  ((dap_chain_hash_fast_t *) a_event->hashes_n_datum_n_signs) + i;
        dap_chain_cs_dag_event_item_t * l_event_search = NULL;
        HASH_FIND(hh, PVT(a_dag)->events_treshold_conflicted,l_hash ,sizeof (*l_hash),  l_event_search);
        if ( l_event_search ){
          //event is linked to event we consider conflicting
          ret = DAP_THRESHOLD_CONFLICTING;
          break;
        }
        HASH_FIND(hh, PVT(a_dag)->events ,l_hash ,sizeof (*l_hash),  l_event_search);
        if ( l_event_search == NULL ){ // If not found in events - search in treshhold
            l_is_events_main_hashes = false;
            HASH_FIND(hh, PVT(a_dag)->events_treshold ,l_hash ,sizeof (*l_hash),  l_event_search);
            if( l_event_search == NULL ){ // Hash is not in events or treshold table, keep the current item where it is
                l_is_events_all_hashes = false;
                break;
            }
        }
    }
    if (ret == DAP_THRESHOLD_CONFLICTING)
        return ret;
    return l_is_events_all_hashes ?
                (l_is_events_main_hashes ?
                    DAP_THRESHOLD_OK :
                DAP_THRESHOLD_NO_HASHES_IN_MAIN) :
            DAP_THRESHOLD_NO_HASHES;
}

/**
 * @brief s_dag_proc_treshold
 * @param a_dag
 * @returns true if some atoms were moved from threshold to events
 */
dap_chain_cs_dag_event_item_t* s_dag_proc_treshold(dap_chain_cs_dag_t * a_dag)
{
    bool res = false;
    dap_chain_cs_dag_event_item_t * l_event_item = NULL, * l_event_item_tmp = NULL;
    pthread_mutex_lock(&PVT(a_dag)->events_mutex);
    int l_count = HASH_COUNT(PVT(a_dag)->events_treshold);
    log_it(L_DEBUG, "*** %d events in threshold", l_count);
    HASH_ITER(hh, PVT(a_dag)->events_treshold, l_event_item, l_event_item_tmp) {
        dap_dag_threshold_verification_res_t ret = dap_chain_cs_dag_event_verify_hashes_with_treshold(a_dag, l_event_item->event);
        if (ret == DAP_THRESHOLD_OK) {
            if (s_debug_more) {
                char * l_event_hash_str = dap_chain_hash_fast_to_str_new(&l_event_item->hash);
                log_it(L_DEBUG, "Processing event (threshold): %s...", l_event_hash_str);
                DAP_DELETE(l_event_hash_str);
            }
            if ( !l_event_item->mapped_region ) {
                if ( dap_chain_atom_save(a_dag->chain, (const byte_t*)l_event_item->event, l_event_item->event_size, l_event_item->event->header.cell_id) < 0 ) {
                    log_it(L_CRITICAL, "Can't move atom from threshold to file");
                    res = false;
                    break;
                } else if (a_dag->chain->is_mapped) {
                    dap_chain_cell_t *l_cell = dap_chain_cell_find_by_id(a_dag->chain, l_event_item->event->header.cell_id);
                    l_event_item->event = (dap_chain_cs_dag_event_t*)( l_cell->map_pos += sizeof(uint64_t) );
                    l_cell->map_pos += l_event_item->event_size;
                }
            }
            int l_add_res = s_dap_chain_add_atom_to_events_table(a_dag, l_event_item);
            HASH_DEL(PVT(a_dag)->events_treshold, l_event_item);
            if (!l_add_res) {
                HASH_ADD(hh, PVT(a_dag)->events, hash, sizeof(l_event_item->hash), l_event_item);
                s_dag_events_lasts_process_new_last_event(a_dag, l_event_item);
                debug_if(s_debug_more, L_INFO, "... moved from treshold to main chains");
                res = true;
            } else {
                // TODO clear other threshold items linked with this one
                debug_if(s_debug_more, L_WARNING, "... rejected with ledger code %d", l_add_res);
                if (!l_event_item->mapped_region)
                    DAP_DELETE(l_event_item->event);
                DAP_DELETE(l_event_item);
            }
            if (a_dag->chain->atom_notifiers) {
                dap_list_t *l_iter;
                DL_FOREACH(a_dag->chain->atom_notifiers, l_iter) {
                    dap_chain_atom_notifier_t *l_notifier = (dap_chain_atom_notifier_t*)l_iter->data;
                    l_notifier->callback(l_notifier->arg, a_dag->chain, l_event_item->event->header.cell_id,
                                         l_event_item->event, l_event_item->event_size);
                }
        }
            break;
        } else if (ret == DAP_THRESHOLD_CONFLICTING) {
            HASH_DEL(PVT(a_dag)->events_treshold, l_event_item);
            HASH_ADD(hh, PVT(a_dag)->events_treshold_conflicted, hash, sizeof (l_event_item->hash), l_event_item);
        }
    }
    pthread_mutex_unlock(&PVT(a_dag)->events_mutex);
    return res ? l_event_item : NULL;
}

/**
 * @brief s_chain_callback_atom_get_static_hdr_size
 * @param a_chain
 * @return
 */
static size_t s_chain_callback_atom_get_static_hdr_size()
{
   return sizeof (dap_chain_class_dag_event_hdr_t);
}

/**
 * @brief s_chain_callback_atom_iter_create_from
 * @param a_chain
 * @param a_atom
 * @return
 */
static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create_from(dap_chain_t * a_chain ,
                                                                     dap_chain_atom_ptr_t a_atom, size_t a_atom_size)
{
    dap_chain_atom_iter_t * l_atom_iter = DAP_NEW_Z(dap_chain_atom_iter_t);
    if (!l_atom_iter) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    l_atom_iter->chain = a_chain;
    l_atom_iter->cur = a_atom;
    l_atom_iter->cur_size = a_atom_size;

    if ( a_atom ){
        dap_chain_hash_fast_t l_atom_hash;
        dap_hash_fast(a_atom, a_atom_size, &l_atom_hash );

        dap_chain_cs_dag_event_item_t  * l_atom_item;
        HASH_FIND(hh, PVT(DAP_CHAIN_CS_DAG(a_chain))->events, &l_atom_hash, sizeof(l_atom_hash),l_atom_item );
        l_atom_iter->cur_item = l_atom_item;
        l_atom_iter->cur_hash = &l_atom_item->hash;
    }
    return l_atom_iter;

}

/**
 * @brief s_chain_callback_atom_iter_create Create atomic element iterator
 * @param a_chain
 * @return
 */
static dap_chain_atom_iter_t *s_chain_callback_atom_iter_create(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, bool a_with_treshold)
{
    dap_chain_atom_iter_t * l_atom_iter = DAP_NEW_Z(dap_chain_atom_iter_t);
    if (!l_atom_iter) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    l_atom_iter->chain = a_chain;
    l_atom_iter->cell_id = a_cell_id;
    l_atom_iter->with_treshold = a_with_treshold;
#ifdef WIN32
    log_it(L_DEBUG, "! %p create caller id %lu", l_atom_iter, GetThreadId(GetCurrentThread()));
#endif
    return l_atom_iter;
}


/**
 * @brief s_chain_callback_atom_get_datum Get the datum from event
 * @param a_atom_iter
 * @param a_datums_count
 * @return
 */
static dap_chain_datum_t **s_chain_callback_atom_get_datum(dap_chain_atom_ptr_t a_event, size_t a_atom_size, size_t *a_datums_count)
{
    assert(a_datums_count);
    if (!a_event)
        return NULL;
    dap_chain_datum_t *l_datum = dap_chain_cs_dag_event_get_datum((dap_chain_cs_dag_event_t*)a_event, a_atom_size);
    if (!l_datum)
        return NULL;

    dap_chain_datum_t **l_datums = DAP_NEW_Z(dap_chain_datum_t*);
    if (!l_datums) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    if (a_datums_count)
        *a_datums_count = 1;
    l_datums[0] = l_datum;
    return l_datums;
}

/**
 * @brief s_chain_callback_atom_iter_get_first Get the first dag event
 * @param a_atom_iter
 * @return
 */
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_first(dap_chain_atom_iter_t * a_atom_iter, size_t * a_ret_size )
{
    if(! a_atom_iter){
        log_it(L_ERROR, "NULL iterator on input for atom_iter_get_first function");
        return NULL;
    }
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG(a_atom_iter->chain);
    assert(l_dag);
    dap_chain_cs_dag_pvt_t *l_dag_pvt = PVT(l_dag);
    assert(l_dag_pvt);
    a_atom_iter->cur_item = NULL;
    dap_chain_cs_dag_event_item_t *l_item_tmp, *l_item_cur;
    int found = 0;

    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
    HASH_ITER(hh, l_dag_pvt->events, l_item_cur, l_item_tmp) {
        if (l_item_cur->event->header.cell_id.uint64 == a_atom_iter->cell_id.uint64) {
            a_atom_iter->cur_item = l_item_cur;
            found = 1;
            a_atom_iter->found_in_treshold = 0;
            break;
        }
    }
    if (!found && a_atom_iter->with_treshold) {
        HASH_ITER(hh, l_dag_pvt->events_treshold, l_item_cur, l_item_tmp) {
            if (l_item_cur->event->header.cell_id.uint64 == a_atom_iter->cell_id.uint64) {
                a_atom_iter->cur_item = l_item_cur;
                a_atom_iter->found_in_treshold = 1;
                break;
            }
        }
    }
    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);

    if ( a_atom_iter->cur_item ){
        a_atom_iter->cur = ((dap_chain_cs_dag_event_item_t*) a_atom_iter->cur_item)->event;
        a_atom_iter->cur_size = ((dap_chain_cs_dag_event_item_t*) a_atom_iter->cur_item)->event_size;
        a_atom_iter->cur_hash = &((dap_chain_cs_dag_event_item_t*) a_atom_iter->cur_item)->hash;
    }else{
        a_atom_iter->cur = NULL;
        a_atom_iter->cur_size = 0;
        a_atom_iter->cur_hash = NULL;
    }

    if (a_ret_size)
        *a_ret_size = a_atom_iter->cur_size;
    return a_atom_iter->cur;
}


/**
 * @brief s_chain_callback_atom_iter_get_lasts
 * @param a_atom_iter
 * @param a_lasts_size_ptr
 * @return
 */
static dap_chain_atom_ptr_t* s_chain_callback_atom_iter_get_lasts( dap_chain_atom_iter_t * a_atom_iter ,size_t * a_lasts_size,
                                                                  size_t ** a_lasts_size_array )
{
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG( a_atom_iter->chain );
    dap_chain_atom_ptr_t * l_ret = NULL;
    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
    size_t l_lasts_size = HASH_COUNT( PVT(l_dag)->events_lasts_unlinked );
    if ( l_lasts_size > 0 ) {
        if( a_lasts_size)
            *a_lasts_size = l_lasts_size;
        l_ret = DAP_NEW_Z_SIZE(dap_chain_atom_ptr_t, sizeof(dap_chain_atom_ptr_t) * l_lasts_size);
        if (!l_ret) {
            log_it(L_CRITICAL, "Memory allocation error");
            pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
            return NULL;
        }
        dap_chain_cs_dag_event_item_t * l_event_item = NULL, *l_event_item_tmp = NULL;
        size_t i = 0;
        *a_lasts_size_array = DAP_NEW_Z_SIZE(size_t, sizeof(size_t) * l_lasts_size);
        if (!*a_lasts_size_array) {
            log_it(L_CRITICAL, "Memory allocation error");
            pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
            DAP_DEL_Z(l_ret);
            return NULL;
        }
        HASH_ITER(hh,PVT(l_dag)->events_lasts_unlinked, l_event_item,l_event_item_tmp){
            l_ret[i] = l_event_item->event;
            (*a_lasts_size_array)[i] = l_event_item->event_size;
            i++;
        }
    }
    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
    return l_ret;
}

/**
 * @brief s_chain_callback_atom_iter_get_links
 * @param a_atom_iter
 * @param a_links_size_ptr
 * @return
 */
static dap_chain_atom_ptr_t* s_chain_callback_atom_iter_get_links( dap_chain_atom_iter_t * a_atom_iter ,size_t* a_links_size,
                                                                  size_t ** a_links_size_array )
{
    if ( a_atom_iter->cur && a_atom_iter->chain){
        dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG( a_atom_iter->chain );
        if(!l_dag){
            log_it(L_ERROR,"Chain %s have DAP_CHAIN_CS_DAG() = NULL", a_atom_iter->chain->name);
            return NULL;
        }
        dap_chain_cs_dag_event_t * l_event =(dap_chain_cs_dag_event_t *) a_atom_iter->cur;
        dap_chain_cs_dag_event_item_t * l_event_item = (dap_chain_cs_dag_event_item_t *) a_atom_iter->cur_item;
        if ( l_event->header.hash_count > 0){
            dap_chain_atom_ptr_t * l_ret = DAP_NEW_Z_SIZE(dap_chain_atom_ptr_t,
                                               sizeof (dap_chain_atom_ptr_t) * l_event->header.hash_count );
            if (!l_ret) {
                log_it(L_CRITICAL, "Memory allocation error");
                return NULL;
            }
            if( a_links_size)
                *a_links_size = l_event->header.hash_count;
            *a_links_size_array = DAP_NEW_Z_SIZE(size_t, l_event->header.hash_count*sizeof (size_t));
            if (!*a_links_size_array) {
                log_it(L_CRITICAL, "Memory allocation error");
                DAP_DEL_Z(l_ret);
                return NULL;
            }
            for (uint16_t i = 0; i < l_event->header.hash_count; i++){
                dap_chain_cs_dag_event_item_t * l_link_item = NULL;
                dap_chain_hash_fast_t * l_link_hash = (dap_chain_hash_fast_t *)
                        (l_event->hashes_n_datum_n_signs +
                        i*sizeof(*l_link_hash));
                pthread_mutex_lock(&PVT(l_dag)->events_mutex);
                HASH_FIND(hh, PVT(l_dag)->events,l_link_hash,sizeof(*l_link_hash),l_link_item);
                pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
                if ( l_link_item ){
                    l_ret[i] = l_link_item->event;
                    (*a_links_size_array)[i] = l_link_item->event_size;
                }else {
                    char * l_link_hash_str = dap_chain_hash_fast_to_str_new(l_link_hash);
                    char * l_event_hash_str = l_event_item ? dap_chain_hash_fast_to_str_new(&l_event_item->hash) : NULL;
                    log_it(L_ERROR,"Can't find %s->%s links", l_event_hash_str ? l_event_hash_str : "[null]", l_link_hash_str);
                    DAP_DEL_Z(l_event_hash_str);
                    DAP_DELETE(l_link_hash_str);
                    (*a_links_size_array)--;
                }
            }
            if(!(*a_links_size_array)){
                DAP_DELETE(l_ret);
                l_ret = NULL;
            }
            return l_ret;
        }
    }
    return  NULL;
}

/**
 * @brief s_chain_callback_atom_iter_find_by_hash
 * @param a_atom_iter
 * @param a_atom_hash
 * @return
 */
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_find_by_hash(dap_chain_atom_iter_t * a_atom_iter ,
                                                                       dap_chain_hash_fast_t * a_atom_hash,size_t *a_atom_size)
{
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG( a_atom_iter->chain );
    dap_chain_cs_dag_event_item_t * l_event_item = NULL;
    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
    HASH_FIND(hh, PVT(l_dag)->events,a_atom_hash,sizeof(*a_atom_hash),l_event_item);
    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
    if ( l_event_item ){
        a_atom_iter->cur_item = l_event_item;
        a_atom_iter->cur = l_event_item->event;
        a_atom_iter->cur_size= l_event_item->event_size;
        a_atom_iter->cur_hash = &l_event_item->hash;
        if(a_atom_size)
            *a_atom_size = l_event_item->event_size;
        return  l_event_item->event;
    }else
        return NULL;
}

/**
 * @brief s_chain_callback_atom_find_by_datum_hash
 * @param IN a_chain
 * @param IN a_datum_hash
 * @param OUT a_event_hash
 * @param OUT a_ret_code
 * @return
 */
static dap_chain_datum_t *s_chain_callback_atom_find_by_datum_hash(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_datum_hash,
                                                                   dap_chain_hash_fast_t *a_event_hash, int *a_ret_code)
{
    dap_chain_cs_dag_t *l_dag = DAP_CHAIN_CS_DAG( a_chain );
    dap_chain_cs_dag_event_item_t *l_event_item = NULL;
    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
    HASH_FIND(hh_datums, PVT(l_dag)->datums, a_datum_hash, sizeof(*a_datum_hash), l_event_item);
    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
    if ( l_event_item ){
        dap_chain_datum_t *l_datum = dap_chain_cs_dag_event_get_datum(l_event_item->event, l_event_item->event_size);
        if (l_datum && l_datum->header.data_size) {
            if (a_event_hash)
                *a_event_hash = l_event_item->hash;
            if (a_ret_code)
                *a_ret_code = l_event_item->ret_code;
            return l_datum;
        }
    }
    return NULL;
}

/**
 * @brief s_chain_callback_atom_iter_get_next Get the next dag event
 * @param a_atom_iter
 * @return
 */
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_next( dap_chain_atom_iter_t * a_atom_iter,size_t * a_atom_size )
{
    dap_chain_cs_dag_event_item_t * l_event_item = (dap_chain_cs_dag_event_item_t*) a_atom_iter->cur_item;

    while (l_event_item) {
        l_event_item = (dap_chain_cs_dag_event_item_t *)l_event_item->hh.next;
        if (l_event_item && l_event_item->event->header.cell_id.uint64 == a_atom_iter->cell_id.uint64)
            break;
    }

    if(!l_event_item && !a_atom_iter->found_in_treshold && a_atom_iter->with_treshold) {
        dap_chain_cs_dag_t *l_dag = DAP_CHAIN_CS_DAG(a_atom_iter->chain);
        assert(l_dag);
        dap_chain_cs_dag_pvt_t *l_dag_pvt = PVT(l_dag);
        assert(l_dag_pvt);
        l_event_item = l_dag_pvt->events_treshold;
        pthread_mutex_lock(&PVT(l_dag)->events_mutex);
        while (l_event_item) {
            if (l_event_item && l_event_item->event->header.cell_id.uint64 == a_atom_iter->cell_id.uint64) {
                a_atom_iter->found_in_treshold = 1;
                break;
            }
            l_event_item = (dap_chain_cs_dag_event_item_t *)l_event_item->hh.next;
        }
        pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
    }
    // if l_event_item=NULL then items are over
    a_atom_iter->cur_item = l_event_item;
    a_atom_iter->cur = l_event_item ? l_event_item->event : NULL;
    a_atom_iter->cur_size = a_atom_iter->cur ? l_event_item->event_size : 0;
    a_atom_iter->cur_hash = l_event_item ? &l_event_item->hash : NULL;
    if(a_atom_size)
        *a_atom_size = a_atom_iter->cur_size;
    return a_atom_iter->cur;
}


/**
 * @brief s_chain_callback_atom_iter_delete Delete dag event iterator
 * @param a_atom_iter
 */
static void s_chain_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter )
{
#ifdef WIN32
    log_it(L_DEBUG, "! Delete caller id %lu", GetThreadId(GetCurrentThread()));
#endif
    DAP_DELETE(a_atom_iter);
}

static dap_chain_datum_iter_t *s_chain_callback_datum_iter_create(dap_chain_t *a_chain)
{
    dap_chain_datum_iter_t *l_ret = DAP_NEW_Z(dap_chain_datum_iter_t);
    if (!l_ret) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    l_ret->chain = a_chain;
    return l_ret;
}

static void s_chain_callback_datum_iter_delete(dap_chain_datum_iter_t *a_datum_iter)
{
    DAP_DELETE(a_datum_iter);
}

static void s_datum_iter_fill(dap_chain_datum_iter_t *a_datum_iter, dap_chain_cs_dag_event_item_t *a_event_item)
{
    a_datum_iter->cur_item = a_event_item;
    if (a_event_item) {
        a_datum_iter->cur = dap_chain_cs_dag_event_get_datum(a_event_item->event, a_event_item->event_size);
        a_datum_iter->cur_size = dap_chain_datum_size(a_datum_iter->cur);
        a_datum_iter->cur_hash = &a_event_item->datum_hash;
        a_datum_iter->cur_atom_hash = &a_event_item->hash;
        a_datum_iter->ret_code = a_event_item->ret_code;
    } else {
        a_datum_iter->cur = NULL;
        a_datum_iter->cur_hash = NULL;
        a_datum_iter->cur_size = 0;
        a_datum_iter->ret_code = 0;
    }
}

static dap_chain_datum_t *s_chain_callback_datum_iter_get_first(dap_chain_datum_iter_t *a_datum_iter)
{
    dap_chain_cs_dag_t *l_dag = DAP_CHAIN_CS_DAG(a_datum_iter->chain);
    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
    dap_chain_cs_dag_event_item_t *l_item = PVT(l_dag)->datums;
    s_datum_iter_fill(a_datum_iter, l_item);
    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
    return a_datum_iter->cur;
}

static dap_chain_datum_t *s_chain_callback_datum_iter_get_next(dap_chain_datum_iter_t *a_datum_iter)
{
    dap_chain_cs_dag_t *l_dag = DAP_CHAIN_CS_DAG(a_datum_iter->chain);
    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
    dap_chain_cs_dag_event_item_t *l_item = a_datum_iter->cur_item;
    if (l_item)
        l_item = l_item->hh_datums.next;
    s_datum_iter_fill(a_datum_iter, l_item);
    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
    return a_datum_iter->cur;
}

/**
 * @brief s_cli_dag
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 */
static int s_cli_dag(int argc, char ** argv, void **reply)
{
    char ** a_str_reply = (char **) reply;
    enum {
        SUBCMD_EVENT_CREATE,
        SUBCMD_EVENT_CANCEL,
        SUBCMD_EVENT_LIST,
        SUBCMD_EVENT_DUMP,
        SUBCMD_EVENT_SIGN,
        SUBCMD_EVENT_COUNT,
        SUBCMD_UNDEFINED
    } l_event_subcmd={0};

    int arg_index = 1;

    const char * l_event_cmd_str = NULL;
    const char * l_round_cmd_str = NULL;

    const char* l_event_hash_str = NULL;
    dap_chain_hash_fast_t l_event_hash = {0};

    const char * l_datum_hash_str = NULL;
    const char * l_cert_str;
    const char * l_from_events_str = NULL;

    dap_chain_t * l_chain = NULL;
    dap_chain_cs_dag_t * l_dag = NULL;
    dap_chain_net_t * l_net = NULL;

    dap_cli_server_cmd_find_option_val(argv, arg_index, arg_index + 1, "event", &l_event_cmd_str);
    dap_cli_server_cmd_find_option_val(argv, arg_index, arg_index + 1, "round", &l_round_cmd_str);

    arg_index++;
    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(argv, 0, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index, argc, argv, a_str_reply, &l_chain, &l_net, CHAIN_TYPE_INVALID);
    if ((l_net == NULL) || (l_chain == NULL)){
        return -1;
    } else if (a_str_reply && *a_str_reply) {
        DAP_DELETE(*a_str_reply);
        *a_str_reply = NULL;
    }
    l_dag = DAP_CHAIN_CS_DAG(l_chain);

    const char *l_chain_type = dap_chain_net_get_type(l_chain);

    if (!strstr(l_chain_type, "dag_")){
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Type of chain %s is not dag. This chain with type %s is not supported by this command",
                        l_chain->name, l_chain_type);
            return -42;
    }

    int ret = 0;
    if ( l_round_cmd_str ) {
        if ( strcmp(l_round_cmd_str,"complete") == 0 ){
            const char * l_cmd_mode_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-mode", &l_cmd_mode_str);
            bool l_verify_only = false;
            if ( dap_strcmp(l_cmd_mode_str,"verify only") == 0 ){
                l_verify_only = true;
            }
            log_it(L_NOTICE,"Round complete command accepted, forming new events");

            size_t l_objs_size=0;
            dap_global_db_obj_t * l_objs = dap_global_db_get_all_sync(l_dag->gdb_group_events_round_new,&l_objs_size);

            dap_string_t *l_str_ret_tmp= l_objs_size>0 ? dap_string_new("Completing round:\n") : dap_string_new("Completing round: no data");

            // list for verifed and added events
            dap_list_t *l_list_to_del = NULL;

            // Check if its ready or not
            for (size_t i = 0; i< l_objs_size; i++ ){
                dap_chain_cs_dag_event_round_item_t *l_round_item = (dap_chain_cs_dag_event_round_item_t *)l_objs[i].value;
                dap_chain_cs_dag_event_t *l_event = (dap_chain_cs_dag_event_t *)l_round_item->event_n_signs;
                size_t l_event_size = l_round_item->event_size;
                int l_ret_event_verify;
                if ( ( l_ret_event_verify = l_dag->callback_cs_verify (l_dag,l_event,l_event_size) ) !=0 ){// if consensus accept the event
                    dap_string_append_printf( l_str_ret_tmp,
                            "Error! Event %s is not passing consensus verification, ret code %d\n",
                                              l_objs[i].key, l_ret_event_verify );
                    ret = -30;
                    break;
                }else {
                    dap_string_append_printf( l_str_ret_tmp, "Event %s verification passed\n", l_objs[i].key);
                    // If not verify only mode we add
                    if ( ! l_verify_only ){
                        dap_chain_atom_ptr_t l_new_atom = DAP_DUP_SIZE(l_event, l_event_size); // produce deep copy of event;
                        if(s_chain_callback_atom_add(l_chain, l_new_atom, l_event_size) < 0) { // Add new atom in chain
                            DAP_DELETE(l_new_atom);
                            dap_string_append_printf(l_str_ret_tmp, "Event %s not added in chain\n", l_objs[i].key);
                        } else {
                            // add event to delete
                            l_list_to_del = dap_list_prepend(l_list_to_del, l_objs[i].key);
                            dap_string_append_printf(l_str_ret_tmp, "Event %s added in chain successfully\n",
                                    l_objs[i].key);
                        }

                    }
                }
            }
            // write events to file and delete events from db
            if(l_list_to_del) {
                if (dap_chain_cell_file_update(l_chain->cells) > 0) {
                    // delete events from db
                    dap_list_t *l_el;
                    DL_FOREACH(l_list_to_del, l_el) {
                        dap_global_db_del_sync(l_dag->gdb_group_events_round_new, (char*)l_el->data);
                    }
                }
                dap_chain_cell_close(l_chain->cells);
                dap_list_free(l_list_to_del);
            }

            // Cleaning up
            dap_global_db_objs_delete(l_objs, l_objs_size);
            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_ret_tmp->str);
            dap_string_free(l_str_ret_tmp, true);

            // Spread new  mempool changes and  dag events in network - going to SYNC_ALL
            // dap_chain_net_sync_all(l_net);
        }
        if (strcmp(l_round_cmd_str, "find") == 0) {
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-datum", &l_datum_hash_str);
            char *l_datum_in_hash = NULL;
            if (l_datum_hash_str) {
                if(!dap_strncmp(l_datum_hash_str, "0x", 2) || !dap_strncmp(l_datum_hash_str, "0X", 2)) {
                    l_datum_in_hash = dap_strdup(l_datum_hash_str);
                } else {
                    l_datum_in_hash = dap_enc_base58_to_hex_str_from_str(l_datum_hash_str);
                }
            } else {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "The -datum option was not specified, so "
                                                               "no datum is known to look for in rounds.\n");
                return 0;
            }
            dap_hash_fast_t l_datum_hash = {0};
            dap_chain_hash_fast_from_str(l_datum_in_hash, &l_datum_hash);
            if (dap_hash_fast_is_blank(&l_datum_hash)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "The -datum parameter is not a valid hash.\n");
                return 0;
            }
            size_t l_objs_size = 0;
            dap_global_db_obj_t * l_objs = dap_global_db_get_all_sync(l_dag->gdb_group_events_round_new, &l_objs_size);
            size_t l_search_events = 0;
            dap_string_t *l_events_str = dap_string_new("Events: \n");
            for (size_t i = 0; i < l_objs_size;i++) {
                dap_chain_cs_dag_event_round_item_t *l_round_item = (dap_chain_cs_dag_event_round_item_t *)l_objs[i].value;
                if (dap_hash_fast_compare(&l_round_item->round_info.datum_hash, &l_datum_hash)) {
                    dap_chain_cs_dag_event_t *l_event = (dap_chain_cs_dag_event_t *)l_round_item->event_n_signs;
                    size_t l_event_size = l_round_item->event_size;
                    dap_hash_fast_t ll_event_hash = {0};
                    dap_hash_fast(l_event, l_event_size, &ll_event_hash);
                    char *ll_event_hash_str = dap_hash_fast_to_str_new(&ll_event_hash);
                    l_search_events++;
                    dap_string_append_printf(l_events_str,
                                             "\t%zu) hash:%s cell_id:%zu\n", l_search_events, ll_event_hash_str,
                                             l_event->header.cell_id.uint64);
                    DAP_DELETE(ll_event_hash_str);
                }
            }
            dap_global_db_objs_delete(l_objs, l_objs_size);
            DAP_DELETE(l_datum_in_hash);
            if (l_search_events > 0) {
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                  "Datum with hash %s found in %zu events:\n%s\n", l_datum_hash_str,
                                                  l_search_events, l_events_str->str);
            } else {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Datum hash %s not found in round event.\n", l_datum_hash_str);
            }
            dap_string_free(l_events_str, true);
            return 0;
        }
    }else if ( l_event_cmd_str  ) {
        char *l_datum_hash_hex_str = NULL;
        char *l_datum_hash_base58_str = NULL;
        if  ( strcmp( l_event_cmd_str, "create" ) == 0  ) {
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-datum", &l_datum_hash_str);

            // datum hash may be in hex or base58 format
            if(l_datum_hash_str) {
                if(!dap_strncmp(l_datum_hash_str, "0x", 2) || !dap_strncmp(l_datum_hash_str, "0X", 2)) {
                    l_datum_hash_hex_str = dap_strdup(l_datum_hash_str);
                    l_datum_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_datum_hash_str);
                }
                else {
                    l_datum_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_datum_hash_str);
                    l_datum_hash_base58_str = dap_strdup(l_datum_hash_str);
                }
            }
            l_event_subcmd = SUBCMD_EVENT_CREATE;
        } else if (  strcmp( l_event_cmd_str, "cancel" ) == 0  ) {
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-event", &l_event_hash_str);
            l_event_subcmd = SUBCMD_EVENT_CANCEL;
        } else if ( strcmp( l_event_cmd_str, "list" ) == 0 ) {
            l_event_subcmd = SUBCMD_EVENT_LIST;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-from", &l_from_events_str);
        } else if ( strcmp( l_event_cmd_str,"dump") == 0 ) {
            l_event_subcmd = SUBCMD_EVENT_DUMP;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-from", &l_from_events_str);
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-event", &l_event_hash_str);
        } else if (  strcmp( l_event_cmd_str, "sign" ) == 0  ) {
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-event", &l_event_hash_str);
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-cert", &l_cert_str);
            l_event_subcmd = SUBCMD_EVENT_SIGN;
        } else if (strcmp(l_event_cmd_str, "count") == 0) {
            l_event_subcmd = SUBCMD_EVENT_COUNT;
        } else {
            l_event_subcmd = SUBCMD_UNDEFINED;
        }

        char *l_event_hash_hex_str = NULL, *l_event_hash_base58_str = NULL;
        // datum hash may be in hex or base58 format
        if(l_event_hash_str) {
            if(!dap_strncmp(l_event_hash_str, "0x", 2) || !dap_strncmp(l_event_hash_str, "0X", 2)) {
                l_event_hash_hex_str = dap_strdup(l_event_hash_str);
                l_event_hash_base58_str = dap_enc_base58_from_hex_str_to_str(l_event_hash_str);
            }
            else {
                l_event_hash_hex_str = dap_enc_base58_to_hex_str_from_str(l_event_hash_str);
                l_event_hash_base58_str = dap_strdup(l_event_hash_str);
            }
        }

        if (l_event_hash_hex_str)
            dap_chain_hash_fast_from_str(l_event_hash_hex_str, &l_event_hash);

        switch (l_event_subcmd) {

        case SUBCMD_EVENT_CREATE: {
            char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_new(l_chain);
            size_t l_datum_size = 0;
            dap_chain_datum_t *l_datum = (dap_chain_datum_t*)
                    dap_global_db_get_sync(l_gdb_group_mempool, l_datum_hash_hex_str, &l_datum_size, NULL, NULL);
            if (s_callback_add_datums(l_chain, &l_datum, 1)) {
                char *l_datums_datum_hash_str;
                dap_get_data_hash_str_static(l_datum->data, l_datum->header.data_size, l_datums_datum_hash_str);
                if (!dap_global_db_del_sync(l_gdb_group_mempool, l_datum_hash_str)) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                      "Converted datum %s from mempool to event in the new forming round ",
                                                      l_datum_hash_str);
                    ret = 0;
                } else {
                    dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                      "Warning! Can't delete datum %s from mempool after conversion to event in the new forming round ",
                                                      l_datum_hash_str);
                    ret = 1;
                }
            } else {
                if (!dap_strcmp(l_hash_out_type, "hex")) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                      "Warning! Can't convert datum %s from mempool to event in the new forming round ", l_datum_hash_hex_str);
                } else {
                    dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                      "Warning! Can't convert datum %s from mempool to event in the new forming round ", l_datum_hash_base58_str);

                    ret = -12;
                }
            }
            DAP_DELETE(l_gdb_group_mempool);
            // dap_chain_net_sync_all(l_net);
        } break;  /* SUBCMD_EVENT_CREATE */

        case SUBCMD_EVENT_CANCEL: {
            char *l_gdb_group_events = DAP_CHAIN_CS_DAG(l_chain)->gdb_group_events_round_new;
            if (dap_global_db_del_sync(l_gdb_group_events, l_event_hash_hex_str) == 0) {
                if(!dap_strcmp(l_hash_out_type, "hex")) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                      "Successfuly removed event %s from the new forming round ",
                                                      l_event_hash_hex_str);
                } else {
                    dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                      "Successfuly removed event %s from the new forming round ",
                                                      l_event_hash_base58_str);
                }
                ret = 0;
            } else {
                dap_chain_cs_dag_event_item_t * l_event_item = NULL;
                pthread_mutex_lock(&PVT(l_dag)->events_mutex);
                HASH_FIND(hh,PVT(l_dag)->events,&l_event_hash,sizeof(l_event_hash),l_event_item);
                pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
                if (l_event_item) {
                    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
                    HASH_DELETE(hh, PVT(l_dag)->events, l_event_item);
                    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
                    if(!dap_strcmp(l_hash_out_type, "hex")) {
                        log_it(L_WARNING, "Dropped event %s from chains! Hope you know what are you doing!",
                               l_event_hash_hex_str);
                        dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Dropped event 0x%s from chains! Hope you know what are you doing! ",
                                                          l_event_hash_hex_str);
                    } else {
                        log_it(L_WARNING, "Dropped event %s from chains! Hope you know what are you doing!",
                               l_event_hash_base58_str);
                        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                          "Dropped event 0x%s from chains! Hope you know what are you doing! ",
                                                          l_event_hash_base58_str);
                    }
                    dap_chain_save_all(l_chain);
                } else {
                    if(!dap_strcmp(l_hash_out_type, "hex")) {
                        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                          "Can't remove event 0x%s ",
                                                          l_event_hash_hex_str);
                    } else {
                        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                          "Can't remove event 0x%s ",
                                                          l_event_hash_base58_str);
                    }
                    ret = -1;
                }
            }
            // dap_chain_net_sync_gdb(l_net);
        } break; /* SUBCMD_EVENT_CANCEL */

        case SUBCMD_EVENT_DUMP: {
            dap_chain_cs_dag_event_round_item_t *l_round_item = NULL;
            dap_chain_cs_dag_event_t *l_event = NULL;
            size_t l_event_size = 0;
                if (l_from_events_str && strcmp(l_from_events_str,"round.new") == 0) {
                    const char * l_gdb_group_events = l_dag->gdb_group_events_round_new;
                    size_t l_round_item_size = 0;
                    l_round_item = (dap_chain_cs_dag_event_round_item_t *)dap_global_db_get_sync(l_gdb_group_events,
                                                    l_event_hash_str, &l_round_item_size, NULL, NULL);
                    if (l_round_item) {
                        l_event_size = l_round_item->event_size;
                        l_event = (dap_chain_cs_dag_event_t *)l_round_item->event_n_signs;
                    }
                } else if (l_from_events_str && strcmp(l_from_events_str,"events_lasts") == 0) {
                    dap_chain_cs_dag_event_item_t * l_event_item = NULL;
                    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
                    HASH_FIND(hh,PVT(l_dag)->events_lasts_unlinked,&l_event_hash,sizeof(l_event_hash),l_event_item);
                    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
                    if ( l_event_item )
                        l_event = l_event_item->event;
                    else {
                        ret = -23;
                        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                          "Can't find event %s in events_last table\n", l_event_hash_str);
                        break;
                    }
                } else if (!l_from_events_str || strcmp(l_from_events_str,"events") == 0) {
                    dap_chain_cs_dag_event_item_t * l_event_item = NULL;
                    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
                    HASH_FIND(hh,PVT(l_dag)->events,&l_event_hash,sizeof(l_event_hash),l_event_item);
                    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
                    if ( l_event_item ) {
                        l_event = l_event_item->event;
                        l_event_size = l_event_item->event_size;
                    } else {
                        ret = -24;
                        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                          "Can't find event %s in events table\n", l_event_hash_str);
                        break;
                    }
                } else if (l_from_events_str && strcmp(l_from_events_str,"threshold") == 0) {
                    dap_chain_cs_dag_event_item_t * l_event_item = NULL;
                    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
                    HASH_FIND(hh,PVT(l_dag)->events_treshold,&l_event_hash,sizeof(l_event_hash),l_event_item);
                    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
                    if (l_event_item)
                        l_event = l_event_item->event;
                    else {
                        ret = -23;
                        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                          "Can't find event %s in threshold table\n", l_event_hash_str);
                        break;
                    }
                } else {
                    ret = -22;
                    dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Wrong events_from option \"%s\", need one of variant: events, round.new, events_lasts, threshold", l_from_events_str);
                    break;

                }
                if ( l_event ){
                    dap_string_t * l_str_tmp = dap_string_new(NULL);
                    char buf[50];

                    dap_string_append_printf(l_str_tmp,"\nEvent %s:\n", l_event_hash_str);

                    // Round info
                    if (l_from_events_str && strcmp(l_from_events_str,"round.new") == 0) {
                        dap_string_append_printf(l_str_tmp,
                            "\tRound info:\n\t\tsigns reject: %d\n",
                            l_round_item->round_info.reject_count);
                        char * l_hash_str = dap_chain_hash_fast_to_str_new(&l_round_item->round_info.datum_hash);
                        dap_string_append_printf(l_str_tmp, "\t\tdatum_hash: %s\n", l_hash_str);
                        DAP_DELETE(l_hash_str);
                        dap_gbd_time_to_str_rfc822(buf, 50, l_round_item->round_info.ts_update);
                        dap_string_append_printf(l_str_tmp,"\t\tts_update: %s\n", buf);
                    }

                     // Header
                    dap_string_append_printf(l_str_tmp,"\t\tHeader:\n");
                    dap_string_append_printf(l_str_tmp,"\t\t\tversion: %hu\n",l_event->header.version);
                    dap_string_append_printf(l_str_tmp,"\t\t\tround ID: %"DAP_UINT64_FORMAT_U"\n",l_event->header.round_id);
                    dap_string_append_printf(l_str_tmp,"\t\t\tcell_id: 0x%016"DAP_UINT64_FORMAT_x"\n",l_event->header.cell_id.uint64);
                    dap_string_append_printf(l_str_tmp,"\t\t\tchain_id: 0x%016"DAP_UINT64_FORMAT_X"\n",l_event->header.chain_id.uint64);
                    dap_time_to_str_rfc822(buf, 50, l_event->header.ts_created);
                    dap_string_append_printf(l_str_tmp,"\t\t\tts_created: %s\n", buf );

                    // Hash links
                    dap_string_append_printf(l_str_tmp,"\t\t\thashes:\tcount: %u\n",l_event->header.hash_count);
                    for (uint16_t i=0; i < l_event->header.hash_count; i++){
                        dap_chain_hash_fast_t * l_hash = (dap_chain_hash_fast_t *) (l_event->hashes_n_datum_n_signs +
                                i*sizeof (dap_chain_hash_fast_t));
                        char * l_hash_str = dap_chain_hash_fast_to_str_new(l_hash);
                        dap_string_append_printf(l_str_tmp,"\t\t\t\thash: %s\n",l_hash_str);
                        DAP_DELETE(l_hash_str);
                    }
                    size_t l_offset =  l_event->header.hash_count*sizeof (dap_chain_hash_fast_t);
                    dap_chain_datum_t * l_datum = (dap_chain_datum_t*) (l_event->hashes_n_datum_n_signs + l_offset);
                    size_t l_datum_size =  dap_chain_datum_size(l_datum);

                    // Nested datum
                    const char *l_datum_type = NULL;
                    DAP_DATUM_TYPE_STR(l_datum->header.type_id, l_datum_type)
                    dap_string_append_printf(l_str_tmp,"\t\tdatum:\tdatum_size: %zu\n",l_datum_size);
                    dap_string_append_printf(l_str_tmp,"\t\t\tversion:=0x%02hhX\n", l_datum->header.version_id);
                    dap_string_append_printf(l_str_tmp,"\t\t\ttype_id:=%s\n", l_datum_type);
                    dap_time_to_str_rfc822(buf, 50, l_datum->header.ts_create);
                    dap_string_append_printf(l_str_tmp,"\t\t\tts_create=%s\n", buf);
                    dap_string_append_printf(l_str_tmp,"\t\t\tdata_size=%u\n", l_datum->header.data_size);

                    // Signatures
                    dap_string_append_printf(l_str_tmp,"\t\t\t\tsigns:\tcount: %u\n",l_event->header.signs_count);
                    l_offset += l_datum_size;
                    while (l_offset + sizeof (l_event->header) < l_event_size ){
                        dap_sign_t * l_sign =(dap_sign_t *) (l_event->hashes_n_datum_n_signs +l_offset);
                        size_t l_sign_size = dap_sign_get_size(l_sign);
                        if (l_sign_size == 0 ){
                            dap_string_append_printf(l_str_tmp,"\t\t\t\tERROR: wrong sign size 0, stop parsing headers\n");
                            break;
                        }
                        dap_chain_hash_fast_t l_pkey_hash;
                        char *l_hash_str;
                        dap_sign_get_pkey_hash(l_sign, &l_pkey_hash);
                        if (!dap_strcmp(l_hash_out_type, "hex"))
                            l_hash_str = dap_chain_hash_fast_to_str_new(&l_pkey_hash);
                        else
                            l_hash_str = dap_enc_base58_encode_hash_to_str(&l_pkey_hash);
                        dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\ttype: %s\tpkey_hash: %s"
                                                           "\n", dap_sign_type_to_str( l_sign->header.type ),
                                                 l_hash_str );
                        l_offset += l_sign_size;
                        DAP_DELETE( l_hash_str);
                    }
                    dap_chain_datum_dump(l_str_tmp, l_datum, l_hash_out_type, l_net->pub.id);

                    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_tmp->str);
                    dap_string_free(l_str_tmp, true);
                    ret=0;
                }else {
                    dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                      "Can't find event 0x%s in the new forming round ",
                                                      l_event_hash_str);
                    ret=-10;
                }
                DAP_DELETE(l_round_item);
            } break;

            case SUBCMD_EVENT_LIST: {
                if (l_from_events_str && strcmp(l_from_events_str,"round.new") == 0) {
                    char * l_gdb_group_events = DAP_CHAIN_CS_DAG(l_chain)->gdb_group_events_round_new;
                    dap_string_t * l_str_tmp = dap_string_new("");
                    if ( l_gdb_group_events ){
                        dap_global_db_obj_t * l_objs;
                        size_t l_objs_count = 0;
                        l_objs = dap_global_db_get_all_sync(l_gdb_group_events,&l_objs_count);
                        dap_string_append_printf(l_str_tmp,"%s.%s: Found %zu records :\n",l_net->pub.name,l_chain->name,l_objs_count);

                        for (size_t i = 0; i< l_objs_count; i++){
                            if (dap_strcmp(l_objs[i].key, DAG_ROUND_CURRENT_KEY)) {
                                dap_chain_cs_dag_event_t *l_event = (dap_chain_cs_dag_event_t *)
                                        ((dap_chain_cs_dag_event_round_item_t *) l_objs[i].value)->event_n_signs;
                                char buf[50];
                                dap_time_to_str_rfc822(buf, 50, l_event->header.ts_created);
                                dap_string_append_printf(l_str_tmp, "\t%s: ts_create=%s\n",
                                                         l_objs[i].key, buf);
                            } else {
                                uint64_t l_number_current_round = *(uint64_t*)l_objs[i].value;
                                dap_string_append_printf(l_str_tmp, "\t%s: %" DAP_UINT64_FORMAT_U "\n", l_objs[i].key,
                                                         l_number_current_round);
                            }
                        }
                        if (l_objs && l_objs_count )
                            dap_global_db_objs_delete(l_objs, l_objs_count);
                        ret = 0;
                    } else {
                        dap_string_append_printf(l_str_tmp,"%s.%s: Error! No GlobalDB group!\n",l_net->pub.name,l_chain->name);
                        ret = -2;

                    }
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_tmp->str);
                    dap_string_free(l_str_tmp, true);
                } else if (!l_from_events_str || (strcmp(l_from_events_str,"events") == 0)) {
                    dap_string_t * l_str_tmp = dap_string_new(NULL);
                    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
                    dap_chain_cs_dag_event_item_t * l_event_item = NULL,*l_event_item_tmp = NULL;
                    HASH_ITER(hh,PVT(l_dag)->events,l_event_item, l_event_item_tmp ) {
                        char buf[50];
                        dap_time_to_str_rfc822(buf, 50, l_event_item->event->header.ts_created);
                        char * l_event_item_hash_str = dap_chain_hash_fast_to_str_new( &l_event_item->hash);
                        dap_string_append_printf(l_str_tmp,"\t%s: ts_create=%s\n",
                                                 l_event_item_hash_str, buf);
                        DAP_DELETE(l_event_item_hash_str);
                    }
                    size_t l_events_count = HASH_COUNT(PVT(l_dag)->events);
                    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
                    dap_string_append_printf(l_str_tmp,"%s.%s have total %zu events :\n",
                                             l_net->pub.name, l_chain->name, l_events_count);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_tmp->str);
                    dap_string_free(l_str_tmp, true);
                 }else if (l_from_events_str && (strcmp(l_from_events_str,"threshold") == 0) ){
                    dap_string_t * l_str_tmp = dap_string_new(NULL);
                    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
                    dap_chain_cs_dag_event_item_t * l_event_item = NULL,*l_event_item_tmp = NULL;
                    dap_string_append_printf(l_str_tmp,"\nDAG threshold events:\n");
                    HASH_ITER(hh,PVT(l_dag)->events_treshold,l_event_item, l_event_item_tmp ) {
                        char buf[50];
                        dap_time_to_str_rfc822(buf, 50, l_event_item->event->header.ts_created);
                        char * l_event_item_hash_str = dap_chain_hash_fast_to_str_new( &l_event_item->hash);
                        dap_string_append_printf(l_str_tmp,"\t%s: ts_create=%s\n",
                                                 l_event_item_hash_str, buf);
                        DAP_DELETE(l_event_item_hash_str);
                    }
                    size_t l_events_count = HASH_COUNT(PVT(l_dag)->events_treshold);
                    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
                    dap_string_append_printf(l_str_tmp,"%s.%s have total %zu events in threshold :\n",
                                             l_net->pub.name, l_chain->name, l_events_count);
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_tmp->str);
                    dap_string_free(l_str_tmp, true);

                }else {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Undefined events source for listing ");
                    ret=-14;

                }
            } break;
            case SUBCMD_EVENT_COUNT: {
                dap_string_t *l_ret_str = dap_string_new(NULL);
                dap_string_append_printf(l_ret_str, "%s.%s:\n", l_net->pub.name, l_chain->name);
                const char * l_gdb_group_events = DAP_CHAIN_CS_DAG(l_chain)->gdb_group_events_round_new;
                if (l_gdb_group_events) {
                    size_t l_objs_count = 0;
                    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_gdb_group_events,&l_objs_count);
                    dap_string_append_printf(l_ret_str,"%zu in round.new\n", l_objs_count);
                }
                size_t l_event_count = HASH_COUNT(PVT(l_dag)->events);
                size_t l_event_treshold_count = HASH_COUNT(PVT(l_dag)->events_treshold);
                dap_string_append_printf(l_ret_str, "%zu atoms(s) in events\n%zu atom(s) in threshold", l_event_count, l_event_treshold_count);
                dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_ret_str->str);
                dap_string_free(l_ret_str, true);
            } break;
            case SUBCMD_EVENT_SIGN: { // Sign event command
                char * l_gdb_group_events = l_dag->gdb_group_events_round_new;
                size_t l_round_item_size = 0;
                dap_chain_cs_dag_event_round_item_t *l_round_item =
                                    (dap_chain_cs_dag_event_round_item_t *)dap_global_db_get_sync(l_gdb_group_events,
                                                        l_event_hash_hex_str, &l_round_item_size, NULL, NULL);
                if (l_round_item) {
                    dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
                    if (l_cert && l_cert->enc_key->priv_key_data) {
                        size_t l_event_size = l_round_item->event_size;
                        dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *)DAP_DUP_SIZE(l_round_item->event_n_signs, l_event_size);
                        size_t l_event_size_new = dap_chain_cs_dag_event_sign_add(&l_event, l_event_size, l_cert->enc_key);
                        if ( l_event_size_new ) {
                            dap_chain_hash_fast_t l_event_new_hash;
                            dap_chain_cs_dag_event_calc_hash(l_event, l_event_size_new, &l_event_new_hash);
                            char * l_event_new_hash_hex_str = dap_chain_hash_fast_to_str_new(&l_event_new_hash);
                            char * l_event_new_hash_base58_str = NULL;
                            if (dap_strcmp(l_hash_out_type, "hex"))
                                l_event_new_hash_base58_str = dap_enc_base58_encode_hash_to_str(&l_event_new_hash);

                            if (dap_chain_cs_dag_event_gdb_set(l_dag, l_event_new_hash_hex_str, l_event,
                                                               l_event_size_new, l_round_item)) {
                                dap_cli_server_cmd_set_reply_text(a_str_reply,
                                            "Added new sign with cert \"%s\", event %s placed back in round.new\n",
                                            l_cert_str, l_event_new_hash_base58_str ?
                                                                      l_event_new_hash_base58_str : l_event_new_hash_hex_str);
                            } else {
                                dap_cli_server_cmd_set_reply_text(a_str_reply,
                                            "GDB Error: Can't place event %s with new sign back in round.new\n",
                                            l_event_new_hash_base58_str ? l_event_new_hash_base58_str : l_event_new_hash_hex_str);
                                ret = -31;
                            }
                            DAP_DELETE(l_event);
                            DAP_DELETE(l_event_new_hash_hex_str);
                            DAP_DEL_Z(l_event_new_hash_base58_str);
                        } else {
                            dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                          "Can't sign event %s in round.new\n",
                                                          l_event_hash_str);
                            ret=-1;
                        }
                    } else {
                        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                          "No valid certificate provided for event %s signing\n",
                                                          l_event_hash_str);
                        ret = -50;
                    }
                    DAP_DELETE(l_round_item);
                } else {
                    dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                      "Can't find event %s in round.new - only place where could be signed the new event\n",
                                                      l_event_hash_str);
                    ret = -30;
                }
            } break;
            case SUBCMD_UNDEFINED: {
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                                                  "Undefined event subcommand \"%s\" ",
                                                  l_event_cmd_str);
                ret=-11;
            }
        }
        DAP_DEL_Z(l_datum_hash_hex_str);
        DAP_DEL_Z(l_datum_hash_base58_str);
        DAP_DEL_Z(l_event_hash_hex_str);
        DAP_DEL_Z(l_event_hash_base58_str);
    } else {
        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                          "Undefined subcommand");
        ret = -13;
    }
    return ret;
}

static size_t s_dap_chain_callback_get_count_tx(dap_chain_t *a_chain)
{
    return PVT(DAP_CHAIN_CS_DAG(a_chain))->tx_count;
}


static dap_list_t *s_dap_chain_callback_get_txs(dap_chain_t *a_chain, size_t a_count, size_t a_page, bool a_reverse)
{
    UNUSED(a_reverse);
    dap_chain_cs_dag_t *l_dag = DAP_CHAIN_CS_DAG(a_chain);
    size_t l_count = s_dap_chain_callback_get_count_tx(a_chain);
    size_t l_offset = a_count * a_page;
    if (a_page < 2)
        l_offset = 0;
    if (l_offset > l_count){
        return NULL;
    }
    dap_list_t *l_list = NULL;
    size_t l_counter = 0;
    size_t l_end = l_offset + a_count;
    for (dap_chain_cs_dag_event_item_t *ptr = PVT(l_dag)->datums; ptr != NULL && l_counter < l_end; ptr = ptr->hh_datums.next){
        dap_chain_datum_t *l_datum = dap_chain_cs_dag_event_get_datum(ptr->event, ptr->event_size);
        if (l_datum->header.type_id == DAP_CHAIN_DATUM_TX && l_counter++ >= l_offset) {
            dap_chain_datum_tx_t  *l_tx = (dap_chain_datum_tx_t*)l_datum->data;
            l_list = dap_list_append(l_list, l_tx);
        }
    }
    return l_list;
}

static size_t s_dap_chain_callback_get_count_atom(dap_chain_t *a_chain){
    dap_chain_cs_dag_t  *l_dag = DAP_CHAIN_CS_DAG(a_chain);
    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
    size_t l_count = HASH_COUNT(PVT(l_dag)->events);
    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
    return l_count;
}

static dap_list_t *s_callback_get_atoms(dap_chain_t *a_chain, size_t a_count, size_t a_page, bool a_reverse)
{
    UNUSED(a_reverse);
    dap_chain_cs_dag_t  *l_dag = DAP_CHAIN_CS_DAG(a_chain);
    dap_chain_cs_dag_pvt_t *l_dag_pvt = PVT(l_dag);
    if (!l_dag_pvt->events) {
        return NULL;
    }
    size_t l_offset = a_count * (a_page - 1);
    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
    size_t l_count = HASH_COUNT(l_dag_pvt->events);
    if (a_page < 2)
        l_offset = 0;
    if (l_offset > l_count){
        pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
        return NULL;
    }
    dap_list_t *l_list = NULL;
    size_t l_counter = 0;
    size_t l_end = l_offset + a_count;

    dap_chain_cs_dag_event_item_t *l_ptr = l_dag_pvt->events->hh.tbl->tail->prev;
    if (!l_ptr)
        l_ptr = l_dag_pvt->events;
    else
        l_ptr = l_ptr->hh.next;
    for (dap_chain_cs_dag_event_item_t *ptr = l_ptr; ptr != NULL && l_counter < l_end; ptr = ptr->hh.prev){
        if (l_counter >= l_offset){
            dap_chain_cs_dag_event_t *l_event = ptr->event;
            l_list = dap_list_append(l_list, l_event);
            l_list = dap_list_append(l_list, &ptr->event_size);
        }
        l_counter++;
    }
    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
    return l_list;
}
