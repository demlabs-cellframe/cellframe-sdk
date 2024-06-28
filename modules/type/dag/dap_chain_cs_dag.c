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
    uint64_t event_number;
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
    dap_interval_timer_t treshold_fee_timer;
    uint64_t tx_count;
} dap_chain_cs_dag_pvt_t;

#define PVT(a) ((dap_chain_cs_dag_pvt_t *) a->_pvt )

static int s_chain_cs_dag_new(dap_chain_t *a_chain, dap_config_t *a_chain_cfg);
static void s_chain_cs_dag_delete(dap_chain_t *a_chain);
static void s_dap_chain_cs_dag_purge(dap_chain_t *a_chain);
static void s_dap_chain_cs_dag_threshold_free(dap_chain_cs_dag_t *a_dag);
static dap_chain_cs_dag_event_item_t *s_dag_proc_treshold(dap_chain_cs_dag_t *a_dag);

// Atomic element organization callbacks
static dap_chain_atom_verify_res_t s_chain_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t , size_t, dap_hash_fast_t *a_atom_hash);                      //    Accept new event in dag
static dap_chain_atom_ptr_t s_chain_callback_atom_add_from_treshold(dap_chain_t * a_chain, size_t *a_event_size_out);                    //    Accept new event in dag from treshold
static dap_chain_atom_verify_res_t s_chain_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_ptr_t , size_t, dap_hash_fast_t *a_atom_hash);                   //    Verify new event in dag
static size_t s_chain_callback_atom_get_static_hdr_size(void);                               //    Get dag event header size

static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create(dap_chain_t * a_chain, dap_chain_cell_id_t a_cell_id, dap_hash_fast_t *a_hash_from);

static dap_chain_atom_ptr_t s_chain_callback_atom_iter_find_by_hash(dap_chain_atom_iter_t * a_atom_iter ,
                                                                       dap_chain_hash_fast_t * a_atom_hash, size_t * a_atom_size);
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_by_num(dap_chain_atom_iter_t *a_atom_iter, uint64_t a_atom_num);
static dap_chain_datum_t *s_chain_callback_atom_find_by_datum_hash(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_datum_hash,
                                                                   dap_chain_hash_fast_t *a_event_hash, int *a_ret_code);
static dap_chain_datum_t** s_chain_callback_atom_get_datum(dap_chain_atom_ptr_t a_event, size_t a_atom_size, size_t *a_datums_count);
static dap_time_t s_chain_callback_atom_get_timestamp(dap_chain_atom_ptr_t a_atom) { return ((dap_chain_cs_dag_event_t *)a_atom)->header.ts_created; }
//    Get event(s) from dag
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get(dap_chain_atom_iter_t *a_atom_iter, dap_chain_iter_op_t a_operation, size_t *a_atom_size);
static dap_chain_atom_ptr_t *s_chain_callback_atom_iter_get_links( dap_chain_atom_iter_t * a_atom_iter , size_t *a_links_size,
                                                                  size_t ** a_links_size_ptr );  //    Get list of linked events

// Delete iterator
static void s_chain_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter );                  //    Get the fisrt event from dag

static bool s_chain_callback_datums_pool_proc(dap_chain_t * a_chain, dap_chain_datum_t *a_datum);
static size_t s_callback_add_datums(dap_chain_t *a_chain, dap_chain_datum_t **a_datums, size_t a_datums_count);

// Datum ops
static dap_chain_datum_iter_t *s_chain_callback_datum_iter_create(dap_chain_t *a_chain);
static void s_chain_callback_datum_iter_delete(dap_chain_datum_iter_t *a_datum_iter);
static dap_chain_datum_t *s_chain_callback_datum_iter_get_first(dap_chain_datum_iter_t *a_datum_iter); // Get the fisrt datum from dag
static dap_chain_datum_t *s_chain_callback_datum_iter_get_next(dap_chain_datum_iter_t *a_datum_iter); // Get the next datum from dag

static int s_cli_dag(int argc, char ** argv, void **a_str_reply);
void s_dag_events_lasts_process_new_last_event(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_item_t * a_event_item);

static uint64_t s_dap_chain_callback_get_count_tx(dap_chain_t *a_chain);
static dap_list_t *s_dap_chain_callback_get_txs(dap_chain_t *a_chain, size_t a_count, size_t a_page, bool a_reverse);

static uint64_t s_dap_chain_callback_get_count_atom(dap_chain_t *a_chain);
static dap_list_t *s_callback_get_atoms(dap_chain_t *a_chain, size_t a_count, size_t a_page, bool a_reverse);

static bool s_seed_mode = false, s_debug_more = false, s_threshold_enabled = false;

/**
 * @brief dap_chain_cs_dag_init
 * @return always 0
 */
int dap_chain_cs_dag_init()
{
    srand((unsigned int) time(NULL));
    dap_chain_cs_type_add( "dag", s_chain_cs_dag_new );
    s_seed_mode         = dap_config_get_item_bool_default(g_config, "general", "seed_mode",        false);
    s_debug_more        = dap_config_get_item_bool_default(g_config, "dag",     "debug_more",       false);
    s_threshold_enabled = dap_config_get_item_bool_default(g_config, "dag",     "threshold_enabled",false);
    debug_if(s_debug_more, L_DEBUG, "Thresholding %s", s_threshold_enabled ? "enabled" : "disabled");
    dap_cli_server_cmd_add ("dag", s_cli_dag, "DAG commands",        
        "dag event sign -net <net_name> -chain <chain_name> -event <event_hash>\n"
            "\tAdd sign to event <event hash> in round.new. Hash doesn't include other signs so event hash\n"
            "\tdoesn't changes after sign add to event. \n\n"
        "dag event dump -net <net_name> -chain <chain_name> -event <event_hash> -from {events | events_lasts | threshold | round.new  | round.<Round id in hex>} [-H {hex | base58(default)}]\n"
            "\tDump event info\n\n"
        "dag event list -net <net_name> -chain <chain_name> -from {events | events_lasts | threshold | round.new | round.<Round id in hex>} [-limit] [-offset]\n\n"
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

/**
 * @brief s_chain_cs_dag_new
 * @param a_chain
 * @param a_chain_cfg
 */
static int s_chain_cs_dag_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg)
{
    dap_chain_cs_dag_t * l_dag = DAP_NEW_Z(dap_chain_cs_dag_t);
    if (!l_dag){
        log_it(L_CRITICAL, "%s", g_error_memory_alloc);
        return -1;
    }
    l_dag->_pvt = DAP_NEW_Z(dap_chain_cs_dag_pvt_t);
    if (!l_dag->_pvt){
        log_it(L_CRITICAL, "%s", g_error_memory_alloc);
        DAP_DELETE(l_dag);
        return -1;
    }
    l_dag->chain = a_chain;

    pthread_mutexattr_t l_mutex_attr;
    pthread_mutexattr_init(&l_mutex_attr);
    pthread_mutexattr_settype(&l_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&PVT(l_dag)->events_mutex, &l_mutex_attr);
    pthread_mutexattr_destroy(&l_mutex_attr);

    a_chain->callback_delete = s_chain_cs_dag_delete;
    a_chain->callback_purge = s_dap_chain_cs_dag_purge;

    // Atom element callbacks
    a_chain->callback_atom_add = s_chain_callback_atom_add ;  // Accept new element in chain
    a_chain->callback_atom_add_from_treshold = s_chain_callback_atom_add_from_treshold;  // Accept new elements in chain from treshold
    a_chain->callback_atom_verify = s_chain_callback_atom_verify ;  // Verify new element in chain
    a_chain->callback_atom_get_hdr_static_size = s_chain_callback_atom_get_static_hdr_size; // Get dag event hdr size

    a_chain->callback_atom_iter_create = s_chain_callback_atom_iter_create;
    a_chain->callback_atom_iter_delete = s_chain_callback_atom_iter_delete;
    a_chain->callback_atom_iter_get = s_chain_callback_atom_iter_get;               // Linear pass through
    a_chain->callback_atom_find_by_hash = s_chain_callback_atom_iter_find_by_hash;  // Get element by hash
    a_chain->callback_atom_get_by_num = s_chain_callback_atom_iter_get_by_num;
    a_chain->callback_atom_iter_get_links = s_chain_callback_atom_iter_get_links;

    a_chain->callback_atom_get_datums = s_chain_callback_atom_get_datum;
    a_chain->callback_atom_get_timestamp = s_chain_callback_atom_get_timestamp;

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
        log_it(L_CRITICAL, "%s", g_error_memory_alloc);
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
#ifndef DAP_LEDGER_TEST
    l_dag->gdb_group_events_round_new = dap_strdup_printf(l_dag->is_celled ? "dag-%s-%s-%016llx-round.new" : "dag-%s-%s-round.new",
                                          l_net->pub.gdb_groups_prefix, a_chain->name, 0LLU);
#else
    l_dag->gdb_group_events_round_new = dap_strdup_printf(l_dag->is_celled ? "dag-%s-%s-%016llx-round.new" : "dag-%s-%s-round.new",
                                        "Snet", a_chain->name, 0LLU);
#endif
    PVT(l_dag)->treshold_fee_timer = dap_interval_timer_create(900000, (dap_timer_callback_t)s_dap_chain_cs_dag_threshold_free, l_dag);

    log_it (L_NOTICE, "DAG chain initialized (%s)", l_dag->is_single_line ? "single line" : "multichain");

    return 0;
}

static void s_dap_chain_cs_dag_threshold_free(dap_chain_cs_dag_t *a_dag) {
    dap_chain_cs_dag_pvt_t *l_pvt = PVT(a_dag);
    dap_chain_cs_dag_event_item_t *l_current = NULL, *l_tmp = NULL;
    dap_nanotime_t  l_time_cut_off = dap_nanotime_now() - dap_nanotime_from_sec(7200); //7200 sec = 2 hours.
    pthread_mutex_lock(&l_pvt->events_mutex);
    //Free threshold
    HASH_ITER(hh, l_pvt->events_treshold, l_current, l_tmp) {
        if (l_current->ts_added < l_time_cut_off) {
            dap_chain_cs_dag_blocked_t *l_el = DAP_NEW(dap_chain_cs_dag_blocked_t);
            if (!l_el) {
        log_it(L_CRITICAL, "%s", g_error_memory_alloc);
                pthread_mutex_unlock(&l_pvt->events_mutex);
                return;
            }
            l_el->hash = l_current->hash;
            HASH_ADD(hh, l_pvt->removed_events_from_treshold, hash, sizeof(dap_chain_hash_fast_t), l_el);
            char *l_hash_dag = dap_hash_fast_to_str_new(&l_current->hash);
            if (!a_dag->chain->is_mapped && !l_current->mapped_region)
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
            if (!a_dag->chain->is_mapped && !l_current->mapped_region)
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
    // Clang bug at this, l_event_current should change at every loop cycle
    HASH_ITER(hh, l_dag_pvt->events, l_event_current, l_event_tmp) {
        HASH_DEL(l_dag_pvt->events, l_event_current);
        if (!a_chain->is_mapped && !l_event_current->mapped_region)
            DAP_DELETE(l_event_current->event);
        DAP_DELETE(l_event_current);
    }
    HASH_ITER(hh, l_dag_pvt->events_lasts_unlinked, l_event_current, l_event_tmp) {
        HASH_DEL(l_dag_pvt->events_lasts_unlinked, l_event_current);
        //if (!a_chain->is_mapped && !l_event_current->mapped_region)
        //    DAP_DELETE(l_event_current->event);
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
    dap_chain_cell_delete_all_and_free_file(a_chain);
}

/**
 * @brief s_chain_cs_dag_delete
 * @param a_dag
 * @return
 */
static void s_chain_cs_dag_delete(dap_chain_t * a_chain)
{
    s_dap_chain_cs_dag_purge(a_chain);
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG ( a_chain );
    pthread_mutex_destroy(& PVT(l_dag)->events_mutex);
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
    if (!l_datum) {
        log_it(L_WARNING, "Corrupted event, failed to extract datum from event.");
        return -2;
    }
    if(a_event_item->event_size < sizeof(l_datum->header) ){
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
    a_event_item->event_number = HASH_COUNT(PVT(a_dag)->events) + 1;
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
static dap_chain_atom_verify_res_t s_chain_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t a_atom, size_t a_atom_size, dap_hash_fast_t *a_atom_hash)
{
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG(a_chain);
    dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *) a_atom;

    dap_chain_cs_dag_event_item_t * l_event_item = DAP_NEW_Z(dap_chain_cs_dag_event_item_t);
    if (!l_event_item) {
        log_it(L_CRITICAL, "Memory allocation error");
        return ATOM_REJECT;
    }
    pthread_mutex_t *l_events_mutex = &PVT(l_dag)->events_mutex;
    l_event_item->event = l_event;
    l_event_item->event_size = a_atom_size;
    l_event_item->ts_added = dap_time_now();

    dap_chain_hash_fast_t l_event_hash = *a_atom_hash;
    l_event_item->hash = l_event_hash;

    if(s_debug_more) {
        char l_event_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' };
        dap_chain_hash_fast_to_str(&l_event_hash, l_event_hash_str, sizeof(l_event_hash_str));
        log_it(L_DEBUG, "Processing event: %s ... (size %zd)", l_event_hash_str,a_atom_size);
    }
    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
    // check if we already have this event
    dap_chain_atom_verify_res_t ret = s_dap_chain_check_if_event_is_present(PVT(l_dag)->events, &l_event_hash) ||
            s_dap_chain_check_if_event_is_present(PVT(l_dag)->events_treshold, &l_event_hash) ? ATOM_PASS : ATOM_ACCEPT;

    // verify hashes and consensus
    switch (ret) {
    case ATOM_ACCEPT:
        ret = s_chain_callback_atom_verify(a_chain, a_atom, a_atom_size, &l_event_hash);
        if (ret == ATOM_MOVE_TO_THRESHOLD) {
            if (!s_threshold_enabled /*&& !dap_chain_net_get_load_mode(dap_chain_net_by_id(a_chain->net_id))*/)
                ret = ATOM_REJECT;
        }
        debug_if(s_debug_more, L_DEBUG, "Verified atom %p: %s", a_atom, dap_chain_atom_verify_res_str[ret]);
        break;
    case ATOM_PASS:
        debug_if(s_debug_more, L_DEBUG, "Atom already present");
        pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
        return ret;
    default:
        break;
    }

    if ( !(l_event_item = DAP_NEW_Z(dap_chain_cs_dag_event_item_t)) ) {
        log_it(L_CRITICAL, "%s", g_error_memory_alloc);
        pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
        return ATOM_REJECT;
    }
    *l_event_item = (dap_chain_cs_dag_event_item_t) {
        .hash       = l_event_hash,
        .ts_added   = dap_time_now(),
        .event      = a_chain->is_mapped ? l_event : DAP_DUP_SIZE(l_event, a_atom_size),
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
        dap_chain_cell_t *l_cell = dap_chain_cell_find_by_id(a_chain, l_event->header.cell_id);
        if ( !dap_chain_net_get_load_mode( dap_chain_net_by_id(a_chain->net_id)) ) {
            if ( dap_chain_atom_save(l_cell, a_atom, a_atom_size, &l_event_hash) < 0 ) {
                log_it(L_ERROR, "Can't save atom to file");
                ret = ATOM_REJECT;
                break;
            } else if (a_chain->is_mapped) {
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
        dap_chain_cs_dag_event_item_t *l_tail = HASH_LAST(PVT(l_dag)->events);
        if (l_tail && l_tail->event->header.ts_created > l_event->header.ts_created) {
            DAP_CHAIN_PVT(a_chain)->need_reorder = true;
            HASH_ADD_INORDER(hh, PVT(l_dag)->events, hash, sizeof(l_event_item->hash), l_event_item, s_sort_event_item);
            dap_chain_cs_dag_event_item_t *it = PVT(l_dag)->events;
            for (uint64_t i = 0; it; it = it->hh.next)  // renumber chain events
                it->event_number = ++i;
        } else
            HASH_ADD(hh, PVT(l_dag)->events, hash, sizeof(l_event_item->hash), l_event_item);
        s_dag_events_lasts_process_new_last_event(l_dag, l_event_item);
        dap_chain_atom_notify(l_cell, &l_event_item->hash, (const byte_t*)l_event_item->event, l_event_item->event_size);
        dap_chain_atom_add_from_threshold(a_chain);
    } break;
    default:
        break;
    }
    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
    if (ret == ATOM_REJECT) { // Neither added, nor freed
        if (!a_chain->is_mapped)
            DAP_DELETE(l_event_item->event);
        DAP_DELETE(l_event_item);
    }
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

static bool s_chain_callback_datums_pool_proc(dap_chain_t *a_chain, dap_chain_datum_t *a_datum)
{
    dap_return_val_if_fail(a_datum && a_chain, false);
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG(a_chain);
    /* If datum passes thru rounds, let's check if it wasn't added before */
    dap_chain_hash_fast_t l_datum_hash;
    dap_hash_fast(a_datum->data, a_datum->header.data_size, &l_datum_hash);
    if (!l_dag->is_add_directly) {
        bool l_dup_found = false;
        size_t l_objs_count = 0;
        dap_global_db_obj_t * l_objs = dap_global_db_get_all_sync(l_dag->gdb_group_events_round_new, &l_objs_count);
        for (size_t i = 0; i < l_objs_count; ++i) {
            if (!strcmp(DAG_ROUND_CURRENT_KEY, l_objs[i].key))
                continue;
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
    dap_hash_fast_t l_event_hash;
    dap_hash_fast(l_event, l_event_size, &l_event_hash);
    bool l_res = false;
    if (l_dag->is_add_directly) {
        dap_chain_atom_verify_res_t l_verify_res = s_chain_callback_atom_add(a_chain, l_event, l_event_size, &l_event_hash);
        DAP_DELETE(l_event);
        if (l_verify_res != ATOM_ACCEPT) {
            log_it(L_ERROR, "Can't add new event to the file, atom verification result %d", l_verify_res);
            return false;
        } else
            return true;
    }

    dap_global_db_set_sync(l_dag->gdb_group_events_round_new, DAG_ROUND_CURRENT_KEY,
                      &l_current_round, sizeof(uint64_t), false);
    dap_chain_cs_dag_event_round_item_t l_round_item = { .round_info.datum_hash = l_datum_hash };
    char *l_event_hash_hex_str = DAP_NEW_STACK_SIZE(char, DAP_CHAIN_HASH_FAST_STR_SIZE);
    dap_chain_hash_fast_to_str(&l_event_hash, l_event_hash_hex_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
    l_res = dap_chain_cs_dag_event_gdb_set(l_dag, l_event_hash_hex_str, l_event, l_event_size, &l_round_item);
    DAP_DELETE(l_event);
    log_it(l_res ? L_INFO : L_ERROR,
           l_res ? "Event %s placed in the new forming round [id %"DAP_UINT64_FORMAT_U"]"
                 : "Can't add new event [%s] to the new events round [id %"DAP_UINT64_FORMAT_U"]",
           l_event_hash_hex_str, l_current_round);
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
static dap_chain_atom_verify_res_t s_chain_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_ptr_t  a_atom,size_t a_atom_size, dap_chain_hash_fast_t *a_atom_hash)
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
    dap_chain_hash_fast_t l_event_hash = *a_atom_hash;
    // Hard accept list
    if (l_dag->hal) {
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
        log_it(L_CRITICAL, "%s", g_error_memory_alloc);
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
            debug_if(s_debug_more, L_DEBUG, "Processing event (threshold): %s...",
                    dap_chain_hash_fast_to_str_static(&l_event_item->hash));
            dap_chain_cell_t *l_cell = dap_chain_cell_find_by_id(a_dag->chain, l_event_item->event->header.cell_id);
            if ( !l_event_item->mapped_region ) {
                if ( dap_chain_atom_save(l_cell, (const byte_t*)l_event_item->event, l_event_item->event_size, &l_event_item->hash) < 0 ) {
                    log_it(L_CRITICAL, "Can't move atom from threshold to file");
                    res = false;
                    break;
                } else if (a_dag->chain->is_mapped) {
                    l_event_item->event = (dap_chain_cs_dag_event_t*)( l_cell->map_pos += sizeof(uint64_t) );
                    l_cell->map_pos += l_event_item->event_size;
                }
            }
            int l_add_res = s_dap_chain_add_atom_to_events_table(a_dag, l_event_item);
            HASH_DEL(PVT(a_dag)->events_treshold, l_event_item);
            if (!l_add_res) {
                HASH_ADD(hh, PVT(a_dag)->events, hash, sizeof(l_event_item->hash), l_event_item);
                s_dag_events_lasts_process_new_last_event(a_dag, l_event_item);
                debug_if(s_debug_more, L_INFO, "... moved from threshold to chain");
                dap_chain_atom_notify(l_cell, &l_event_item->hash, (byte_t*)l_event_item->event, l_event_item->event_size);
                res = true;
            } else {
                // TODO clear other threshold items linked with this one
                debug_if(s_debug_more, L_WARNING, "... rejected with ledger code %d", l_add_res);
                if (!l_event_item->mapped_region)
                    DAP_DELETE(l_event_item->event);
                DAP_DELETE(l_event_item);
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
        log_it(L_CRITICAL, "%s", g_error_memory_alloc);
        return NULL;
    }
    if (a_datums_count)
        *a_datums_count = 1;
    l_datums[0] = l_datum;
    return l_datums;
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
                log_it(L_CRITICAL, "%s", g_error_memory_alloc);
                return NULL;
            }
            if( a_links_size)
                *a_links_size = l_event->header.hash_count;
            *a_links_size_array = DAP_NEW_Z_SIZE(size_t, l_event->header.hash_count*sizeof (size_t));
            if (!*a_links_size_array) {
                log_it(L_CRITICAL, "%s", g_error_memory_alloc);
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
                    char l_err_str[256];
                    unsigned l_off = snprintf(l_err_str, sizeof(l_err_str), "Can't find %s -> ",
                        dap_chain_hash_fast_to_str_static(l_link_hash));
                    snprintf(l_err_str + l_off, sizeof(l_err_str) - l_off, "%s links",
                        l_event_item ? dap_chain_hash_fast_to_str_static(&l_event_item->hash) : "<null>");
                    log_it(L_ERROR, "%s", l_err_str);
                    (*a_links_size_array)--;
                }
            }
            if(!(*a_links_size_array)) {
                DAP_DEL_Z(l_ret);
            }
            return l_ret;
        }
    }
    return  NULL;
}

/**
 * @brief s_chain_callback_atom_iter_create Create atomic element iterator
 * @param a_chain
 * @return
 */
static dap_chain_atom_iter_t *s_chain_callback_atom_iter_create(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, dap_hash_fast_t *a_hash_from)
{
    dap_chain_atom_iter_t * l_atom_iter = DAP_NEW_Z(dap_chain_atom_iter_t);
    if (!l_atom_iter) {
        log_it(L_CRITICAL, "%s", g_error_memory_alloc);
        return NULL;
    }
    l_atom_iter->chain = a_chain;
    l_atom_iter->cell_id = a_cell_id;
    if (a_hash_from)
        s_chain_callback_atom_iter_find_by_hash(l_atom_iter, a_hash_from, NULL);
    return l_atom_iter;
}

/**
 * @brief s_chain_callback_atom_iter_get Get pointed dag event
 * @param a_atom_iter
 * @param a_opertaion
 * @param a_atom_size
 * @return
 */
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get(dap_chain_atom_iter_t *a_atom_iter, dap_chain_iter_op_t a_operation, size_t *a_atom_size)
{
    dap_return_val_if_fail(a_atom_iter, NULL);
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG(a_atom_iter->chain);
    assert(l_dag);
    dap_chain_cs_dag_pvt_t *l_dag_pvt = PVT(l_dag);
    assert(l_dag_pvt);
    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
    switch (a_operation) {
    case DAP_CHAIN_ITER_OP_FIRST:
        a_atom_iter->cur_item = l_dag_pvt->events;
        break;
    case DAP_CHAIN_ITER_OP_LAST:
        a_atom_iter->cur_item = HASH_LAST(l_dag_pvt->events);
        break;
    case DAP_CHAIN_ITER_OP_NEXT:
        if (a_atom_iter->cur_item)
            a_atom_iter->cur_item = ((dap_chain_cs_dag_event_item_t *)a_atom_iter->cur_item)->hh.next;
        break;
    case DAP_CHAIN_ITER_OP_PREV:
        if (a_atom_iter->cur_item)
            a_atom_iter->cur_item = ((dap_chain_cs_dag_event_item_t *)a_atom_iter->cur_item)->hh.prev;
        break;
    }
    if (a_atom_iter->cur_item) {
        dap_chain_cs_dag_event_item_t *l_item = a_atom_iter->cur_item;
        a_atom_iter->cur = l_item->event;
        a_atom_iter->cur_size = l_item->event_size;
        a_atom_iter->cur_hash = &l_item->hash;
        a_atom_iter->cur_num = l_item->event_number;
    } else
        *a_atom_iter = (dap_chain_atom_iter_t) { .chain = a_atom_iter->chain,
                                                 .cell_id = a_atom_iter->cell_id };
    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
    if (a_atom_size)
        *a_atom_size = a_atom_iter->cur_size;
    return a_atom_iter->cur;
}

/**
 * @brief s_chain_callback_atom_iter_find_by_hash
 * @param a_atom_iter
 * @param a_atom_hash
 * @return
 */
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_find_by_hash(dap_chain_atom_iter_t *a_atom_iter ,
                                                                       dap_chain_hash_fast_t * a_atom_hash, size_t *a_atom_size)
{
    dap_chain_cs_dag_t *l_dag = DAP_CHAIN_CS_DAG(a_atom_iter->chain);
    dap_chain_cs_dag_event_item_t *l_event_item = NULL;
    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
    HASH_FIND(hh, PVT(l_dag)->events, a_atom_hash, sizeof(*a_atom_hash), l_event_item);
    if (l_event_item) {
        a_atom_iter->cur_item = l_event_item;
        a_atom_iter->cur = l_event_item->event;
        a_atom_iter->cur_size = l_event_item->event_size;
        a_atom_iter->cur_hash = &l_event_item->hash;
        a_atom_iter->cur_num = l_event_item->event_number;
    } else
        *a_atom_iter = (dap_chain_atom_iter_t) { .chain = a_atom_iter->chain,
                                                 .cell_id = a_atom_iter->cell_id };
    if (a_atom_size)
        *a_atom_size = a_atom_iter->cur_size;
    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
    return a_atom_iter->cur;
}

static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_by_num(dap_chain_atom_iter_t *a_atom_iter, uint64_t a_atom_num)
{
    dap_chain_cs_dag_t *l_dag = DAP_CHAIN_CS_DAG(a_atom_iter->chain);
    dap_chain_cs_dag_event_item_t *l_event_item = NULL;
    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
    for (l_event_item = PVT(l_dag)->events; l_event_item; l_event_item = l_event_item->hh.next)
        if (l_event_item->event_number == a_atom_num)
            break;
    if (l_event_item) {
        a_atom_iter->cur_item = l_event_item;
        a_atom_iter->cur = l_event_item->event;
        a_atom_iter->cur_size = l_event_item->event_size;
        a_atom_iter->cur_hash = &l_event_item->hash;
        a_atom_iter->cur_num = l_event_item->event_number;
    } else
        *a_atom_iter = (dap_chain_atom_iter_t) { .chain = a_atom_iter->chain,
                                                 .cell_id = a_atom_iter->cell_id };
    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
    return a_atom_iter->cur;
}

/**
 * @brief s_chain_callback_atom_iter_delete Delete dag event iterator
 * @param a_atom_iter
 */
static void s_chain_callback_atom_iter_delete(dap_chain_atom_iter_t *a_atom_iter)
{
    DAP_DELETE(a_atom_iter);
}

static dap_chain_datum_iter_t *s_chain_callback_datum_iter_create(dap_chain_t *a_chain)
{
    dap_chain_datum_iter_t *l_ret = DAP_NEW_Z(dap_chain_datum_iter_t);
    if (!l_ret) {
        log_it(L_CRITICAL, "%s", g_error_memory_alloc);
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
static int s_cli_dag(int argc, char ** argv, void **a_str_reply)
{
    json_object **json_arr_reply = (json_object **)a_str_reply;
    enum {
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
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_PARAM_ERR,"invalid parameter -H, valid values: -H <hex | base58>");
        return -DAP_CHAIN_NODE_CLI_COM_DAG_PARAM_ERR;
    }

    if(dap_chain_node_cli_cmd_values_parse_net_chain_for_json(&arg_index, argc, argv, &l_chain, &l_net,CHAIN_TYPE_TX) < 0)
        return -DAP_CHAIN_NODE_CLI_COM_DAG_PARAM_ERR;

    if ((l_net == NULL) || (l_chain == NULL)){
        return -1;
    } 
    l_dag = DAP_CHAIN_CS_DAG(l_chain);

    const char *l_chain_type = dap_chain_get_cs_type(l_chain);

    if (!strstr(l_chain_type, "dag_")){
            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_CHAIN_TYPE_ERR,"Type of chain %s is not dag. This chain with type %s is not supported by this command",
                        l_chain->name, l_chain_type);            
            return -DAP_CHAIN_NODE_CLI_COM_DAG_CHAIN_TYPE_ERR;
    }

    int ret = 0;
    if ( l_round_cmd_str ) {
        json_object * json_obj_round = json_object_new_object();
        char l_buf[150] = {};
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
            dap_string_t *l_str_ret_tmp= l_objs_size>0 ? json_object_object_add(json_obj_round,"round status", json_object_new_string("Completing round")):
                                                         json_object_object_add(json_obj_round,"round status", json_object_new_string("Completing round: no data"));
            // list for verifed and added events
            dap_list_t *l_list_to_del = NULL;

            // Check if its ready or not
            for (size_t i = 0; i< l_objs_size; i++ ){
                if (!strcmp(DAG_ROUND_CURRENT_KEY, l_objs[i].key))
                    continue;
                dap_chain_cs_dag_event_round_item_t *l_round_item = (dap_chain_cs_dag_event_round_item_t *)l_objs[i].value;
                dap_chain_cs_dag_event_t *l_event = (dap_chain_cs_dag_event_t *)l_round_item->event_n_signs;
                dap_hash_fast_t l_event_hash = {};
                size_t l_event_size = l_round_item->event_size;
                dap_hash_fast(l_event, l_event_size, &l_event_hash);
                int l_ret_event_verify;
                if ( ( l_ret_event_verify = l_dag->callback_cs_verify (l_dag,l_event,l_event_size) ) !=0 ){// if consensus accept the event                                        
                    dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_EVENT_ERR,"Error! Event %s is not passing consensus verification, ret code %d\n",
                                              l_objs[i].key, l_ret_event_verify );
                    ret = -DAP_CHAIN_NODE_CLI_COM_DAG_EVENT_ERR;
                    break;
                }else {
                    snprintf(l_buf, 150, "Event %s verification passed", l_objs[i].key);
                    json_object_object_add(json_obj_round,"verification status", json_object_new_string(l_buf));
                    // If not verify only mode we add
                    if ( ! l_verify_only ){
                        if (s_chain_callback_atom_add(l_chain, l_event, l_event_size, &l_event_hash)!= ATOM_ACCEPT) { // Add new atom in chain
                            snprintf(l_buf, 150, "Event %s not added in chain\n", l_objs[i].key);
                            json_object_object_add(json_obj_round,"status add", json_object_new_string(l_buf));                            
                        } else {
                            // add event to delete
                            l_list_to_del = dap_list_prepend(l_list_to_del, (void *)l_objs[i].key);
                            snprintf(l_buf, 150, "Event %s added in chain successfully\n",
                                    l_objs[i].key);
                            json_object_object_add(json_obj_round,"status add", json_object_new_string(l_buf));
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
            json_object_array_add(*json_arr_reply, json_obj_round);
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
                dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_PARAM_ERR,"The -datum option was not specified, so "
                                          "no datum is known to look for in rounds.\n");
                return 0;
            }
            dap_hash_fast_t l_datum_hash = {0};
            dap_chain_hash_fast_from_str(l_datum_in_hash, &l_datum_hash);
            if (dap_hash_fast_is_blank(&l_datum_hash)) {
                dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_PARAM_ERR,"The -datum parameter is not a valid hash.\n");
                return 0;
            }
            size_t l_objs_size = 0;
            dap_global_db_obj_t * l_objs = dap_global_db_get_all_sync(l_dag->gdb_group_events_round_new, &l_objs_size);
            size_t l_search_events = 0;
            json_object_object_add(json_obj_round,"Events", json_object_new_string("empty"));
            for (size_t i = 0; i < l_objs_size;i++) {
                if (!strcmp(DAG_ROUND_CURRENT_KEY, l_objs[i].key))
                    continue;
                dap_chain_cs_dag_event_round_item_t *l_round_item = (dap_chain_cs_dag_event_round_item_t *)l_objs[i].value;
                if (dap_hash_fast_compare(&l_round_item->round_info.datum_hash, &l_datum_hash)) {
                    dap_chain_cs_dag_event_t *l_event = (dap_chain_cs_dag_event_t *)l_round_item->event_n_signs;
                    size_t l_event_size = l_round_item->event_size;
                    dap_hash_fast_t ll_event_hash = {0};
                    dap_hash_fast(l_event, l_event_size, &ll_event_hash);
                    char *ll_event_hash_str = dap_hash_fast_to_str_new(&ll_event_hash);
                    l_search_events++;
                    json_object_object_add(json_obj_round,"events count", json_object_new_uint64(l_search_events));
                    json_object_object_add(json_obj_round,"event hash", json_object_new_string(ll_event_hash_str));
                    json_object_object_add(json_obj_round,"cell_id", json_object_new_uint64(l_event->header.cell_id.uint64));
                    DAP_DELETE(ll_event_hash_str);
                }
            }
            dap_global_db_objs_delete(l_objs, l_objs_size);
            DAP_DELETE(l_datum_in_hash);
            if (!l_search_events) {                  
                snprintf(l_buf, 150, "Datum hash %s not found in round event.\n", l_datum_hash_str);
                json_object_object_add(json_obj_round,"find result", json_object_new_string(l_buf));
            }            
            return 0;
        }
    }else if ( l_event_cmd_str  ) {        
        char *l_datum_hash_hex_str = NULL;
        char *l_datum_hash_base58_str = NULL;
        if ( strcmp( l_event_cmd_str, "list" ) == 0 ) {
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

        case SUBCMD_EVENT_DUMP: {
            json_object * json_obj_event = json_object_new_object();
            char l_buf[150] = {};
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
                        ret = -DAP_CHAIN_NODE_CLI_COM_DAG_FIND_ERR;
                        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_FIND_ERR,"Can't find event %s in events_last table\n", l_event_hash_str);                        
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
                        ret = -DAP_CHAIN_NODE_CLI_COM_DAG_FIND_ERR;
                        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_FIND_ERR,"Can't find event %s in events table\n", l_event_hash_str);                        
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
                        ret = -DAP_CHAIN_NODE_CLI_COM_DAG_FIND_ERR;
                        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_FIND_ERR,"Can't find event %s in threshold table\n", l_event_hash_str);                        
                        break;
                    }
                } else {
                    ret = -DAP_CHAIN_NODE_CLI_COM_DAG_PARAM_ERR;
                    dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_PARAM_ERR,
                            "Wrong events_from option \"%s\", need one of variant: events, round.new, events_lasts, threshold", l_from_events_str);                    
                    break;

                }
                if ( l_event ) {
                    char buf[DAP_TIME_STR_SIZE];
                    json_object_object_add(json_obj_event,"Event hash", json_object_new_string(l_event_hash_str));

                    // Round info
                    if ((l_from_events_str && strcmp(l_from_events_str,"round.new") == 0) && l_round_item) {
                        json_object_object_add(json_obj_event,"Round info", json_object_new_string(" "));
                        json_object_object_add(json_obj_event,"tsigns reject", json_object_new_uint64(l_round_item->round_info.reject_count));
                        json_object_object_add(json_obj_event,"ts_update", json_object_new_string(buf));
                        dap_nanotime_to_str_rfc822(buf, DAP_TIME_STR_SIZE, l_round_item->round_info.ts_update);
                        json_object_object_add(json_obj_event,"datum_hash", json_object_new_string(dap_chain_hash_fast_to_str_static(&l_round_item->round_info.datum_hash)));
                        json_object_object_add(json_obj_event,"ts_update", json_object_new_string(buf));                        
                    }

                    // Header
                    json_object_object_add(json_obj_event,"Header", json_object_new_string("empty"));
                    sprintf(l_buf,"%hu",l_event->header.version);
                    json_object_object_add(json_obj_event,"version", json_object_new_string(l_buf));
                    json_object_object_add(json_obj_event,"round ID", json_object_new_uint64(l_event->header.round_id));
                    sprintf(l_buf,"0x%016"DAP_UINT64_FORMAT_x"",l_event->header.cell_id.uint64);
                    json_object_object_add(json_obj_event,"cell_id", json_object_new_string(l_buf));
                    sprintf(l_buf,"0x%016"DAP_UINT64_FORMAT_x"",l_event->header.chain_id.uint64);
                    json_object_object_add(json_obj_event,"chain_id", json_object_new_string(l_buf));
                    dap_time_to_str_rfc822(buf, DAP_TIME_STR_SIZE, l_event->header.ts_created);
                    json_object_object_add(json_obj_event,"ts_created", json_object_new_string(l_buf));

                    // Hash links
                    json_object_object_add(json_obj_event,"hashes count", json_object_new_uint64(l_event->header.hash_count));
                    for (uint16_t i=0; i < l_event->header.hash_count; i++){
                        dap_chain_hash_fast_t * l_hash = (dap_chain_hash_fast_t *) (l_event->hashes_n_datum_n_signs +
                                i*sizeof (dap_chain_hash_fast_t));
                        json_object_object_add(json_obj_event,"hash", json_object_new_string(dap_chain_hash_fast_to_str_static(l_hash)));
                    }
                    size_t l_offset =  l_event->header.hash_count*sizeof (dap_chain_hash_fast_t);
                    dap_chain_datum_t * l_datum = (dap_chain_datum_t*) (l_event->hashes_n_datum_n_signs + l_offset);
                    size_t l_datum_size =  dap_chain_datum_size(l_datum);

                    // Nested datum
                    const char *l_datum_type = NULL;
                    DAP_DATUM_TYPE_STR(l_datum->header.type_id, l_datum_type)
                    json_object_object_add(json_obj_event,"Datum", json_object_new_string("empty"));
                    json_object_object_add(json_obj_event,"datum_size", json_object_new_uint64(l_datum_size));
                    sprintf(l_buf,"0x%02hhX",l_datum->header.version_id);
                    json_object_object_add(json_obj_event,"version", json_object_new_string(l_buf));
                    json_object_object_add(json_obj_event,"type_id", json_object_new_string(l_datum_type));
                    dap_time_to_str_rfc822(buf, DAP_TIME_STR_SIZE, l_datum->header.ts_create);
                    json_object_object_add(json_obj_event,"ts_create", json_object_new_string(buf));
                    json_object_object_add(json_obj_event,"data_size", json_object_new_uint64(l_datum->header.data_size));
                    
                    // Signatures
                    json_object_object_add(json_obj_event,"signs count", json_object_new_uint64(l_event->header.signs_count));
                    l_offset += l_datum_size;
                    while (l_offset + sizeof (l_event->header) < l_event_size ){
                        dap_sign_t * l_sign =(dap_sign_t *) (l_event->hashes_n_datum_n_signs +l_offset);
                        size_t l_sign_size = dap_sign_get_size(l_sign);
                        if (l_sign_size == 0 ){
                            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_SIGN_ERR," wrong sign size 0, stop parsing headers");
                            break;
                        }
                        dap_chain_hash_fast_t l_pkey_hash;
                        dap_sign_get_pkey_hash(l_sign, &l_pkey_hash);
                        const char *l_hash_str = dap_strcmp(l_hash_out_type, "hex")
                            ? dap_enc_base58_encode_hash_to_str_static(&l_pkey_hash)
                            : dap_chain_hash_fast_to_str_static(&l_pkey_hash);

                        json_object_object_add(json_obj_event,"type", json_object_new_string(dap_sign_type_to_str( l_sign->header.type )));
                        json_object_object_add(json_obj_event,"pkey_hash", json_object_new_string(l_hash_str));
                        
                        l_offset += l_sign_size;
                    }
                    dap_chain_datum_dump_json(json_obj_event, l_datum, l_hash_out_type, l_net->pub.id);
                    json_object_array_add(*json_arr_reply, json_obj_event);

                    ret=0;
                }else {
                    dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_FIND_ERR,"Can't find event 0x%s in the new forming round ",
                                                      l_event_hash_str);
                    ret=-10;
                }
                DAP_DEL_Z(l_round_item);
            } break;

            case SUBCMD_EVENT_LIST: {
                json_object * json_obj_event_list = json_object_new_object();
                json_object * json_arr_obj_event = json_object_new_array();
                const char *l_limit_str = NULL, *l_offset_str = NULL;
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-limit", &l_limit_str);
                dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-offset", &l_offset_str);                
                char *ptr;
                size_t l_limit = l_limit_str ? strtoull(l_limit_str, &ptr, 10) : 1000;
                size_t l_offset = l_offset_str ? strtoull(l_offset_str, &ptr, 10) : 0;
                if (l_offset)
                    json_object_object_add(json_obj_event_list,"offset", json_object_new_uint64(l_offset));                
                if (l_limit)
                    json_object_object_add(json_obj_event_list,"limit", json_object_new_uint64(l_limit));
                    
                if (l_from_events_str && strcmp(l_from_events_str,"round.new") == 0) {
                    char * l_gdb_group_events = DAP_CHAIN_CS_DAG(l_chain)->gdb_group_events_round_new;
                    if ( l_gdb_group_events ){
                        dap_global_db_obj_t * l_objs;
                        size_t l_objs_count = 0;
                        l_objs = dap_global_db_get_all_sync(l_gdb_group_events,&l_objs_count);                        
                        size_t l_arr_start = 0;
                        if (l_offset) {
                            l_arr_start = l_offset;                           
                        }
                        size_t l_arr_end = l_objs_count;
                        if (l_limit) {
                            l_arr_end = l_arr_start + l_limit;
                            if (l_arr_end > l_objs_count)
                                l_arr_end = l_objs_count;
                        }
                        json_object_object_add(json_obj_event_list,"net name", json_object_new_string(l_net->pub.name));
                        json_object_object_add(json_obj_event_list,"chain", json_object_new_string(l_chain->name));
                        json_object_object_add(json_obj_event_list,"obj count", json_object_new_uint64(l_objs_count));                        

                        for (size_t i = l_arr_start; i < l_arr_end; i++) {
                            json_object * json_obj_event_i = json_object_new_object();
                            if (!strcmp(DAG_ROUND_CURRENT_KEY, l_objs[i].key)) {
                                json_object_object_add(json_obj_event_i, l_objs[i].key, json_object_new_uint64(*(uint64_t *)l_objs[i].value)); 
                                json_object_array_add(json_arr_obj_event, json_obj_event_i);                               
                                continue;
                            }
                            dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *)
                                            ((dap_chain_cs_dag_event_round_item_t *)l_objs[i].value)->event_n_signs;
                            char buf[DAP_TIME_STR_SIZE];
                            dap_time_to_str_rfc822(buf, DAP_TIME_STR_SIZE, l_event->header.ts_created);
                            json_object_object_add(json_obj_event_i, "#", json_object_new_string(dap_itoa(i-1)));
                            json_object_object_add(json_obj_event_i, "obj key", json_object_new_string(l_objs[i].key));
                            json_object_object_add(json_obj_event_i, "ts_create", json_object_new_string(buf));
                            json_object_array_add(json_arr_obj_event, json_obj_event_i);
                        }
                        json_object_object_add(json_obj_event_list, "OBJ", json_arr_obj_event);
                        if (l_objs && l_objs_count )
                            dap_global_db_objs_delete(l_objs, l_objs_count);
                        ret = 0;
                    } else {
                        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_GLOBALDB_ERR, "%s.%s: Error! No GlobalDB group!\n", l_net->pub.name, l_chain->name);
                        ret = -2;

                    }
                    json_object_array_add(*json_arr_reply, json_obj_event_list);   
                } else if (!l_from_events_str || (strcmp(l_from_events_str,"events") == 0)) {
                    pthread_mutex_lock(&PVT(l_dag)->events_mutex);                    
                    size_t l_arr_start = 0;
                    if (l_offset > 0) {
                        l_arr_start = l_offset;                        
                    }
                    size_t l_arr_end = HASH_COUNT(PVT(l_dag)->events);
                    if (l_limit) {
                        l_arr_end = l_arr_start + l_limit;
                        if (l_arr_end > HASH_COUNT(PVT(l_dag)->events))
                            l_arr_end = HASH_COUNT(PVT(l_dag)->events);
                    }
                    size_t i_tmp = 0;
                    dap_chain_cs_dag_event_item_t * l_event_item = NULL,*l_event_item_tmp = NULL;
                    HASH_ITER(hh,PVT(l_dag)->events,l_event_item, l_event_item_tmp ) {
                        if (i_tmp < l_arr_start || i_tmp >= l_arr_end) {
                            i_tmp++;
                        } else {
                            json_object * json_obj_event_i = json_object_new_object();
                            i_tmp++;
                            char buf[DAP_TIME_STR_SIZE];
                            dap_time_to_str_rfc822(buf, DAP_TIME_STR_SIZE, l_event_item->event->header.ts_created);
                            json_object_object_add(json_obj_event_i, "#", json_object_new_string(dap_itoa(i_tmp)));
                            json_object_object_add(json_obj_event_i, "hash", json_object_new_string(dap_chain_hash_fast_to_str_static(&l_event_item->hash)));
                            json_object_object_add(json_obj_event_i, "ts_create", json_object_new_string(buf)); 
                            json_object_array_add(json_arr_obj_event, json_obj_event_i);                           
                        }
                    }
                    json_object_object_add(json_obj_event_list, "EVENTS", json_arr_obj_event);
                    size_t l_events_count = HASH_COUNT(PVT(l_dag)->events);
                    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);

                    json_object_object_add(json_obj_event_list,"net name", json_object_new_string(l_net->pub.name));
                    json_object_object_add(json_obj_event_list,"chain", json_object_new_string(l_chain->name));
                    json_object_object_add(json_obj_event_list,"total events", json_object_new_uint64(l_events_count));

                    json_object_array_add(*json_arr_reply, json_obj_event_list);                                       
                }else if (l_from_events_str && (strcmp(l_from_events_str,"threshold") == 0) ){
                    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
                    dap_chain_cs_dag_event_item_t * l_event_item = NULL,*l_event_item_tmp = NULL;
                    size_t l_arr_start = 0;
                    if (l_offset) {
                        l_arr_start = l_offset;
                    }
                    size_t l_arr_end = HASH_COUNT(PVT(l_dag)->events_treshold);
                    if (l_limit) {
                        l_arr_end = l_arr_start + l_limit;
                        if (l_arr_end > HASH_COUNT(PVT(l_dag)->events_treshold))
                            l_arr_end = HASH_COUNT(PVT(l_dag)->events_treshold);
                    }
                    size_t i_tmp = 0;
                    HASH_ITER(hh,PVT(l_dag)->events_treshold,l_event_item, l_event_item_tmp ) {
                        if (i_tmp < l_arr_start || i_tmp > l_arr_end) {
                            i_tmp++;
                            continue;
                        }
                        i_tmp++;
                        json_object * json_obj_event_i = json_object_new_object();
                        char buf[DAP_TIME_STR_SIZE];
                        dap_time_to_str_rfc822(buf, DAP_TIME_STR_SIZE, l_event_item->event->header.ts_created);
                        json_object_object_add(json_obj_event_i, "#", json_object_new_string(dap_itoa(i_tmp)));
                        json_object_object_add(json_obj_event_i, "hash", json_object_new_string(dap_chain_hash_fast_to_str_static(&l_event_item->hash)));
                        json_object_object_add(json_obj_event_i, "ts_create", json_object_new_string(buf)); 
                        json_object_array_add(json_arr_obj_event, json_obj_event_i);                       
                    }
                    json_object_object_add(json_obj_event_list, "TRESHOLD", json_arr_obj_event);
                    size_t l_events_count = HASH_COUNT(PVT(l_dag)->events_treshold);
                    pthread_mutex_unlock(&PVT(l_dag)->events_mutex);
                    json_object_object_add(json_obj_event_list,"net name", json_object_new_string(l_net->pub.name));
                    json_object_object_add(json_obj_event_list,"chain", json_object_new_string(l_chain->name));
                    json_object_object_add(json_obj_event_list,"total events", json_object_new_uint64(l_events_count));

                    json_object_array_add(*json_arr_reply, json_obj_event_list);

                }else {
                    dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_UNDEF_ERR, "Undefined events source for listing ");
                    ret=-14;

                }
            } break;

            case SUBCMD_EVENT_COUNT: {
                json_object * json_obj_event_count = json_object_new_object();
                json_object_object_add(json_obj_event_count,"net name", json_object_new_string(l_net->pub.name));
                json_object_object_add(json_obj_event_count,"chain", json_object_new_string(l_chain->name));
                const char * l_gdb_group_events = DAP_CHAIN_CS_DAG(l_chain)->gdb_group_events_round_new;
                if (l_gdb_group_events) {
                    size_t l_objs_count = 0;
                    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_gdb_group_events,&l_objs_count);
                    json_object_object_add(json_obj_event_count,"event count in round new", json_object_new_string(l_objs_count));
                }
                size_t l_event_count = HASH_COUNT(PVT(l_dag)->events);
                size_t l_event_treshold_count = HASH_COUNT(PVT(l_dag)->events_treshold);
                json_object_object_add(json_obj_event_count,"atom in events", json_object_new_uint64(l_event_count));
                json_object_object_add(json_obj_event_count,"atom in threshold", json_object_new_uint64(l_event_treshold_count));
                json_object_array_add(*json_arr_reply, json_obj_event_count);
            } break;

            case SUBCMD_EVENT_SIGN: { // Sign event command
                json_object * json_obj_event_count = json_object_new_object();
                json_object * json_arr_obj_event = json_object_new_array();
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
                            const char *l_event_new_hash_hex_str = dap_chain_hash_fast_to_str_static(&l_event_new_hash);
                            const char *l_event_new_hash_base58_str = NULL;
                            if (dap_strcmp(l_hash_out_type, "hex"))
                                l_event_new_hash_base58_str = dap_enc_base58_encode_hash_to_str_static(&l_event_new_hash);

                            if (dap_chain_cs_dag_event_gdb_set(l_dag, l_event_new_hash_hex_str, l_event,
                                                               l_event_size_new, l_round_item)) {
                                json_object * json_obj_sign = json_object_new_object();

                                json_object_object_add(json_obj_sign,"cert", json_object_new_string(l_cert_str));
                                json_object_object_add(json_obj_sign,"event", l_event_new_hash_base58_str ?
                                                           json_object_new_string(l_event_new_hash_base58_str) :
                                                           json_object_new_string(l_event_new_hash_hex_str));
                                json_object_array_add(json_arr_obj_event, json_obj_sign);

                                json_object_object_add(json_obj_event_count,"Added new sign with cert, event placed back in round.new", json_arr_obj_event);
                                json_object_array_add(*json_arr_reply, json_obj_event_count);

                            } else {
                                dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_SIGN_ERR,"GDB Error: Can't place event %s with new sign back in round.new\n",
                                                       l_event_new_hash_base58_str ? l_event_new_hash_base58_str : l_event_new_hash_hex_str);
                                ret = -DAP_CHAIN_NODE_CLI_COM_DAG_SIGN_ERR;
                            }
                            DAP_DELETE(l_event);
                        } else {
                            dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_SIGN_ERR,"Can't sign event %s in round.new\n",
                                                   l_event_hash_str);
                            ret=-DAP_CHAIN_NODE_CLI_COM_DAG_SIGN_ERR;
                        }
                    } else {
                        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_CERT_ERR,"No valid certificate provided for event %s signing\n",
                                               l_event_hash_str);
                        ret = -DAP_CHAIN_NODE_CLI_COM_DAG_CERT_ERR;
                    }
                    DAP_DELETE(l_round_item);
                } else {
                    dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_FIND_EVENT_ERR,"Can't find event %s in round.new - only place where could be signed the new event\n",
                                           l_event_hash_str);
                    ret = -DAP_CHAIN_NODE_CLI_COM_DAG_FIND_EVENT_ERR;
                }
            } break;
            case SUBCMD_UNDEFINED: {
                dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_UNKNOWN,"Undefined event subcommand \"%s\" ",
                                       l_event_cmd_str);
                ret=-DAP_CHAIN_NODE_CLI_COM_DAG_UNKNOWN;
            }
        }
        DAP_DEL_Z(l_datum_hash_hex_str);
        DAP_DEL_Z(l_datum_hash_base58_str);
        DAP_DEL_Z(l_event_hash_hex_str);
        DAP_DEL_Z(l_event_hash_base58_str);
    } else {
        dap_json_rpc_error_add(DAP_CHAIN_NODE_CLI_COM_DAG_UNDEF_SUB_ERR,"Undefined subcommand");
        ret = -DAP_CHAIN_NODE_CLI_COM_DAG_UNDEF_SUB_ERR;
    }
    return ret;
}

static uint64_t s_dap_chain_callback_get_count_tx(dap_chain_t *a_chain)
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

static uint64_t s_dap_chain_callback_get_count_atom(dap_chain_t *a_chain)
{
    dap_chain_cs_dag_t  *l_dag = DAP_CHAIN_CS_DAG(a_chain);
    pthread_mutex_lock(&PVT(l_dag)->events_mutex);
    uint64_t l_count = HASH_COUNT(PVT(l_dag)->events);
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

    dap_chain_cs_dag_event_item_t *l_ptr = HASH_LAST(l_dag_pvt->events);
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
