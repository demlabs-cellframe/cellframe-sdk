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
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include "errno.h"
#include "uthash.h"

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
#include "dap_enc_base58.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_hash.h"
#include "dap_chain_datum.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_global_db.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_cell.h"
#include "dap_chain_net.h"

#define LOG_TAG "dap_chain_cs_dag"


typedef struct dap_chain_cs_dag_event_item {
    dap_chain_hash_fast_t hash;
    const char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    time_t ts_added;
    dap_chain_cs_dag_event_t *event;
    size_t event_size;
    UT_hash_handle hh;
} dap_chain_cs_dag_event_item_t;


typedef struct dap_chain_cs_dag_pvt {
    dap_enc_key_t* datum_add_sign_key;


    pthread_rwlock_t events_rwlock;

    dap_chain_cs_dag_event_item_t * events;

    dap_chain_cs_dag_event_item_t * tx_events;
    dap_chain_cs_dag_event_item_t * events_treshold;
    dap_chain_cs_dag_event_item_t * events_treshold_conflicted;
    dap_chain_cs_dag_event_item_t * events_lasts_unlinked;

} dap_chain_cs_dag_pvt_t;

#define PVT(a) ((dap_chain_cs_dag_pvt_t *) a->_pvt )

static void s_dap_chain_cs_dag_purge(dap_chain_t *a_chain);
dap_chain_cs_dag_event_item_t* dap_chain_cs_dag_proc_treshold(dap_chain_cs_dag_t * a_dag, dap_ledger_t * a_ledger);

// Atomic element organization callbacks
static dap_chain_atom_verify_res_t s_chain_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t , size_t);                      //    Accept new event in dag
static dap_chain_atom_ptr_t s_chain_callback_atom_add_from_treshold(dap_chain_t * a_chain, size_t *a_event_size_out);                    //    Accept new event in dag from treshold
static dap_chain_atom_verify_res_t s_chain_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_ptr_t , size_t);                   //    Verify new event in dag
static size_t s_chain_callback_atom_get_static_hdr_size(void);                               //    Get dag event header size

static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create(dap_chain_t * a_chain );
static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create_from(dap_chain_t *  ,
                                                                     dap_chain_atom_ptr_t , size_t);


static dap_chain_atom_ptr_t s_chain_callback_atom_iter_find_by_hash(dap_chain_atom_iter_t * a_atom_iter ,
                                                                       dap_chain_hash_fast_t * a_atom_hash, size_t * a_atom_size);
static dap_chain_datum_tx_t* s_chain_callback_atom_find_by_tx_hash(dap_chain_t *a_chain,
                                                                   dap_chain_hash_fast_t *a_tx_hash);

static dap_chain_datum_t** s_chain_callback_atom_get_datum(dap_chain_atom_ptr_t a_event, size_t a_atom_size, size_t *a_datums_count);
//    Get event(s) from dag
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_first( dap_chain_atom_iter_t * a_atom_iter, size_t *a_atom_size ); //    Get the fisrt event from dag
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_next( dap_chain_atom_iter_t * a_atom_iter,size_t *a_atom_size );  //    Get the next event from dag
static dap_chain_atom_ptr_t *s_chain_callback_atom_iter_get_links( dap_chain_atom_iter_t * a_atom_iter , size_t *a_links_size,
                                                                  size_t ** a_links_size_ptr );  //    Get list of linked events
static dap_chain_atom_ptr_t *s_chain_callback_atom_iter_get_lasts( dap_chain_atom_iter_t * a_atom_iter ,size_t *a_links_size,
                                                                  size_t ** a_lasts_size_ptr );  //    Get list of linked events

// Delete iterator
static void s_chain_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter );                  //    Get the fisrt event from dag

static size_t s_chain_callback_datums_pool_proc(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums, size_t a_datums_size);
// Datum ops
/*
static dap_chain_datum_iter_t* s_chain_callback_datum_iter_create(dap_chain_t * a_chain );
static void s_chain_callback_datum_iter_delete(dap_chain_datum_iter_t * a_iter );
static dap_chain_datum_t* s_chain_callback_datum_iter_get_first( dap_chain_datum_iter_t * a_datum_iter ); // Get the fisrt datum from dag
static dap_chain_datum_t* s_chain_callback_datum_iter_get_next( dap_chain_datum_iter_t * a_datum_iter ); // Get the next datum from dag
*/

static int s_cli_dag(int argc, char ** argv, char **str_reply);
void s_dag_events_lasts_process_new_last_event(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_item_t * a_event_item);
static void s_dag_chain_cs_set_event_round_cfg(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_round_cfg_t * a_event_round_cfg);

static bool s_seed_mode = false;
static bool s_debug_more = false;
/**
 * @brief dap_chain_cs_dag_init
 * @return
 */
int dap_chain_cs_dag_init(void)
{
    srand((unsigned int) time(NULL));
    dap_chain_cs_type_add( "dag", dap_chain_cs_dag_new );
    s_seed_mode = dap_config_get_item_bool_default(g_config,"general","seed_mode",false);
    s_debug_more = dap_config_get_item_bool_default(g_config,"dag","debug_more",false);

    dap_chain_node_cli_cmd_item_create ("dag", s_cli_dag, "DAG commands",
        "dag -net <chain net name> -chain <chain name> event create -datum <datum hash> [-H hex|base58(default)]\n"
            "\tCreate event from datum mempool element\n\n"
        "dag -net <chain net name> -chain <chain name> event cancel -event <event hash>\n"
            "\tRemove event from forming new round and put back its datum to mempool\n\n"
        "dag -net <chain net name> -chain <chain name> event sign -event <event hash>\n"
            "\tAdd sign to event <event hash> in round.new. Hash doesn't include other signs so event hash\n"
            "\tdoesn't changes after sign add to event. \n\n"
        "dag -net <chain net name> -chain <chain name> event dump -event <event hash> -from < events | events_lasts | round.new  | round.<Round id in hex> > [-H hex|base58(default)]\n"
            "\tDump event info\n\n"
        "dag -net <chain net name> -chain <chain name> event list -from < events | events_lasts | round.new  | round.<Round id in hex> \n\n"
            "\tShow event list \n\n"
        "dag -net <chain net name> -chain <chain name> round complete\n\n"
                                        "\tComplete the current new round, verify it and if everything is ok - publish new events in chain\n\n"
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

static void s_history_callback_round_notify(void * a_arg, const char a_op_code, const char * a_group,
        const char * a_key, const void * a_value, const size_t a_value_size)
{
    if (a_arg){
        dap_chain_cs_dag_t * l_dag = (dap_chain_cs_dag_t *) a_arg;
        dap_chain_net_t *l_net = dap_chain_net_by_id( l_dag->chain->net_id);
        log_it(L_DEBUG,"%s.%s: op_code='%c' group=\"%s\" key=\"%s\" value_size=%zu",
            l_net->pub.name, l_dag->chain->name, a_op_code, a_group, a_key, a_value_size);
        if (l_dag->callback_cs_event_round_sync) {
            l_dag->callback_cs_event_round_sync(l_dag, a_op_code, a_group, a_key, a_value, a_value_size);
        }
        dap_chain_net_sync_gdb_broadcast((void *)l_net, a_op_code, a_group, a_key, a_value, a_value_size);
    }
}

/**
 * @brief dap_chain_cs_dag_new
 * @param a_chain
 * @param a_chain_cfg
 */
int dap_chain_cs_dag_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg)
{
    dap_chain_cs_dag_t * l_dag = DAP_NEW_Z(dap_chain_cs_dag_t);
    l_dag->_pvt = DAP_NEW_Z(dap_chain_cs_dag_pvt_t);
    l_dag->chain = a_chain;

    pthread_rwlock_init(& PVT(l_dag)->events_rwlock,NULL);

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
    a_chain->callback_atom_get_datums = s_chain_callback_atom_get_datum;

    a_chain->callback_atom_iter_get_links = s_chain_callback_atom_iter_get_links; // Get the next element from chain from the current one
    a_chain->callback_atom_iter_get_lasts = s_chain_callback_atom_iter_get_lasts;

    a_chain->callback_atom_find_by_hash = s_chain_callback_atom_iter_find_by_hash;
    a_chain->callback_tx_find_by_hash = s_chain_callback_atom_find_by_tx_hash;


    a_chain->callback_add_datums = s_chain_callback_datums_pool_proc;

    // Datum operations callbacks
/*
    a_chain->callback_datum_iter_create = s_chain_callback_datum_iter_create; // Datum iterator create
    a_chain->callback_datum_iter_delete = s_chain_callback_datum_iter_delete; // Datum iterator delete
    a_chain->callback_datum_iter_get_first = s_chain_callback_datum_iter_get_first; // Get the fisrt datum from chain
    a_chain->callback_datum_iter_get_next = s_chain_callback_datum_iter_get_next; // Get the next datum from chain from the current one
*/
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
    char **l_hard_accept_list = dap_config_get_array_str(a_chain_cfg, "dag", "hard_accept_list", &l_list_len);
    for (uint16_t i = 0; i < l_list_len; i++) {
        dap_chain_cs_dag_hal_item_t *l_hal_item = DAP_NEW_Z(dap_chain_cs_dag_hal_item_t);
        dap_chain_hash_fast_from_str(l_hard_accept_list[i], &l_hal_item->hash);
        HASH_ADD(hh, l_dag->hal, hash, sizeof(l_hal_item->hash), l_hal_item);
    }

    l_dag->is_static_genesis_event = (l_static_genesis_event_hash_str != NULL) && dap_config_get_item_bool_default(a_chain_cfg,"dag","is_static_genesis_event",false);

    l_dag->is_single_line = dap_config_get_item_bool_default(a_chain_cfg,"dag","is_single_line",false);
    l_dag->is_celled = dap_config_get_item_bool_default(a_chain_cfg,"dag","is_celled",false);
    l_dag->is_add_directly = dap_config_get_item_bool_default(a_chain_cfg,"dag","is_add_directly",false);
    l_dag->datum_add_hashes_count = dap_config_get_item_uint16_default(a_chain_cfg,"dag","datum_add_hashes_count",1);
    l_dag->use_event_round_cfg = false;
    l_dag->callback_cs_set_event_round_cfg = s_dag_chain_cs_set_event_round_cfg;
    // l_dag->gdb_group_events_round_new = dap_strdup( dap_config_get_item_str_default(a_chain_cfg,"dag","gdb_group_events_round_new",
    //                                                                     "events.round.new"));

    char * l_round_new_str = dap_strdup( dap_config_get_item_str_default(a_chain_cfg,"dag","gdb_group_events_round_new", "events.round.new"));
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    if(!l_dag->is_celled){
        l_dag->gdb_group_events_round_new = dap_strdup_printf( "round-gdb.%s.chain-%016llX.%s",l_net->pub.name,
                                                  a_chain->id.uint64, l_round_new_str);
    }else {
        l_dag->gdb_group_events_round_new = dap_strdup_printf( "round-gdb.%s.chain-%016llX.cell-%016llX.%s",l_net->pub.name,
                                                  a_chain->id.uint64, l_net->pub.cell_id.uint64, l_round_new_str);
    }
    DAP_DELETE(l_round_new_str);

    dap_chain_global_db_add_sync_group("round-gdb", s_history_callback_round_notify, l_dag);

    if ( l_dag->is_single_line ) {
        log_it (L_NOTICE, "DAG chain initialized (single line)");
    } else {
        log_it (L_NOTICE, "DAG chain initialized (multichain)");
    }

    return 0;
}

static void s_dag_chain_cs_set_event_round_cfg(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_round_cfg_t * a_event_round_cfg){
    memcpy(&a_dag->event_round_cfg, 
                a_event_round_cfg, 
                sizeof(dap_chain_cs_dag_event_round_cfg_t));
    a_dag->use_event_round_cfg = true;
}

static void s_dap_chain_cs_dag_purge(dap_chain_t *a_chain)
{
    dap_chain_cs_dag_pvt_t *l_dag_pvt = PVT(DAP_CHAIN_CS_DAG(a_chain));
    pthread_rwlock_wrlock(&l_dag_pvt->events_rwlock);
    dap_chain_cs_dag_event_item_t *l_event_current, *l_event_tmp;
    HASH_ITER(hh, l_dag_pvt->events, l_event_current, l_event_tmp) {
        HASH_DEL(l_dag_pvt->events, l_event_current);
        DAP_DELETE(l_event_current);
    }
    HASH_ITER(hh, l_dag_pvt->events_lasts_unlinked, l_event_current, l_event_tmp) {
        HASH_DEL(l_dag_pvt->events_lasts_unlinked, l_event_current);
        DAP_DELETE(l_event_current);
    }
    HASH_ITER(hh, l_dag_pvt->events_treshold, l_event_current, l_event_tmp) {
        HASH_DEL(l_dag_pvt->events_treshold, l_event_current);
        DAP_DELETE(l_event_current);
    }
    HASH_ITER(hh, l_dag_pvt->events_treshold_conflicted, l_event_current, l_event_tmp) {
        HASH_DEL(l_dag_pvt->events_treshold_conflicted, l_event_current);
        DAP_DELETE(l_event_current);
    }
    HASH_ITER(hh, l_dag_pvt->tx_events, l_event_current, l_event_tmp) {
        HASH_DEL(l_dag_pvt->tx_events, l_event_current);
        DAP_DELETE(l_event_current);
    }
    pthread_rwlock_unlock(&l_dag_pvt->events_rwlock);
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
    pthread_rwlock_destroy(& PVT(l_dag)->events_rwlock);

    if(l_dag->callback_delete )
        l_dag->callback_delete(l_dag);
    if(l_dag->_inheritor)
        DAP_DELETE(l_dag->_inheritor);
    if(l_dag->_pvt)
        DAP_DELETE(l_dag->_pvt);
}


static int s_dap_chain_add_atom_to_ledger(dap_chain_cs_dag_t * a_dag, dap_ledger_t * a_ledger, dap_chain_cs_dag_event_item_t * a_event_item)
{
    dap_chain_datum_t *l_datum = (dap_chain_datum_t*) dap_chain_cs_dag_event_get_datum(a_event_item->event, a_event_item->event_size);
    pthread_rwlock_t * l_events_rwlock = &PVT(a_dag)->events_rwlock;
    switch (l_datum->header.type_id) {
        case DAP_CHAIN_DATUM_TOKEN_DECL: {
            dap_chain_datum_token_t *l_token = (dap_chain_datum_token_t*) l_datum->data;
            return dap_chain_ledger_token_load(a_ledger, l_token, l_datum->header.data_size);
        }
        break;
        case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
            return dap_chain_ledger_token_emission_load(a_ledger, l_datum->data, l_datum->header.data_size);
        }
        break;
        case DAP_CHAIN_DATUM_TX: {
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*) l_datum->data;
            // don't save bad transactions to base
            int l_ret = dap_chain_ledger_tx_load(a_ledger, l_tx);
            if( l_ret != 1 ) {
                return l_ret;
            }
            dap_chain_cs_dag_event_item_t * l_tx_event = DAP_NEW_Z(dap_chain_cs_dag_event_item_t);
            l_tx_event->ts_added = a_event_item->ts_added;
            l_tx_event->event = a_event_item->event;
            l_tx_event->event_size = a_event_item->event_size;
            dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_event->hash);
            int l_err = pthread_rwlock_wrlock(l_events_rwlock);
            HASH_ADD(hh, PVT(a_dag)->tx_events, hash, sizeof(l_tx_event->hash), l_tx_event);
            if (l_err != EDEADLK) {
                pthread_rwlock_unlock(l_events_rwlock);
            }
        }
        break;
        case DAP_CHAIN_DATUM_CA: {
            dap_cert_chain_file_save(l_datum, a_dag->chain->net_name);
            return DAP_CHAIN_DATUM_CA;
        }
        break;
        default:
            return -1;
    }
    return 0;
}

static int s_dap_chain_add_atom_to_events_table(dap_chain_cs_dag_t * a_dag, dap_ledger_t * a_ledger, dap_chain_cs_dag_event_item_t * a_event_item )
{
    int l_ledger_res = s_dap_chain_add_atom_to_ledger(a_dag, a_ledger, a_event_item);
    if (s_debug_more) {
        char l_buf_hash[128] = {'\0'};
        dap_chain_hash_fast_to_str(&a_event_item->hash,l_buf_hash,sizeof(l_buf_hash)-1);
        if (l_ledger_res != 0)
            log_it(L_WARNING,"Dag event %s checked, but ledger declined: code %d", l_buf_hash, l_ledger_res);
        else
            log_it(L_DEBUG,"Dag event %s checked, add it to ledger", l_buf_hash);
    }
    return l_ledger_res;
}

static bool s_dap_chain_check_if_event_is_present(dap_chain_cs_dag_event_item_t * a_hash_table, const dap_chain_hash_fast_t * hash) {
    if(!a_hash_table)
        return false;
    dap_chain_cs_dag_event_item_t * l_event_search = NULL;
    HASH_FIND(hh, a_hash_table, hash, sizeof(*hash), l_event_search);
    return (l_event_search != NULL);
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

    dap_chain_cs_dag_event_item_t * l_event_item = DAP_NEW_Z(dap_chain_cs_dag_event_item_t);
    pthread_rwlock_t * l_events_rwlock = &PVT(l_dag)->events_rwlock;
    l_event_item->event = l_event;
    l_event_item->event_size = a_atom_size;
    l_event_item->ts_added = time(NULL);

    dap_chain_hash_fast_t l_event_hash;
    dap_chain_cs_dag_event_calc_hash(l_event, a_atom_size, &l_event_hash);
    memcpy(&l_event_item->hash, &l_event_hash, sizeof(dap_chain_hash_fast_t));

    char * l_event_hash_str;
    if(s_debug_more) {
        l_event_hash_str = dap_chain_hash_fast_to_str_new(&l_event_item->hash);
        log_it(L_DEBUG, "Processing event: %s... (size %zd)", l_event_hash_str,a_atom_size);
    }

    pthread_rwlock_rdlock(l_events_rwlock);
    // check if we already have this event
    dap_chain_atom_verify_res_t ret = s_dap_chain_check_if_event_is_present(PVT(l_dag)->events, &l_event_item->hash) ||
            s_dap_chain_check_if_event_is_present(PVT(l_dag)->events_treshold, &l_event_item->hash) ? ATOM_PASS : ATOM_ACCEPT;
    pthread_rwlock_unlock(l_events_rwlock);

    // verify hashes and consensus
    switch (ret) {
    case ATOM_ACCEPT:
        ret = s_chain_callback_atom_verify(a_chain, a_atom, a_atom_size);
        if(s_debug_more)
            log_it(L_DEBUG, "Verified atom %p: %s", a_atom, ret == ATOM_ACCEPT ? "accepted" :
                                                           (ret == ATOM_REJECT ? "rejected" : "thresholded"));
        break;
    case ATOM_PASS:
        if(s_debug_more) {
            log_it(L_DEBUG, "Atom already present");
            DAP_DELETE(l_event_hash_str);
        }
        DAP_DELETE(l_event_item);
        return ret;
    default:
        break;
    }

    switch (ret) {
    case ATOM_MOVE_TO_THRESHOLD:
        pthread_rwlock_wrlock(l_events_rwlock);
        HASH_ADD(hh, PVT(l_dag)->events_treshold, hash,sizeof (l_event_item->hash), l_event_item);
        pthread_rwlock_unlock(l_events_rwlock);
        if(s_debug_more)
            log_it(L_DEBUG, "... added to threshold");
        break;
    case ATOM_ACCEPT: {
        int l_consensus_check = s_dap_chain_add_atom_to_events_table(l_dag, a_chain->ledger, l_event_item);
        switch (l_consensus_check) {
        case 0:
            pthread_rwlock_wrlock(l_events_rwlock);
            HASH_ADD(hh, PVT(l_dag)->events,hash,sizeof (l_event_item->hash), l_event_item);
            s_dag_events_lasts_process_new_last_event(l_dag, l_event_item);
            pthread_rwlock_unlock(l_events_rwlock);
            if(s_debug_more)
                log_it(L_DEBUG, "... added");
            break;
        case DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS:
        case DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION:
        case DAP_CHAIN_CS_VERIFY_CODE_TX_NO_TOKEN:
            pthread_rwlock_wrlock(l_events_rwlock);
            HASH_ADD(hh, PVT(l_dag)->events_treshold, hash, sizeof(l_event_item->hash), l_event_item);
            pthread_rwlock_unlock(l_events_rwlock);
            if(s_debug_more)
                log_it(L_DEBUG, "... tresholded");
            ret = ATOM_MOVE_TO_THRESHOLD;
            break;
        case DAP_CHAIN_DATUM_CA:
            ret = ATOM_ACCEPT;
            if(s_debug_more)
                log_it(L_DEBUG, "... DATUM_CA");
            break;
        default:
            if (s_debug_more) {
                l_event_hash_str = dap_chain_hash_fast_to_str_new(&l_event_item->hash);
                log_it(L_WARNING, "Atom %s (size %zd) error adding (code %d)", l_event_hash_str, a_atom_size, l_consensus_check);
            }
            ret = ATOM_REJECT;
            break;
        }
    }
        break;
    default: break;
    }
    if(s_debug_more)
        DAP_DELETE(l_event_hash_str);
    return ret;
}


/**
 * @brief s_chain_callback_atom_add_from_treshold Accept new event in dag
 * @param a_chain DAG object
 * @return true if added one item, otherwise false
 */
static dap_chain_atom_ptr_t s_chain_callback_atom_add_from_treshold(dap_chain_t * a_chain, size_t *a_event_size_out)
{
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG(a_chain);
    dap_chain_cs_dag_event_item_t *l_item = dap_chain_cs_dag_proc_treshold(l_dag, a_chain->ledger);
//    dap_chain_cs_dag_event_calc_size()
    if(l_item) {
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
static size_t s_chain_callback_datums_pool_proc(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums, size_t a_datums_count)
{
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG(a_chain);
    size_t l_datum_processed =0;
    size_t l_events_round_new_size = 0;
    // Load current events new round pool
    dap_global_db_obj_t * l_events_round_new = dap_chain_global_db_gr_load(l_dag->gdb_group_events_round_new, &l_events_round_new_size );
    // Prepare hashes
    size_t l_hashes_int_size = min(l_events_round_new_size + a_datums_count, l_dag->datum_add_hashes_count);
//            ( l_events_round_new_size + a_datums_count ) > l_dag->datum_add_hashes_count ?
//                                   l_dag->datum_add_hashes_count :
//                                   l_events_round_new_size+a_datums_count;

    if (l_dag->is_single_line ) // If single line - only one link inside
        l_hashes_int_size = min(l_hashes_int_size, 1);

    size_t l_hashes_ext_size = 0; // Change in cfg
    size_t l_hashes_size = l_hashes_int_size+l_hashes_ext_size;
    dap_chain_hash_fast_t * l_hashes = l_hashes_size ?DAP_NEW_Z_SIZE(dap_chain_hash_fast_t,
                                             sizeof(dap_chain_hash_fast_t) * l_hashes_size) : NULL;
    size_t l_hashes_linked = 0;
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    dap_chain_cell_id_t l_cell_id = {
        .uint64 = l_net ? l_net->pub.cell_id.uint64 : 0
    };
    dap_chain_cell_t *l_cell = dap_chain_cell_find_by_id(a_chain, l_cell_id);

    for (size_t d = 0; d <a_datums_count ; d++){
        dap_chain_datum_t * l_datum = a_datums[d];
        if(l_datum == NULL){ // Was wrong datum thats not passed checks
            log_it(L_WARNING,"Datum in mempool processing comes NULL");
            continue;
        }

        // Verify for correctness
        dap_chain_net_t * l_net = dap_chain_net_by_id( a_chain->net_id);
        int l_verify_datum= dap_chain_net_verify_datum_for_add( l_net, l_datum) ;
        if (l_verify_datum != 0 &&
                l_verify_datum != DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS &&
                l_verify_datum != DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION &&
                l_verify_datum != DAP_CHAIN_CS_VERIFY_CODE_TX_NO_TOKEN){
            log_it(L_WARNING, "Datum doesn't pass verifications (code %d)",
                                     l_verify_datum);
            continue;
        }

        // Prepare round
        if ( l_hashes_int_size && l_events_round_new_size){
            // Linking randomly with current new round set
            size_t l_rnd_steps;
            // Linking events inside round
            l_rnd_steps = 0;
            do{
                int l_index = rand() % (int) l_events_round_new_size;
                dap_chain_hash_fast_t l_hash;
                // dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *) l_events_round_new[l_index].value;
                // size_t l_event_size = l_events_round_new[l_index].value_len;
                dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *)
                                ((dap_chain_cs_dag_event_round_item_t *)l_events_round_new[l_index].value)->event;
                size_t l_event_size = ((dap_chain_cs_dag_event_round_item_t *)l_events_round_new[l_index].value)->event_size;
                dap_hash_fast(l_event, l_event_size,&l_hash);

                bool l_is_already_in_event = false;
                for (uint16_t i=0; i<l_hashes_linked;i++ ){ // check if we already added it
                    if (l_hashes && memcmp(&l_hashes[i],&l_hash,sizeof (l_hash) )==0 ){
                        l_is_already_in_event = true;
                        break;
                    }
                }

                if ( ! l_is_already_in_event ){
                    if(l_hashes_linked < l_hashes_size) {
                        memcpy(&l_hashes[l_hashes_linked], &l_hash, sizeof(l_hash));
                        l_hashes_linked++;
                    }
                }
                l_rnd_steps++;
                if (l_rnd_steps > 100) // Too many attempts
                    break;
            } while (l_hashes_linked <(l_events_round_new_size) );

            // Check if we have enought hash links
            if (l_hashes_linked<l_events_round_new_size ){
                log_it(L_ERROR,"Can't link new events randomly for 100 attempts");
                break;
            }
        }
        // Now link with ext events
        dap_chain_cs_dag_event_item_t *l_event_ext_item = NULL;
        // is_single_line - only one link inside
        if(!l_dag->is_single_line || !l_hashes_linked){
            pthread_rwlock_rdlock(&PVT(l_dag)->events_rwlock);
            if( PVT(l_dag)->events_lasts_unlinked && l_hashes_linked < l_hashes_size) { // Take then the first one if any events_lasts are present
                    l_event_ext_item = PVT(l_dag)->events_lasts_unlinked;
                    if(l_hashes)
                        memcpy(&l_hashes[l_hashes_linked], &l_event_ext_item->hash, sizeof(l_event_ext_item->hash));
                    l_hashes_linked++;
                }
            pthread_rwlock_unlock(&PVT(l_dag)->events_rwlock);
        }

        if (l_hashes_linked || s_seed_mode ) {
            dap_chain_cs_dag_event_t * l_event = NULL;
            size_t l_event_size = 0;
            if(l_dag->callback_cs_event_create)
                l_event = l_dag->callback_cs_event_create(l_dag,l_datum,l_hashes,l_hashes_linked,&l_event_size);
            if ( l_event&&l_event_size){ // Event is created
                if (l_dag->is_add_directly) {
                    if (s_chain_callback_atom_add(a_chain, l_event, l_event_size) == ATOM_ACCEPT) {
                        // add events to file
                        if (!l_cell) {
                            l_cell = dap_chain_cell_create_fill(a_chain, l_cell_id);
                        }
                        if (dap_chain_cell_file_append(l_cell, l_event, l_event_size )  < 0) {
                            log_it(L_ERROR, "Can't add new event to the file '%s'", l_cell->file_storage_path);
                            continue;
                        }
                        // add all atoms from treshold
                        {
                            dap_chain_atom_ptr_t l_atom_treshold;
                            do {
                                size_t l_atom_treshold_size;
                                // add in ledger
                                l_atom_treshold = s_chain_callback_atom_add_from_treshold(a_chain, &l_atom_treshold_size);
                                // add into file
                                if(l_atom_treshold) {
                                    int l_res = dap_chain_cell_file_append(l_cell, l_atom_treshold, l_atom_treshold_size);
                                    if(l_res < 0) {
                                        log_it(L_ERROR, "Can't save event %p from treshold to the file '%s'",
                                                l_atom_treshold, l_cell ? l_cell->file_storage_path : "[null]");
                                    }
                                }
                            }
                            while(l_atom_treshold);
                        }
                        l_datum_processed++;
                    }
                    else {
                        log_it(L_ERROR, "Can't add new event");
                        continue;
                    }
                }
                // add to new round into global_db
                else {
                    dap_chain_hash_fast_t l_event_hash;
                    dap_chain_cs_dag_event_calc_hash(l_event,l_event_size, &l_event_hash);
                    char * l_event_hash_str = dap_chain_hash_fast_to_str_new(&l_event_hash);
                    // if(dap_chain_global_db_gr_set(dap_strdup(l_event_hash_str), (uint8_t *)l_event,
                    //         l_event_size,
                    //         l_dag->gdb_group_events_round_new)) {
                    dap_chain_cs_dag_event_round_cfg_t l_event_round_cfg;
                    if ( l_dag->callback_cs_get_round_cfg ) {
                        l_dag->callback_cs_get_round_cfg(l_dag, &l_event_round_cfg);
                    }
                    // set first event hash for round
                    memcpy(&l_event_round_cfg.first_event_hash, &l_event_hash, sizeof(dap_chain_hash_fast_t));
                    if(dap_chain_cs_dag_event_gdb_set(l_event_hash_str, l_event,
                                l_event_size, l_dag->gdb_group_events_round_new,
                                &l_event_round_cfg)) {
                        log_it(L_INFO, "Event %s placed in the new forming round", l_event_hash_str);
                        DAP_DELETE(l_event_hash_str);
                        l_event_hash_str = NULL;
                        // Clear old ext link and place itself as event_lasts

                        dap_chain_cs_dag_event_item_t * l_event_unlinked_item = DAP_NEW_Z(
                                dap_chain_cs_dag_event_item_t);
                        if(l_event_ext_item)
                            memcpy(&l_event_unlinked_item->hash, &l_event_ext_item->hash,
                                    sizeof(l_event_ext_item->hash));
                        l_event_unlinked_item->event = l_event;
                        l_event_unlinked_item->event_size = l_event_size;
                        l_event_unlinked_item->ts_added = (time_t) l_event->header.ts_created;
                        pthread_rwlock_wrlock(&PVT(l_dag)->events_rwlock);
                        HASH_ADD(hh, PVT(l_dag)->events_lasts_unlinked, hash, sizeof(l_event_unlinked_item->hash),
                                l_event_unlinked_item);
                        if(l_event_ext_item) {
                            HASH_DEL(PVT(l_dag)->events_lasts_unlinked, l_event_ext_item);
                            DAP_DELETE(l_event_ext_item);
                        }
                        pthread_rwlock_unlock(&PVT(l_dag)->events_rwlock);

                        l_datum_processed++;
                    }else {
                        log_it(L_ERROR,"Can't add new event to the new events round");
                        break;
                    }
                }
            }else {
                log_it(L_ERROR,"Can't create new event!");
                break;
            }
        }
    }
    DAP_DELETE(l_hashes);
    if (l_cell) {
        dap_chain_cell_close(l_cell);
    }
    dap_chain_global_db_objs_delete(l_events_round_new, l_events_round_new_size);
    return  l_datum_processed;
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
    pthread_rwlock_rdlock(&PVT(a_dag)->events_rwlock);
    HASH_FIND(hh, PVT(a_dag)->events ,a_hash,sizeof(*a_hash), l_event_item);
    pthread_rwlock_unlock(&PVT(a_dag)->events_rwlock);
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
    for (int i = 0; i < a_event->header.signs_count; i++) {
        dap_sign_t *l_sign = (dap_sign_t *)((uint8_t *)a_event + l_sign_offset);
        l_sign_offset += dap_sign_get_size(l_sign);
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
    pthread_rwlock_t *l_events_rwlock = &PVT(l_dag)->events_rwlock;
    if (l_event->header.version) {
        if (s_debug_more)
            log_it(L_WARNING, "Unsupported event version, possible corrupted event");
        return ATOM_REJECT;
    }
    if (l_event->header.chain_id.uint64 != a_chain->id.uint64) {
        if (s_debug_more)
            log_it(L_WARNING, "Event from another chain, possible corrupted event");
        return ATOM_REJECT;
    }
    if (!s_event_verify_size(l_event, a_atom_size)) {
        if (s_debug_more)
            log_it(L_WARNING,"Event size not equal to expected");
        return  ATOM_REJECT;
    }
    // Hard accept list
    if (l_dag->hal) {
        dap_chain_hash_fast_t l_event_hash = { };
        dap_chain_cs_dag_event_calc_hash(l_event,a_atom_size, &l_event_hash);
        dap_chain_cs_dag_hal_item_t *l_hash_found = NULL;
        pthread_rwlock_rdlock(l_events_rwlock);
        HASH_FIND(hh, l_dag->hal, &l_event_hash, sizeof(l_event_hash), l_hash_found);
        pthread_rwlock_unlock(l_events_rwlock);
        if (l_hash_found) {
            return ATOM_ACCEPT;
        }
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
                char * l_event_hash_str = dap_chain_hash_fast_to_str_new(&l_event_hash);
                char * l_genesis_event_hash_str = dap_chain_hash_fast_to_str_new(&l_dag->static_genesis_event_hash);

                log_it(L_WARNING, "Wrong genesis block %s (staticly predefined %s)",l_event_hash_str, l_genesis_event_hash_str);
                DAP_DELETE(l_event_hash_str);
                DAP_DELETE(l_genesis_event_hash_str);
                return ATOM_REJECT;
            } else {
                if (s_debug_more)
                    log_it(L_INFO, "Accepting static genesis event");
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
            pthread_rwlock_rdlock(l_events_rwlock);
            HASH_FIND(hh, PVT(l_dag)->events ,l_hash ,sizeof (*l_hash),  l_event_search);
            pthread_rwlock_unlock(l_events_rwlock);
            if ( l_event_search == NULL ){
                char * l_hash_str = dap_chain_hash_fast_to_str_new(l_hash);
                if(s_debug_more)
                    log_it(L_WARNING, "Hash %s wasn't in hashtable of previously parsed", l_hash_str);
                DAP_DELETE(l_hash_str);
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
        HASH_FIND(hh, PVT(a_dag)->events_lasts_unlinked ,l_hash ,sizeof (*l_hash),  l_event_item);
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
                l_is_events_main_hashes ?
                    DAP_THRESHOLD_OK :
                DAP_THRESHOLD_NO_HASHES :
            DAP_THRESHOLD_NO_HASHES_IN_MAIN;
}

/**
 * @brief dap_chain_cs_dag_proc_treshold
 * @param a_dag
 * @returns true if some atoms were moved from threshold to events
 */
dap_chain_cs_dag_event_item_t* dap_chain_cs_dag_proc_treshold(dap_chain_cs_dag_t * a_dag, dap_ledger_t * a_ledger)
{
    bool res = false;
    // TODO Process finish treshold. For now - easiest from possible
    dap_chain_cs_dag_event_item_t * l_event_item = NULL, * l_event_item_tmp = NULL;
    pthread_rwlock_wrlock(&PVT(a_dag)->events_rwlock);
    // !!!
    int l_count = HASH_COUNT(PVT(a_dag)->events_treshold);
    log_it(L_DEBUG, "*** %d events in threshold", l_count);
    HASH_ITER(hh,PVT(a_dag)->events_treshold,l_event_item, l_event_item_tmp){
        dap_dag_threshold_verification_res_t ret = dap_chain_cs_dag_event_verify_hashes_with_treshold (a_dag, l_event_item->event);
        if ( ret == DAP_THRESHOLD_OK || ret == DAP_THRESHOLD_CONFLICTING ){ // All its hashes are in main table, move thats one too into it
            HASH_DEL(PVT(a_dag)->events_treshold,l_event_item);
            if(ret == DAP_THRESHOLD_OK){
                if(s_debug_more) {
                    char * l_event_hash_str = dap_chain_hash_fast_to_str_new(&l_event_item->hash);
                    log_it(L_DEBUG, "Processing event (threshold): %s...", l_event_hash_str);
                    DAP_DELETE(l_event_hash_str);
                }
                int l_add_res = s_dap_chain_add_atom_to_events_table(a_dag, a_ledger, l_event_item);
                if (!l_add_res) {
                    HASH_ADD(hh, PVT(a_dag)->events,hash,sizeof (l_event_item->hash), l_event_item);
                    s_dag_events_lasts_process_new_last_event(a_dag, l_event_item);
                    if(s_debug_more)
                        log_it(L_INFO, "... moved from treshold to main chains");
                    res = true;
                    break;
                }else{
                    if(s_debug_more)
                        log_it(L_WARNING, "... error adding");
                    DAP_DELETE(l_event_item);
                }
                //res = true;
            }else if(ret == DAP_THRESHOLD_CONFLICTING)
                HASH_ADD(hh, PVT(a_dag)->events_treshold_conflicted, hash,sizeof (l_event_item->hash),  l_event_item);

        }
    }
    pthread_rwlock_unlock(&PVT(a_dag)->events_rwlock);
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
static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create(dap_chain_t * a_chain )
{
    dap_chain_atom_iter_t * l_atom_iter = DAP_NEW_Z(dap_chain_atom_iter_t);
    l_atom_iter->chain = a_chain;
    pthread_rwlock_rdlock(&a_chain->atoms_rwlock);
#ifdef WIN32
    log_it(L_DEBUG, "! Create caller id %lu", GetThreadId(GetCurrentThread()));
#endif
    return l_atom_iter;
}

/**
 * @brief s_chain_callback_atom_get_datum Get the datum from event
 * @param a_atom_iter
 * @param a_datums_count
 * @return
 */
static dap_chain_datum_t** s_chain_callback_atom_get_datum(dap_chain_atom_ptr_t a_event, size_t a_atom_size, size_t *a_datums_count)
{
    assert(a_datums_count);
    if(a_event){
        dap_chain_datum_t * l_datum = dap_chain_cs_dag_event_get_datum((dap_chain_cs_dag_event_t*) a_event, a_atom_size);
        if (l_datum){
            dap_chain_datum_t ** l_datums = DAP_NEW_SIZE(dap_chain_datum_t*, sizeof(dap_chain_datum_t*));
            *a_datums_count = 1;
            l_datums[0] = l_datum;
            return l_datums;
        }else
            return NULL;
    }else
        return NULL;
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
    a_atom_iter->cur_item = l_dag_pvt->events;
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
    pthread_rwlock_rdlock(&PVT(l_dag)->events_rwlock);
    size_t l_lasts_size = HASH_COUNT( PVT(l_dag)->events_lasts_unlinked );
    if ( l_lasts_size > 0 ) {
        if( a_lasts_size)
            *a_lasts_size = l_lasts_size;
        l_ret = DAP_NEW_Z_SIZE(dap_chain_atom_ptr_t, sizeof(dap_chain_atom_ptr_t) * l_lasts_size);
        dap_chain_cs_dag_event_item_t * l_event_item = NULL, *l_event_item_tmp = NULL;
        size_t i = 0;
        *a_lasts_size_array = DAP_NEW_Z_SIZE(size_t, sizeof(size_t) * l_lasts_size);
        HASH_ITER(hh,PVT(l_dag)->events_lasts_unlinked, l_event_item,l_event_item_tmp){
            l_ret[i] = l_event_item->event;
            (*a_lasts_size_array)[i] = l_event_item->event_size;
            i++;
        }    
    }
    pthread_rwlock_unlock(&PVT(l_dag)->events_rwlock);
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
            if( a_links_size)
                *a_links_size = l_event->header.hash_count;
            *a_links_size_array = DAP_NEW_Z_SIZE(size_t, l_event->header.hash_count*sizeof (size_t));
            for (uint16_t i = 0; i < l_event->header.hash_count; i++){
                dap_chain_cs_dag_event_item_t * l_link_item = NULL;
                dap_chain_hash_fast_t * l_link_hash = (dap_chain_hash_fast_t *)
                        (l_event->hashes_n_datum_n_signs +
                        i*sizeof(*l_link_hash));
                pthread_rwlock_rdlock(&PVT(l_dag)->events_rwlock);
                HASH_FIND(hh, PVT(l_dag)->events,l_link_hash,sizeof(*l_link_hash),l_link_item);
                pthread_rwlock_unlock(&PVT(l_dag)->events_rwlock);
                if ( l_link_item ){
                    l_ret[i] = l_link_item->event;
                    (*a_links_size_array)[i] = l_link_item->event_size;
                }else {
                    char * l_link_hash_str = dap_chain_hash_fast_to_str_new(l_link_hash);
                    char * l_event_hash_str = l_event_item ? dap_chain_hash_fast_to_str_new(&l_event_item->hash) : NULL;
                    log_it(L_ERROR,"Can't find %s->%s links", l_event_hash_str ? l_event_hash_str : "[null]", l_link_hash_str);
                    DAP_DELETE(l_event_hash_str);
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
    pthread_rwlock_rdlock(&PVT(l_dag)->events_rwlock);
    HASH_FIND(hh, PVT(l_dag)->events,a_atom_hash,sizeof(*a_atom_hash),l_event_item);
    pthread_rwlock_unlock(&PVT(l_dag)->events_rwlock);
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


static dap_chain_datum_tx_t* s_chain_callback_atom_find_by_tx_hash(dap_chain_t *a_chain,
                                                                   dap_chain_hash_fast_t *a_tx_hash)
{
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG( a_chain );
    dap_chain_cs_dag_event_item_t * l_event_item = NULL;
    pthread_rwlock_rdlock(&PVT(l_dag)->events_rwlock);
    HASH_FIND(hh, PVT(l_dag)->tx_events, a_tx_hash, sizeof(*a_tx_hash), l_event_item);
    pthread_rwlock_unlock(&PVT(l_dag)->events_rwlock);
    if ( l_event_item ){
        dap_chain_datum_t *l_datum = dap_chain_cs_dag_event_get_datum(l_event_item->event, l_event_item->event_size);
        return l_datum ? l_datum->header.data_size ? (dap_chain_datum_tx_t*) l_datum->data : NULL :NULL;
    }else
        return NULL;
}

/**
 * @brief s_chain_callback_atom_iter_get_next Get the next dag event
 * @param a_atom_iter
 * @return
 */
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_next( dap_chain_atom_iter_t * a_atom_iter,size_t * a_atom_size )
{
    if (a_atom_iter->cur ){
        //dap_chain_cs_dag_pvt_t* l_dag_pvt = PVT(DAP_CHAIN_CS_DAG(a_atom_iter->chain));
        dap_chain_cs_dag_event_item_t * l_event_item = (dap_chain_cs_dag_event_item_t*) a_atom_iter->cur_item;
        a_atom_iter->cur_item = l_event_item->hh.next;
        l_event_item = (dap_chain_cs_dag_event_item_t*) a_atom_iter->cur_item;
        // if l_event_item=NULL then items are over
        a_atom_iter->cur = l_event_item ? l_event_item->event : NULL;
        a_atom_iter->cur_size = a_atom_iter->cur ? l_event_item->event_size : 0;
        a_atom_iter->cur_hash = l_event_item ? &l_event_item->hash : NULL;
        if(a_atom_size)
            *a_atom_size = a_atom_iter->cur_size;
        return a_atom_iter->cur;
    }else
        return NULL;

}

/**
 * @brief s_chain_callback_atom_iter_delete Delete dag event iterator
 * @param a_atom_iter
 */
static void s_chain_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter )
{
    pthread_rwlock_unlock(&a_atom_iter->chain->atoms_rwlock);
#ifdef WIN32
    log_it(L_DEBUG, "! Delete caller id %lu", GetThreadId(GetCurrentThread()));
#endif
    DAP_DELETE(a_atom_iter);
}

/**
 * @brief s_cli_dag
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return
 */
static int s_cli_dag(int argc, char ** argv, char **a_str_reply)
{
    enum {
        SUBCMD_EVENT_CREATE,
        SUBCMD_EVENT_CANCEL,
        SUBCMD_EVENT_LIST,
        SUBCMD_EVENT_DUMP,
        SUBCMD_UNDEFINED
    } l_event_subcmd={0};

    /*const char* l_event_subcmd_str[]={
        [SUBCMD_EVENT_CREATE]="create",
        [SUBCMD_EVENT_CANCEL]="cancel",
        [SUBCMD_EVENT_LIST]="list",
        [SUBCMD_EVENT_DUMP]="dump",
        [SUBCMD_UNDEFINED]="UNDEFINED"
    };*/


    int arg_index = 1;

    const char * l_net_name = NULL;

    const char * l_chain_name = NULL;

    const char * l_event_cmd_str = NULL;
    const char * l_round_cmd_str = NULL;

    const char* l_event_hash_str = NULL;
    dap_chain_hash_fast_t l_event_hash = {0};

    const char * l_datum_hash_str = NULL;

    const char * l_from_events_str = NULL;

    dap_chain_t * l_chain = NULL;
    dap_chain_cs_dag_t * l_dag = NULL;
    dap_chain_net_t * l_net = NULL;

    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-net", &l_net_name);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-chain", &l_chain_name);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "event", &l_event_cmd_str);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "round", &l_round_cmd_str);

    const char * l_hash_out_type = NULL;
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_chain_node_cli_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
        return -1;
    }

    if ( l_net_name == NULL){
        dap_chain_node_cli_set_reply_text(a_str_reply, "Need -net <net name> param!");
        return -1;
    }
    l_net = dap_chain_net_by_name( l_net_name );
    if ( l_net == NULL ){
        dap_chain_node_cli_set_reply_text(a_str_reply, "Can't find network \"%s\"",l_net_name);
        return -2;

    }

    if ( l_chain_name == NULL){
        dap_chain_node_cli_set_reply_text(a_str_reply, "Need -chain <chain name> param!");
        return -3;
    }
    l_chain = dap_chain_net_get_chain_by_name(l_net,l_chain_name);
    if ( l_chain == NULL ){
        dap_chain_node_cli_set_reply_text(a_str_reply, "Can't find chain \"%s\" in network \"%s\"",
                                          l_chain_name, l_net_name);
        return -4;
    }
    l_dag = DAP_CHAIN_CS_DAG(l_chain);

    int ret = 0;
    if ( l_round_cmd_str ) {
        if ( strcmp(l_round_cmd_str,"complete") == 0 ){
            const char * l_cmd_mode_str = NULL;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-mode", &l_cmd_mode_str);
            bool l_verify_only = false;
            if ( dap_strcmp(l_cmd_mode_str,"verify only") == 0 ){
                l_verify_only = true;
            }
            log_it(L_NOTICE,"Round complete command accepted, forming new events");

            size_t l_objs_size=0;
            dap_global_db_obj_t * l_objs = dap_chain_global_db_gr_load(l_dag->gdb_group_events_round_new,&l_objs_size);

            dap_string_t *l_str_ret_tmp= l_objs_size>0 ? dap_string_new("Completing round:\n") : dap_string_new("Completing round: no data");

            // list for verifed and added events
            dap_list_t *l_list_to_del = NULL;

            // Check if its ready or not
            for (size_t i = 0; i< l_objs_size; i++ ){
                // dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t*) l_objs[i].value;
                // size_t l_event_size = l_objs[i].value_len;
                dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *)
                                ((dap_chain_cs_dag_event_round_item_t *)l_objs[i].value)->event;
                size_t l_event_size = ((dap_chain_cs_dag_event_round_item_t *)l_objs[i].value)->event_size;
                l_dag->callback_cs_set_event_round_cfg(l_dag, &((dap_chain_cs_dag_event_round_item_t *)l_objs[i].value)->cfg);
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
                        dap_chain_atom_ptr_t l_new_atom = (dap_chain_atom_ptr_t)dap_chain_cs_dag_event_copy(l_event, l_event_size); // produce deep copy of event;
                        memcpy(l_new_atom, l_event, l_event_size);
                        if(s_chain_callback_atom_add(l_chain, l_new_atom,l_event_size) < 0) { // Add new atom in chain
                            DAP_DELETE(l_new_atom);
                            dap_string_append_printf(l_str_ret_tmp, "Event %s not added in chain\n", l_objs[i].key);
                        }
                        else {
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
                dap_chain_cell_id_t l_cell_id = {
                    .uint64 = l_net ? l_net->pub.cell_id.uint64 : 0
                };
                dap_chain_cell_t *l_cell = dap_chain_cell_find_by_id(l_chain, l_cell_id);
                if (!l_cell)
                    l_cell = dap_chain_cell_create_fill(l_chain, l_cell_id);
                if(l_cell) {
                    if(dap_chain_cell_file_update(l_cell) > 0) {
                        // delete events from db
                        dap_list_t *l_list_tmp = l_list_to_del;
                        while(l_list_tmp) {
                            char *l_key = strdup((char*) l_list_tmp->data);
                            dap_chain_global_db_gr_del(l_key, l_dag->gdb_group_events_round_new);
                            l_list_tmp = dap_list_next(l_list_tmp);
                        }
                    }
                }
                dap_chain_cell_close(l_cell);
                dap_list_free(l_list_to_del);
            }

            // Cleaning up
            dap_chain_global_db_objs_delete(l_objs, l_objs_size);
            dap_chain_node_cli_set_reply_text(a_str_reply,l_str_ret_tmp->str);
            dap_string_free(l_str_ret_tmp,false);

            // Spread new  mempool changes and  dag events in network - going to SYNC_ALL
            // dap_chain_net_sync_all(l_net);
        }
    }else if ( l_event_cmd_str  ) {
        char *l_datum_hash_hex_str = NULL;
        char *l_datum_hash_base58_str = NULL;
        if  ( strcmp( l_event_cmd_str, "create" ) == 0  ) {
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-datum", &l_datum_hash_str);

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
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-event", &l_event_hash_str);
            l_event_subcmd = SUBCMD_EVENT_CANCEL;
        } else if ( strcmp( l_event_cmd_str, "list" ) == 0 ) {
            l_event_subcmd = SUBCMD_EVENT_LIST;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-from", &l_from_events_str);
        } else if ( strcmp( l_event_cmd_str,"dump") == 0 ) {
            l_event_subcmd = SUBCMD_EVENT_DUMP;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-from", &l_from_events_str);
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-event", &l_event_hash_str);
        } else {
            l_event_subcmd = SUBCMD_UNDEFINED;
        }

        char *l_event_hash_hex_str = NULL;
        char *l_event_hash_base58_str = NULL;
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
            dap_chain_hash_fast_from_str(l_event_hash_hex_str,&l_event_hash);

        switch ( l_event_subcmd ){
            case SUBCMD_EVENT_CREATE:{
                size_t l_datums_count=1;
                char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);
                dap_chain_datum_t ** l_datums = DAP_NEW_Z_SIZE(dap_chain_datum_t*,
                                                               sizeof(dap_chain_datum_t*)*l_datums_count);
                size_t l_datum_size = 0;
                dap_chain_datum_t * l_datum = (dap_chain_datum_t*) dap_chain_global_db_gr_get( l_datum_hash_hex_str ,
                                                                                                  &l_datum_size,
                                                                   l_gdb_group_mempool);
                l_datums[0] = l_datum;
                if ( s_chain_callback_datums_pool_proc(l_chain,l_datums,l_datums_count ) == l_datums_count ){
                    for ( size_t i = 0; i <l_datums_count; i++){
                       dap_chain_hash_fast_t l_datum_hash;
                       dap_hash_fast(l_datums[i],dap_chain_datum_size(l_datums[i]),&l_datum_hash);
                       char * l_datums_datum_hash_str = dap_chain_hash_fast_to_str_new(&l_datum_hash);
                       if ( dap_chain_global_db_gr_del( dap_strdup(l_datums_datum_hash_str),l_gdb_group_mempool ) ){
                           dap_chain_node_cli_set_reply_text(a_str_reply,
                                                             "Converted datum %s from mempool to event in the new forming round ",
                                                             l_datums_datum_hash_str);
                           DAP_DELETE(l_datums_datum_hash_str);
                           ret = 0;
                       }else {
                           dap_chain_node_cli_set_reply_text(a_str_reply,
                                                             "Warning! Can't delete datum %s from mempool after conversion to event in the new forming round ",
                                                             l_datums_datum_hash_str);
                           ret = 1;
                       }
                    }
                }else {
                    if(!dap_strcmp(l_hash_out_type,"hex")){
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                                                      "Warning! Can't convert datum %s from mempool to event in the new forming round ", l_datum_hash_hex_str);
                    }
                else {
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                            "Warning! Can't convert datum %s from mempool to event in the new forming round ", l_datum_hash_base58_str);
                }
                    ret = -12;

                }
                DAP_DELETE(l_gdb_group_mempool);
                DAP_DELETE(l_datum_hash_hex_str);
                DAP_DELETE(l_datum_hash_base58_str);
                // dap_chain_net_sync_all(l_net);
            }break;
            case SUBCMD_EVENT_CANCEL:{
                char * l_gdb_group_events = DAP_CHAIN_CS_DAG(l_chain)->gdb_group_events_round_new;
                if ( dap_chain_global_db_gr_del( dap_strdup(l_event_hash_hex_str) ,l_gdb_group_events ) ){
                    if(!dap_strcmp(l_hash_out_type, "hex")){
                        dap_chain_node_cli_set_reply_text(a_str_reply,
                                "Successfuly removed event %s from the new forming round ",
                                l_event_hash_hex_str);
                    }
                    else{
                        dap_chain_node_cli_set_reply_text(a_str_reply,
                                "Successfuly removed event %s from the new forming round ",
                                l_event_hash_base58_str);
                    }
                    ret = 0;
                }else {
                    dap_chain_cs_dag_event_item_t * l_event_item = NULL;
                    pthread_rwlock_rdlock(&PVT(l_dag)->events_rwlock);
                    HASH_FIND(hh,PVT(l_dag)->events,&l_event_hash,sizeof(l_event_hash),l_event_item);
                    pthread_rwlock_unlock(&PVT(l_dag)->events_rwlock);
                    if ( l_event_item ){
                        pthread_rwlock_wrlock(&PVT(l_dag)->events_rwlock);
                        HASH_DELETE(hh, PVT(l_dag)->events, l_event_item);
                        pthread_rwlock_unlock(&PVT(l_dag)->events_rwlock);
                        if(!dap_strcmp(l_hash_out_type, "hex")) {
                            log_it(L_WARNING, "Dropped event %s from chains! Hope you know what are you doing!",
                                    l_event_hash_hex_str);
                            dap_chain_node_cli_set_reply_text(a_str_reply,
                                    "Dropped event 0x%s from chains! Hope you know what are you doing! ",
                                    l_event_hash_hex_str);
                        }
                        else {
                            log_it(L_WARNING, "Dropped event %s from chains! Hope you know what are you doing!",
                                    l_event_hash_base58_str);
                            dap_chain_node_cli_set_reply_text(a_str_reply,
                                    "Dropped event 0x%s from chains! Hope you know what are you doing! ",
                                    l_event_hash_base58_str);
                        }
                        dap_chain_save_all(l_chain);
                    }else {
                        if(!dap_strcmp(l_hash_out_type, "hex")) {
                            dap_chain_node_cli_set_reply_text(a_str_reply,
                                    "Can't remove event 0x%s ",
                                    l_event_hash_hex_str);
                        }
                        else {
                            dap_chain_node_cli_set_reply_text(a_str_reply,
                                    "Can't remove event 0x%s ",
                                    l_event_hash_base58_str);
                        }
                        ret = -1;
                    }
                }
                DAP_DELETE(l_event_hash_hex_str);
                DAP_DELETE(l_event_hash_base58_str);
                // DAP_DELETE( l_gdb_group_events );
                // dap_chain_net_sync_gdb(l_net);
            }break;
            case SUBCMD_EVENT_DUMP:{
                dap_chain_cs_dag_event_t * l_event = NULL;
                dap_chain_cs_dag_event_round_cfg_t l_event_round_cfg;
                size_t l_event_size = 0;
                if ( l_from_events_str ){
                    if ( strcmp(l_from_events_str,"round.new") == 0 ){
                        const char * l_gdb_group_events = l_dag->gdb_group_events_round_new;
                        // l_event = (dap_chain_cs_dag_event_t *)  dap_chain_global_db_gr_get
                        //                       ( l_event_hash_str ,&l_event_size,l_gdb_group_events );
                        l_event = dap_chain_cs_dag_event_gdb_get(l_event_hash_str, &l_event_size,
                                                                l_gdb_group_events, &l_event_round_cfg);
                    }else if ( strncmp(l_from_events_str,"round.",6) == 0){

                    }else if ( strcmp(l_from_events_str,"events_lasts") == 0){
                        dap_chain_cs_dag_event_item_t * l_event_item = NULL;
                        pthread_rwlock_rdlock(&PVT(l_dag)->events_rwlock);
                        HASH_FIND(hh,PVT(l_dag)->events_lasts_unlinked,&l_event_hash,sizeof(l_event_hash),l_event_item);
                        pthread_rwlock_unlock(&PVT(l_dag)->events_rwlock);
                        if ( l_event_item )
                            l_event = l_event_item->event;
                        else {
                            ret = -23;
                            dap_chain_node_cli_set_reply_text(a_str_reply,
                                                              "Can't find event %s in events_last table\n", l_event_hash_str);
                            break;
                        }
                    }else if ( strcmp(l_from_events_str,"events") == 0){
                        dap_chain_cs_dag_event_item_t * l_event_item = NULL;
                        pthread_rwlock_rdlock(&PVT(l_dag)->events_rwlock);
                        HASH_FIND(hh,PVT(l_dag)->events,&l_event_hash,sizeof(l_event_hash),l_event_item);
                        pthread_rwlock_unlock(&PVT(l_dag)->events_rwlock);
                        if ( l_event_item ) {
                            l_event = l_event_item->event;
                            l_event_size = l_event_item->event_size;
                        } else {
                            ret = -24;
                            dap_chain_node_cli_set_reply_text(a_str_reply,
                                                              "Can't find event %s in events table\n", l_event_hash_str);
                            break;
                        }

                    }else {
                        ret = -22;
                        dap_chain_node_cli_set_reply_text(a_str_reply,
                                                          "Wrong events_from option \"%s\", need one of variant: events, round.new, events_lasts, round.0x0123456789ABCDEF", l_from_events_str);
                        break;

                    }
                } else {
                    ret = -21;
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                                                      "No events_from option");
                    break;
                }
                if ( l_event ){
                    dap_string_t * l_str_tmp = dap_string_new(NULL);
                    char buf[50];
                    time_t l_ts_reated = (time_t) l_event->header.ts_created;
                    dap_string_append_printf(l_str_tmp,"\nEvent %s:\n", l_event_hash_str);

                    // Round cfg
                    if ( strcmp(l_from_events_str,"round.new") == 0 ) {
                        dap_string_append_printf(l_str_tmp,
                            "\t\tRound cfg:\n\t\t\t\tconfirmations_minimum: %d\n\t\t\t\tconfirmations_timeout: %d\n", 
                            l_event_round_cfg.confirmations_minimum,
                            l_event_round_cfg.confirmations_timeout);
                        char * l_hash_str = dap_chain_hash_fast_to_str_new(&l_event_round_cfg.first_event_hash);
                        dap_string_append_printf(l_str_tmp, "\t\t\t\tfirst_event_hash: %s\n", l_hash_str);
                        DAP_DELETE(l_hash_str);
                        dap_string_append_printf(l_str_tmp,
                            "\t\t\t\tts_update: %s", 
                            dap_ctime_r((time_t *)&l_event_round_cfg.ts_update, buf) );
                        if (l_event_round_cfg.ts_confirmations_minimum_completed != 0)
                            dap_string_append_printf(l_str_tmp,
                                "\t\t\t\tts_confirmations_minimum_completed: %s", 
                                dap_ctime_r((time_t *)&l_event_round_cfg.ts_confirmations_minimum_completed, buf) );
                    }

                     // Header
                    dap_string_append_printf(l_str_tmp,"\t\tHeader:\n");
                    dap_string_append_printf(l_str_tmp,"\t\t\t\tversion: 0x%02X\n",l_event->header.version);
                    dap_string_append_printf(l_str_tmp,"\t\t\t\tcell_id: 0x%016"DAP_UINT64_FORMAT_x"\n",l_event->header.cell_id.uint64);
                    dap_string_append_printf(l_str_tmp,"\t\t\t\tchain_id: 0x%016"DAP_UINT64_FORMAT_X"\n",l_event->header.chain_id.uint64);
                    dap_string_append_printf(l_str_tmp,"\t\t\t\tts_created: %s\n", dap_ctime_r(&l_ts_reated, buf) );

                    // Hash links
                    dap_string_append_printf(l_str_tmp,"\t\t\t\thashes:\tcount: %u\n",l_event->header.hash_count);
                    for (uint16_t i=0; i < l_event->header.hash_count; i++){
                        dap_chain_hash_fast_t * l_hash = (dap_chain_hash_fast_t *) (l_event->hashes_n_datum_n_signs +
                                i*sizeof (dap_chain_hash_fast_t));
                        char * l_hash_str = dap_chain_hash_fast_to_str_new(l_hash);
                        dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\thash: %s\n",l_hash_str);
                        DAP_DELETE(l_hash_str);
                    }
                    size_t l_offset =  l_event->header.hash_count*sizeof (dap_chain_hash_fast_t);
                    dap_chain_datum_t * l_datum = (dap_chain_datum_t*) (l_event->hashes_n_datum_n_signs + l_offset);
                    size_t l_datum_size =  dap_chain_datum_size(l_datum);
                    time_t l_datum_ts_create = (time_t) l_datum->header.ts_create;

                    // Nested datum
                    const char *l_datum_type = NULL;
                    DAP_DATUM_TYPE_STR(l_datum->header.type_id, l_datum_type)
                    dap_string_append_printf(l_str_tmp,"\t\t\t\tdatum:\tdatum_size: %zu\n",l_datum_size);
                    dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\tversion:=0x%02hhX\n", l_datum->header.version_id);
                    dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\ttype_id:=%s\n", l_datum_type);
                    dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\tts_create=%s\n", dap_ctime_r( &l_datum_ts_create,buf ));
                    dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\tdata_size=%u\n", l_datum->header.data_size);

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
                        dap_chain_addr_t l_addr = {0};
                        dap_chain_hash_fast_t l_pkey_hash;
                        dap_sign_get_pkey_hash(l_sign, &l_pkey_hash);
                        dap_chain_addr_fill(&l_addr, l_sign->header.type, &l_pkey_hash, l_net->pub.id);
                        char * l_addr_str = dap_chain_addr_to_str(&l_addr);
                        dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\ttype: %s\taddr: %s"
                                                           "\n", dap_sign_type_to_str( l_sign->header.type ),
                                                 l_addr_str );
                        l_offset += l_sign_size;
                        DAP_DELETE( l_addr_str);
                    }
                    dap_chain_net_dump_datum(l_str_tmp, l_datum, l_hash_out_type);

                    dap_chain_node_cli_set_reply_text(a_str_reply, l_str_tmp->str);
                    dap_string_free(l_str_tmp,false);
                    ret=0;
                }else {
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                                                      "Can't find event 0x%s in the new forming round ",
                                                      l_event_hash_str);
                    ret=-10;
                }
            }break;
            case SUBCMD_EVENT_LIST:{
                if( (l_from_events_str == NULL) ||
                        (strcmp(l_from_events_str,"round.new") == 0) ){
                    char * l_gdb_group_events = DAP_CHAIN_CS_DAG(l_chain)->gdb_group_events_round_new;
                    dap_string_t * l_str_tmp = dap_string_new("");
                    if ( l_gdb_group_events ){
                        dap_global_db_obj_t * l_objs;
                        size_t l_objs_count = 0;
                        l_objs = dap_chain_global_db_gr_load(l_gdb_group_events,&l_objs_count);
                        dap_string_append_printf(l_str_tmp,"%s.%s: Found %zu records :\n",l_net->pub.name,l_chain->name,l_objs_count);

                        for (size_t i = 0; i< l_objs_count; i++){
                            // dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *) l_objs[i].value;
                            dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *)
                                            ((dap_chain_cs_dag_event_round_item_t *)l_objs[i].value)->event;
                            char buf[50];
                            time_t l_ts_create = (time_t) l_event->header.ts_created;
                            dap_string_append_printf(l_str_tmp,"\t%s: ts_create=%s",
                                                     l_objs[i].key, dap_ctime_r( &l_ts_create,buf ) );

                        }
                        // bugs-3932
                        //DAP_DELETE( l_gdb_group_events);
                        if (l_objs && l_objs_count )
                            dap_chain_global_db_objs_delete(l_objs, l_objs_count);
                        ret = 0;
                    } else {
                        dap_string_append_printf(l_str_tmp,"%s.%s: Error! No GlobalDB group!\n",l_net->pub.name,l_chain->name);
                        ret = -2;

                    }
                    dap_chain_node_cli_set_reply_text(a_str_reply, l_str_tmp->str);
                    dap_string_free(l_str_tmp,false);
                }else if (l_from_events_str && (strcmp(l_from_events_str,"events") == 0) ){
                    dap_string_t * l_str_tmp = dap_string_new(NULL);
                    pthread_rwlock_rdlock(&PVT(l_dag)->events_rwlock);
                    size_t l_events_count = HASH_COUNT(PVT(l_dag)->events);
                    dap_string_append_printf(l_str_tmp,"%s.%s: Have %zu events :\n",
                                             l_net->pub.name,l_chain->name,l_events_count);
                    dap_chain_cs_dag_event_item_t * l_event_item = NULL,*l_event_item_tmp = NULL;
                    HASH_ITER(hh,PVT(l_dag)->events,l_event_item, l_event_item_tmp ) {
                        char buf[50];
                        char * l_event_item_hash_str = dap_chain_hash_fast_to_str_new( &l_event_item->hash);
                        time_t l_ts_create = (time_t) l_event_item->event->header.ts_created;
                        dap_string_append_printf(l_str_tmp,"\t%s: ts_create=%s",
                                                 l_event_item_hash_str, dap_ctime_r( &l_ts_create,buf ) );
                        DAP_DELETE(l_event_item_hash_str);
                    }
                    pthread_rwlock_unlock(&PVT(l_dag)->events_rwlock);
                    dap_chain_node_cli_set_reply_text(a_str_reply, l_str_tmp->str);
                    dap_string_free(l_str_tmp,false);

                }else {
                    dap_chain_node_cli_set_reply_text(a_str_reply, "Undefined events source for listing ");
                    ret=-14;

                }
            }break;

            case SUBCMD_UNDEFINED: {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "Undefined event subcommand \"%s\" ",
                                                  l_event_cmd_str);
                ret=-11;
            }
        }
    }else {
        dap_chain_node_cli_set_reply_text(a_str_reply,
                                          "Undefined subcommand");
        ret = -13;
    }
    return ret;
}
