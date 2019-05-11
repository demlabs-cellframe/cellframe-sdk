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
#include "uthash.h"

#include "dap_common.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_hash.h"
#include "dap_chain_datum.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_global_db.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_net.h"

#define LOG_TAG "dap_chain_cs_dag"


typedef struct dap_chain_cs_dag_event_item {
    dap_chain_hash_fast_t hash;
    time_t ts_added;
    dap_chain_cs_dag_event_t *event;
    UT_hash_handle hh;
} dap_chain_cs_dag_event_item_t;

typedef struct dap_chain_cs_dag_pvt {
    dap_enc_key_t* datum_add_sign_key;


    pthread_rwlock_t events_rwlock;
    dap_chain_cs_dag_event_item_t * events;
    dap_chain_cs_dag_event_item_t * events_treshold;
    dap_chain_cs_dag_event_item_t * events_lasts;

} dap_chain_cs_dag_pvt_t;

#define PVT(a) ((dap_chain_cs_dag_pvt_t *) a->_pvt )

// Atomic element organization callbacks
static int s_chain_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t *);                      //    Accept new event in dag
static int s_chain_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_ptr_t *);                   //    Verify new event in dag
static size_t s_chain_callback_atom_hdr_get_size(dap_chain_atom_ptr_t *);                                 //    Get dag event size
static size_t s_chain_callback_atom_get_static_hdr_size(void);                               //    Get dag event header size

static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create(dap_chain_t * a_chain );              //    Get the fisrt event from dag
static dap_chain_atom_ptr_t* s_chain_callback_atom_iter_get_first( dap_chain_atom_iter_t * a_atom_iter ); //    Get the fisrt event from dag
static dap_chain_atom_ptr_t* s_chain_callback_atom_iter_get_next( dap_chain_atom_iter_t * a_atom_iter );  //    Get the next event from dag
static void s_chain_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter );                  //    Get the fisrt event from dag

static size_t s_chain_callback_events_round_new_add_datums(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums, size_t a_datums_size);
// Datum ops
/*
static dap_chain_datum_iter_t* s_chain_callback_datum_iter_create(dap_chain_t * a_chain );
static void s_chain_callback_datum_iter_delete(dap_chain_datum_iter_t * a_iter );
static dap_chain_datum_t* s_chain_callback_datum_iter_get_first( dap_chain_datum_iter_t * a_datum_iter ); // Get the fisrt datum from dag
static dap_chain_datum_t* s_chain_callback_datum_iter_get_next( dap_chain_datum_iter_t * a_datum_iter ); // Get the next datum from dag
*/

static int s_cli_dag(int argc, const char ** argv, char **str_reply);

static bool s_seed_mode = false;
/**
 * @brief dap_chain_cs_dag_init
 * @return
 */
int dap_chain_cs_dag_init(void)
{
    srand((unsigned int) time(NULL));
    dap_chain_class_add( "dag", dap_chain_cs_dag_new );
    s_seed_mode = dap_config_get_item_bool_default(g_config,"general","seed_mode",false);
    dap_chain_node_cli_cmd_item_create ("dag", s_cli_dag, "DAG commands",
                                        "\tCreate event from datum mempool element\n\n"
        "dag -net <chain net name> -chain <chain name> event create -datum <datum hash>\n"
                                        "\tRemove event from forming new round and put back its datum to mempool\n\n"
        "dag -net <chain net name> -chain <chain name> event cancel -event <event hash>\n"
                                        "\tDump event info\n\n"
        "dag -net <chain net name> -chain <chain name> event dump -event <event hash> -from < events | events_lasts | round.new  | round.<Round id in hex> >\n"
                                        "\tShow event list \n\n"
        "dag -net <chain net name> -chain <chain name> event list -from < events | events_lasts | round.new  | round.<Round id in hex> \n\n"
                                        "\t<datum hash> Datum hash from mempool\n"
                                        "\t<event hash> Event hash from forming new round, must return back datum to mempool\n\n"
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

    // Atom element callbacks
    a_chain->callback_atom_add = s_chain_callback_atom_add ;  // Accept new element in chain
    a_chain->callback_atom_verify = s_chain_callback_atom_verify ;  // Verify new element in chain
    a_chain->callback_atom_hdr_get_size  = s_chain_callback_atom_hdr_get_size; // Get dag event size
    a_chain->callback_atom_get_hdr_size = s_chain_callback_atom_get_static_hdr_size; // Get dag event hdr size

    a_chain->callback_atom_iter_create = s_chain_callback_atom_iter_create;
    a_chain->callback_atom_iter_delete = s_chain_callback_atom_iter_delete;
    a_chain->callback_atom_iter_get_first = s_chain_callback_atom_iter_get_first; // Get the fisrt element from chain
    a_chain->callback_atom_iter_get_next = s_chain_callback_atom_iter_get_next; // Get the next element from chain from the current one

    a_chain->callback_datums_pool_proc = s_chain_callback_events_round_new_add_datums;

    // Datum operations callbacks
/*
    a_chain->callback_datum_iter_create = s_chain_callback_datum_iter_create; // Datum iterator create
    a_chain->callback_datum_iter_delete = s_chain_callback_datum_iter_delete; // Datum iterator delete
    a_chain->callback_datum_iter_get_first = s_chain_callback_datum_iter_get_first; // Get the fisrt datum from chain
    a_chain->callback_datum_iter_get_next = s_chain_callback_datum_iter_get_next; // Get the next datum from chain from the current one
*/
    // Others
    a_chain->_inheritor = l_dag;

    l_dag->is_single_line = dap_config_get_item_bool_default(a_chain_cfg,"dag","is_single_line",false);
    l_dag->is_celled = dap_config_get_item_bool_default(a_chain_cfg,"dag","is_celled",false);
    l_dag->datum_add_hashes_count = dap_config_get_item_uint16_default(a_chain_cfg,"dag","datum_add_hashes_count",1);
    l_dag->gdb_group_events_round_new = strdup( dap_config_get_item_str_default(a_chain_cfg,"dag","gdb_group_events_round_new",
                                                                        "events.round.new"));
    if ( l_dag->is_single_line ) {
        log_it (L_NOTICE, "DAG chain initialized (single line)");
    } else {
        log_it (L_NOTICE, "DAG chain initialized (multichain)");
    }

    return 0;
}

/**
 * @brief dap_chain_cs_dag_delete
 * @param a_dag
 * @return
 */
void dap_chain_cs_dag_delete(dap_chain_t * a_chain)
{
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG ( a_chain );
    pthread_rwlock_destroy(& PVT(l_dag)->events_rwlock);

    if(l_dag->callback_delete )
        l_dag->callback_delete(l_dag);
    if(l_dag->_inheritor)
        DAP_DELETE(l_dag->_inheritor);
    if(l_dag->_pvt)
        DAP_DELETE(l_dag->_pvt);
}

/**
 * @brief s_chain_callback_atom_add Accept new event in dag
 * @param a_chain DAG object
 * @param a_atom
 * @return 0 if verified and added well, otherwise if not
 */
static int s_chain_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t * a_atom)
{
    int ret = s_chain_callback_atom_verify (a_chain, a_atom);
    if ( ret < 0 ){
        log_it(L_WARNING,"Wrong event, can't accept, verification returned %d",ret);
        return  -1;
    }
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG(a_chain);
    dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *) a_atom;

    ret = l_dag->callback_cs_verify(l_dag,l_event);
    if ( ret != 0 ){
        log_it(L_WARNING,"Consensus can't accept the event, verification returned %d",ret);
        return  -2;
    }
    dap_chain_cs_dag_event_item_t * l_event_item = DAP_NEW_Z(dap_chain_cs_dag_event_item_t);
    l_event_item->event = l_event;
    dap_hash_fast(l_event, dap_chain_cs_dag_event_calc_size(l_event),&l_event_item->hash );

    // Put in main table or in the treshhold if not all the rest linked event are present
    dap_chain_cs_dag_event_item_t * l_event_search = NULL;
    dap_chain_cs_dag_event_item_t * l_events =( ret==0 ? PVT(l_dag)->events : PVT(l_dag)->events_treshold );
    pthread_rwlock_t * l_events_rwlock = &PVT(l_dag)->events_rwlock ;
    pthread_rwlock_wrlock( l_events_rwlock );
    HASH_FIND(hh, l_events,&l_event_item->hash,sizeof (l_event_search->hash),  l_event_search);
    if ( l_event_search ) {
        pthread_rwlock_unlock( l_events_rwlock );
        char * l_hash_str = dap_chain_hash_fast_to_str_new(&l_event_item->hash);
        log_it(L_ERROR, "Dag event %s is already present in dag",l_hash_str);
        DAP_DELETE(l_event_item);
        DAP_DELETE(l_hash_str);
        return -3;
    }
    HASH_ADD(hh, l_events,hash,sizeof (l_event_item->hash),  l_event_item);
    pthread_rwlock_unlock( l_events_rwlock );

    // Now check the treshold if some events now are ready to move to the main table
    dap_chain_cs_dag_proc_treshold(l_dag);
    return 0;
}

/**
 * @brief s_chain_callback_datums_add
 * @param a_chain
 * @param a_datums
 * @param a_datums_size
 */
static size_t s_chain_callback_events_round_new_add_datums(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums, size_t a_datums_count)
{
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG(a_chain);
    size_t l_datum_processed =0;
    size_t l_events_round_new_size = 0;
    // Load current events new round pool
    dap_global_db_obj_t ** l_events_round_new = dap_chain_global_db_gr_load(l_dag->gdb_group_events_round_new, &l_events_round_new_size );
    // Prepare hashes
    size_t l_hashes_int_size = ( l_events_round_new_size + a_datums_count )> l_dag->datum_add_hashes_count ?
                                   l_dag->datum_add_hashes_count :
                                   l_events_round_new_size+a_datums_count;

    if (l_dag->is_single_line ) // If single line - no any link inside
        l_hashes_int_size = 0;

    size_t l_hashes_ext_size = 1; // Change in cfg
    dap_chain_hash_fast_t * l_hashes = DAP_NEW_Z_SIZE(dap_chain_hash_fast_t,
                                             sizeof(dap_chain_hash_fast_t) *
                                             (l_hashes_int_size+l_hashes_ext_size)  );
    size_t l_hashes_linked = 0;

    for (size_t d = 0; d <a_datums_count ; d++){
        dap_chain_datum_t * l_datum = a_datums[d];

        if ( l_hashes_int_size ){
            // Linking randomly with current new round set
            size_t l_rnd_steps;
            // Linking events inside round
            l_rnd_steps = 0;
            do{
                int l_index = rand() % (int) l_events_round_new_size;
                dap_chain_hash_fast_t l_hash;
                dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *) l_events_round_new[l_index]->value;
                size_t l_event_size = dap_chain_cs_dag_event_calc_size(l_event);
                dap_hash_fast(l_event, l_event_size,&l_hash);

                bool l_is_already_in_event = false;
                for (uint16_t i=0; i<l_hashes_linked;i++ ){ // check if we already added it
                    if (memcmp(&l_hashes[i],&l_hash,sizeof (l_hash) )==0 ){
                        l_is_already_in_event = true;
                        break;
                    }
                }

                if ( ! l_is_already_in_event ){
                    memcpy(&l_hashes[l_hashes_linked],&l_hash,sizeof (l_hash) );
                    l_hashes_linked++;
                }
                l_rnd_steps++;
                if (l_rnd_steps > 100) // Too many attempts
                    break;
            } while (l_hashes_linked <(l_hashes_int_size) );

            // Check if we have enought hash links
            if (l_hashes_linked<l_hashes_int_size ){
                log_it(L_ERROR,"Can't link new events randomly for 100 attempts");
                break;
            }
        }
        // Now link with ext events
        if ( PVT(l_dag)->events_lasts ){ // Take then the first one if any present
            dap_chain_cs_dag_event_item_t *l_event_ext = PVT(l_dag)->events_lasts;
            memcpy(&l_hashes[l_hashes_linked],& l_event_ext->hash,sizeof (l_event_ext->hash) );
            l_hashes_linked++;
            HASH_DEL(PVT(l_dag)->events_lasts, l_event_ext);
        }

        if (l_hashes_linked || s_seed_mode ) {
            dap_chain_cs_dag_event_t * l_event = l_dag->callback_cs_event_create(l_dag,l_datum,l_hashes,l_hashes_linked);
            if ( l_event){ // Event is created
                dap_chain_hash_fast_t l_event_hash;
                dap_chain_cs_dag_event_calc_hash(l_event,&l_event_hash);
                char * l_event_hash_str = dap_chain_hash_fast_to_str_new(&l_event_hash);
                if( dap_chain_global_db_gr_set( l_event_hash_str, (uint8_t *) l_event, dap_chain_cs_dag_event_calc_size(l_event),
                                                l_dag->gdb_group_events_round_new ) ){
                    log_it(L_INFO,"Event %s placed in the new forming round",l_event_hash_str);
                    dap_chain_cs_dag_proc_event_round_new(l_dag);
                    l_datum_processed++;
                }else {
                    log_it(L_ERROR,"Can't add new event to the new events round");
                    break;
                }
            }
        }
    }
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
    pthread_rwlock_rdlock( &PVT(a_dag)->events_rwlock );
    HASH_FIND(hh, PVT(a_dag)->events ,a_hash,sizeof(*a_hash), l_event_item);
    dap_chain_cs_dag_event_t * l_event = l_event_item->event;
    pthread_rwlock_unlock( &PVT(a_dag)->events_rwlock );
    return  l_event;
}



/**
 * @brief s_chain_callback_atom_verify Verify atomic element
 * @param a_chain
 * @param a_atom
 * @return
 */
static int s_chain_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_ptr_t *  a_atom)
{
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG(a_chain);
    dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *) a_atom;
    int ret = l_dag->callback_cs_verify ( l_dag, l_event );
    if (ret == 0 ){
        for (size_t i = 0; i< l_event->header.hash_count; i++) {
            dap_chain_hash_fast_t * l_hash =  ((dap_chain_hash_fast_t *) l_event->hashes_n_datum_n_signs) + i;
            dap_chain_cs_dag_event_item_t * l_event_search = NULL;
            HASH_FIND(hh, PVT(l_dag)->events ,l_hash ,sizeof (*l_hash),  l_event_search);
            if ( l_event_search == NULL ){
                log_it(L_DEBUG, "Hash %s wasn't in hashtable of previously parsed");
                return 1;
            }

        }
        return 0;
    }else {
        return  ret;
    }
}

/**
 * @brief dap_chain_cs_dag_proc_event_round_new
 * @param a_dag
 */
void dap_chain_cs_dag_proc_event_round_new(dap_chain_cs_dag_t *a_dag)
{

}


/**
 * @brief s_dag_events_lasts_delete_linked_with_event
 * @param a_dag
 * @param a_event
 */
void s_dag_events_lasts_delete_linked_with_event(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_event)
{

}



int dap_chain_cs_dag_event_verify_hashes_with_treshold(dap_chain_cs_dag_t * a_dag, dap_chain_cs_dag_event_t * a_event)
{
    bool l_is_events_all_hashes = true;
    bool l_is_events_main_hashes = true;
    for (size_t i = 0; i< a_event->header.hash_count; i++) {
        dap_chain_hash_fast_t * l_hash =  ((dap_chain_hash_fast_t *) a_event->hashes_n_datum_n_signs) + i;
        dap_chain_cs_dag_event_item_t * l_event_search = NULL;
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
    if( l_is_events_all_hashes && l_is_events_main_hashes ){
        return  0;
    }else if ( ! l_is_events_all_hashes) {
        return  -1;
    }else {
        return  1;
    }
}

/**
 * @brief dap_chain_cs_dag_proc_treshold
 * @param a_dag
 */
void dap_chain_cs_dag_proc_treshold(dap_chain_cs_dag_t * a_dag)
{
    // TODO Process finish treshold. For now - easiest from possible
    pthread_rwlock_rdlock(&PVT(a_dag)->events_rwlock);
    dap_chain_cs_dag_event_item_t * l_event_item = NULL, * l_event_item_tmp = NULL;
    HASH_ITER(hh,PVT(a_dag)->events_treshold,l_event_item, l_event_item_tmp){
        dap_chain_cs_dag_event_t * l_event = l_event_item->event;
        int ret = dap_chain_cs_dag_event_verify_hashes_with_treshold (a_dag,l_event);
        if ( ret == 0){ // All its hashes are in main table, move thats one too into it
            pthread_rwlock_unlock(&PVT(a_dag)->events_rwlock);
            pthread_rwlock_wrlock(&PVT(a_dag)->events_rwlock);
            HASH_DEL(PVT(a_dag)->events_treshold,l_event_item);
            HASH_ADD(hh, PVT(a_dag)->events, hash,sizeof (l_event_item->hash),  l_event_item);
            s_dag_events_lasts_delete_linked_with_event(a_dag, l_event);
        }
    }
    pthread_rwlock_unlock(&PVT(a_dag)->events_rwlock);
}


/**
 * @brief s_chain_callback_atom_get_size Get size of atomic element
 * @param a_atom
 * @return
 */
static size_t s_chain_callback_atom_hdr_get_size(dap_chain_atom_ptr_t * a_atom)
{
    return dap_chain_cs_dag_event_calc_size( (dap_chain_cs_dag_event_t * ) a_atom);
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
 * @brief s_chain_callback_atom_iter_create Create atomic element iterator
 * @param a_chain
 * @return
 */
static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create(dap_chain_t * a_chain )
{
    dap_chain_atom_iter_t * l_atom_iter = DAP_NEW_Z(dap_chain_atom_iter_t);
    l_atom_iter->chain = a_chain;
    return l_atom_iter;
}

/**
 * @brief s_chain_callback_atom_iter_get_first Get the first dag event
 * @param a_atom_iter
 * @return
 */
static dap_chain_atom_ptr_t* s_chain_callback_atom_iter_get_first(dap_chain_atom_iter_t * a_atom_iter )
{
    a_atom_iter->cur =  a_atom_iter->cur ?
                (dap_chain_cs_dag_event_t*) PVT (DAP_CHAIN_CS_DAG( a_atom_iter->chain) )->events->event : NULL;
    a_atom_iter->cur_item = PVT (DAP_CHAIN_CS_DAG( a_atom_iter->chain) )->events;
    return a_atom_iter->cur;
}

/**
 * @brief s_chain_callback_atom_iter_get_next Get the next dag event
 * @param a_atom_iter
 * @return
 */
static dap_chain_atom_ptr_t* s_chain_callback_atom_iter_get_next( dap_chain_atom_iter_t * a_atom_iter )
{
    if (a_atom_iter->cur ){
        dap_chain_cs_dag_event_item_t * l_event_item = (dap_chain_cs_dag_event_item_t*) a_atom_iter->cur_item;
        a_atom_iter->cur_item = l_event_item->hh.next;
        l_event_item = (dap_chain_cs_dag_event_item_t*) a_atom_iter->cur_item;
        if ( a_atom_iter->cur_item)
            a_atom_iter->cur = l_event_item->event;
        else {
            dap_chain_cs_dag_event_item_t * l_event_search = NULL;
            dap_chain_cs_dag_pvt_t * l_dag_pvt = PVT (DAP_CHAIN_CS_DAG( a_atom_iter->chain));
            HASH_FIND(hh,l_dag_pvt->events,&l_event_item->hash,sizeof(l_event_item->hash),l_event_search);
            if (l_event_search){
                a_atom_iter->cur_item = l_dag_pvt->events_treshold;
                a_atom_iter->cur = l_dag_pvt->events_treshold ? l_dag_pvt->events_treshold->event : NULL ;
            }
        }
    }
    return a_atom_iter->cur;
}

/**
 * @brief s_chain_callback_atom_iter_delete Delete dag event iterator
 * @param a_atom_iter
 */
static void s_chain_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter )
{
    DAP_DELETE(a_atom_iter);
}

/**
 * @brief s_cli_dag
 * @param argc
 * @param argv
 * @param str_reply
 * @return
 */
static int s_cli_dag(int argc, const char ** argv, char **a_str_reply)
{
    enum {
        SUBCMD_EVENT_CREATE,
        SUBCMD_EVENT_CANCEL,
        SUBCMD_EVENT_LIST,
        SUBCMD_EVENT_DUMP,
        SUBCMD_UNDEFINED=-1
    } l_subcmd={0};

    int arg_index = 1;
    const char *str_tmp = NULL;
    char *str_reply_tmp = NULL;

    const char * l_net_name = NULL;

    const char * l_chain_name = NULL;

    const char * l_event_cmd_str = NULL;

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
    if ( l_event_cmd_str  ) {
        if  ( strcmp( l_event_cmd_str, "create" ) == 0  ) {
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-datum", &l_datum_hash_str);
            l_subcmd = SUBCMD_EVENT_CREATE;
        } else if (  strcmp( l_event_cmd_str, "cancel" ) == 0  ) {
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-event", &l_event_hash_str);
            l_subcmd = SUBCMD_EVENT_CANCEL;
        } else if ( strcmp( l_event_cmd_str, "list" ) == 0 ) {
            l_subcmd = SUBCMD_EVENT_LIST;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-from", &l_from_events_str);
        } else if ( strcmp( l_event_cmd_str,"dump") == 0 ) {
            l_subcmd = SUBCMD_EVENT_DUMP;
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-from", &l_from_events_str);
            dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-event", &l_event_hash_str);
        } else {
            l_subcmd = SUBCMD_UNDEFINED;
        }

        if (l_event_hash_str)
            dap_chain_str_to_hash_fast(l_event_hash_str,&l_event_hash);

        switch ( l_subcmd ){
            case SUBCMD_EVENT_CREATE:{
                size_t l_datums_count=1;
                char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);
                dap_chain_datum_t ** l_datums = DAP_NEW_Z_SIZE(dap_chain_datum_t*,
                                                               sizeof(dap_chain_datum_t*)*l_datums_count);
                size_t l_datum_size = 0;
                dap_chain_datum_t * l_datum = (dap_chain_datum_t*) dap_chain_global_db_gr_get( l_datum_hash_str ,
                                                                                                  &l_datum_size,
                                                                   l_gdb_group_mempool);
                l_datums[0] = l_datum;
                if ( s_chain_callback_events_round_new_add_datums(l_chain,l_datums,l_datums_count ) == l_datums_count ){
                    for ( size_t i = 0; i <l_datums_count; i++){
                       dap_chain_hash_fast_t l_datum_hash;
                       dap_hash_fast(l_datums[i],dap_chain_datum_size(l_datums[i]),&l_datum_hash);
                       char * l_datums_datum_hash_str = dap_chain_hash_fast_to_str_new(&l_datum_hash);
                       if ( dap_chain_global_db_gr_del(l_datums_datum_hash_str,l_gdb_group_mempool ) ){
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
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                                                      "Warning! Can't convert datum %s from mempool toevent in the new forming round ",
                                                      l_datum_hash_str);
                    ret = -12;

                }
                DAP_DELETE(l_gdb_group_mempool);
            }break;
            case SUBCMD_EVENT_CANCEL:{
                char * l_gdb_group_events = DAP_CHAIN_CS_DAG(l_chain)->gdb_group_events_round_new;
                if ( dap_chain_global_db_gr_del(l_event_hash_str ,l_gdb_group_events ) ){
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                                                      "Successfuly removed event 0x%s from the new forming round ",
                                                      l_event_hash_str);
                    ret = 0;
                }else {
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                                                      "Can't remove event 0x%s from the new forming round ",
                                                      l_event_hash_str);
                    ret = -1;
                }

            }break;
            case SUBCMD_EVENT_DUMP:{
                dap_chain_cs_dag_event_t * l_event = NULL;
                size_t l_event_size = 0;
                if ( l_from_events_str ){
                    if ( strcmp(l_from_events_str,"round.new") == 0 ){
                        const char * l_gdb_group_events = l_dag->gdb_group_events_round_new;
                        l_event = (dap_chain_cs_dag_event_t *)  dap_chain_global_db_gr_get
                                              ( l_event_hash_str ,&l_event_size,l_gdb_group_events );
                    }else if ( strncmp(l_from_events_str,"round.",6) == 0){

                    }else if ( strcmp(l_from_events_str,"events_lasts") == 0){
                        dap_chain_cs_dag_event_item_t * l_event_item = NULL;
                        HASH_FIND(hh,PVT(l_dag)->events_lasts,&l_event_hash,sizeof(l_event_hash),l_event_item);
                        if ( l_event_item )
                            l_event = l_event_item->event;
                        else {
                            ret = -23;
                            dap_chain_node_cli_set_reply_text(a_str_reply,
                                                              "Can't find events %s in events_last table\n");
                            break;
                        }
                    }else if ( strcmp(l_from_events_str,"events") == 0){
                        dap_chain_cs_dag_event_item_t * l_event_item = NULL;
                        HASH_FIND(hh,PVT(l_dag)->events,&l_event_hash,sizeof(l_event_hash),l_event_item);
                        if ( l_event_item )
                            l_event = l_event_item->event;
                        else {
                            ret = -24;
                            dap_chain_node_cli_set_reply_text(a_str_reply,
                                                              "Can't find events %s in events table\n");
                            break;
                        }

                    }else {
                        ret = -22;
                        dap_chain_node_cli_set_reply_text(a_str_reply,
                                                          "Wrong events_from option \"%s\", need one of variant: events, round.new, events_lasts, round.0x0123456789ABCDEF");
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
                    char * l_ctime_tmp = NULL;
                    time_t l_ts_reated = (time_t) l_event->header.ts_created;
                     // Header
                    dap_string_append_printf(l_str_tmp,"Event 0x%s:\n", l_event_hash_str);
                    dap_string_append_printf(l_str_tmp,"\t\t\t\tversion: 0x%04sX\n",l_event->header.version);
                    dap_string_append_printf(l_str_tmp,"\t\t\t\tcell_id: 0x%016llX\n",l_event->header.cell_id.uint64);
                    dap_string_append_printf(l_str_tmp,"\t\t\t\tchain_id: 0x%016llX\n",l_event->header.chain_id.uint64);
                    dap_string_append_printf(l_str_tmp,"\t\t\t\tts_created: %s\n",ctime_r(&l_ts_reated,l_ctime_tmp) );

                    // Hash links
                    dap_string_append_printf(l_str_tmp,"\t\t\t\thashes:\tcount: %us\n",l_event->header.hash_count);
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
                    char buf[50];
                    time_t l_datum_ts_create = (time_t) l_datum->header.ts_create;

                    // Nested datum
                    dap_string_append_printf(l_str_tmp,"\t\t\t\tdatum:\tdatum_size: %u\n",l_datum_size);
                    dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\tversion:=%0x02X\n", l_datum->header.version_id);
                    dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\ttype_id:=%s\n", c_datum_type_str[l_datum->header.type_id]);
                    dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\tts_create=%s\n",ctime_r( &l_datum_ts_create,buf ));
                    dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\tdata_size=%u\n", l_datum->header.data_size);

                    // Signatures
                    dap_string_append_printf(l_str_tmp,"\t\t\t\tsigns:\tcount: %us\n",l_event->header.signs_count);
                    l_offset += l_datum_size;
                    while (l_offset + sizeof (l_event->header) < l_event_size ){
                        dap_chain_sign_t * l_sign =(dap_chain_sign_t *) (l_event->hashes_n_datum_n_signs +l_offset);
                        size_t l_sign_size = dap_chain_sign_get_size(l_sign);
                        if (l_sign_size == 0 ){
                            dap_string_append_printf(l_str_tmp,"\t\t\t\tERROR: wrong sign size 0, stop parsing headers\n");
                            break;
                        }
                        dap_enc_key_t * l_sign_key = dap_chain_sign_to_enc_key(l_sign);
                        dap_chain_addr_t l_addr = {0};
                        dap_chain_addr_fill(&l_addr,l_sign_key,&l_net->pub.id);
                        char * l_addr_str = dap_chain_addr_to_str(&l_addr);
                        dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\ttype: %s\taddr: %s"
                                                           "n", dap_chain_sign_type_to_str( l_sign->header.type ),
                                                 l_addr_str );
                        l_offset += l_sign_size;
                        DAP_DELETE( l_addr_str);
                        dap_enc_key_delete(l_sign_key);
                    }

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
                char * l_gdb_group_events = DAP_CHAIN_CS_DAG(l_chain)->gdb_group_events_round_new;
                dap_global_db_obj_t ** l_objs;
                size_t l_objs_count = 0;
                l_objs = dap_chain_global_db_gr_load(l_gdb_group_events,&l_objs_count);
            }break;
            case SUBCMD_UNDEFINED: {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "Undefined event subcommand %s ",
                                                  l_subcmd);
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
