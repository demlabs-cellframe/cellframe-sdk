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
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include "uthash.h"

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_chain_datum.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"

#define LOG_TAG "dap_chain_cs_dag"

typedef struct dap_chain_cs_dag_event_item {
    dap_chain_hash_fast_t hash;
    time_t ts_added;
    dap_chain_cs_dag_event_t *event;
    UT_hash_handle hh;
} dap_chain_cs_dag_event_item_t;

typedef struct dap_chain_cs_dag_pvt {
    dap_chain_cs_dag_event_item_t * events;
    pthread_rwlock_t events_rwlock;

    dap_chain_cs_dag_event_item_t * events_treshold;
    pthread_rwlock_t events_treshold_rwlock;
    dap_chain_cs_dag_event_item_t * events_lasts;
} dap_chain_cs_dag_pvt_t;

#define PVT(a) ((dap_chain_cs_dag_pvt_t *) a->_pvt )

// Atomic element organization callbacks
static int s_chain_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_t *);                      //    Accept new event in dag
static int s_chain_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_t *);                   //    Verify new event in dag
static size_t s_chain_callback_atom_hdr_get_size(dap_chain_atom_t *);                                 //    Get dag event size
static size_t s_chain_callback_atom_get_static_hdr_size();                               //    Get dag event header size

static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create(dap_chain_t * a_chain );              //    Get the fisrt event from dag
static dap_chain_atom_t* s_chain_callback_atom_iter_get_first( dap_chain_atom_iter_t * a_atom_iter ); //    Get the fisrt event from dag
static dap_chain_atom_t* s_chain_callback_atom_iter_get_next( dap_chain_atom_iter_t * a_atom_iter );  //    Get the next event from dag
static void s_chain_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter );                  //    Get the fisrt event from dag

// Datum ops

static dap_chain_datum_iter_t* s_chain_callback_datum_iter_create(dap_chain_t * a_chain );
static void s_chain_callback_datum_iter_delete(dap_chain_datum_iter_t * a_iter );
static dap_chain_datum_t* s_chain_callback_datum_iter_get_first( dap_chain_datum_iter_t * a_datum_iter ); // Get the fisrt datum from dag
static dap_chain_datum_t* s_chain_callback_datum_iter_get_next( dap_chain_datum_iter_t * a_datum_iter ); // Get the next datum from dag



/**
 * @brief dap_chain_cs_dag_init
 * @return
 */
int dap_chain_cs_dag_init(void)
{
    dap_chain_class_add( "dag", dap_chain_cs_dag_new );

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
    pthread_rwlock_init(& PVT(l_dag)->events_treshold_rwlock,NULL);

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

    // Datum operations callbacks
    a_chain->callback_datum_iter_create = s_chain_callback_datum_iter_create; // Datum iterator create
    a_chain->callback_datum_iter_delete = s_chain_callback_datum_iter_delete; // Datum iterator delete
    a_chain->callback_datum_iter_get_first = s_chain_callback_datum_iter_get_first; // Get the fisrt datum from chain
    a_chain->callback_datum_iter_get_next = s_chain_callback_datum_iter_get_next; // Get the next datum from chain from the current one

    // Others
    a_chain->_inheritor = l_dag;

    l_dag->is_single_line = dap_config_get_item_bool_default(a_chain_cfg,"dag","is_single_line",false);
    if ( l_dag->is_single_line )
        log_it (L_NOTICE, "DAG chain initialized (single line)");
    else
        log_it (L_NOTICE, "DAG chain initialized (multichain)");

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
    pthread_rwlock_destroy(& PVT(l_dag)->events_treshold_rwlock);

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
static int s_chain_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_t * a_atom)
{
    int ret = s_chain_callback_atom_verify (a_chain, a_atom);
    if ( ret < 0 ){
        log_it(L_WARNING,"Wrong event, can't accept, verification returned %d",ret);
        return  -1;
    }
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG(a_chain);
    dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *) a_atom;

    ret = l_dag->callback_cs_input(l_dag,l_event);
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
    pthread_rwlock_t * l_events_rwlock =( ret==0 ? &PVT(l_dag)->events_rwlock : &PVT(l_dag)->events_treshold_rwlock );
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
 * @brief s_chain_callback_atom_verify Verify atomic element
 * @param a_chain
 * @param a_atom
 * @return
 */
static int s_chain_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_t *  a_atom)
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
 * @brief dap_chain_cs_dag_proc_treshold
 * @param a_dag
 */
void dap_chain_cs_dag_proc_treshold(dap_chain_cs_dag_t * a_dag)
{

}


/**
 * @brief s_chain_callback_atom_get_size Get size of atomic element
 * @param a_atom
 * @return
 */
static size_t s_chain_callback_atom_hdr_get_size(dap_chain_atom_t * a_atom)
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
    return NULL; // TODO
}

/**
 * @brief s_chain_callback_atom_iter_get_first Get the first dag event
 * @param a_atom_iter
 * @return
 */
static dap_chain_atom_t* s_chain_callback_atom_iter_get_first(dap_chain_atom_iter_t * a_atom_iter )
{
    return NULL; // TODO
}

/**
 * @brief s_chain_callback_atom_iter_get_next Get the next dag event
 * @param a_atom_iter
 * @return
 */
static dap_chain_atom_t* s_chain_callback_atom_iter_get_next( dap_chain_atom_iter_t * a_atom_iter )
{
    return NULL; // TODO
}

/**
 * @brief s_chain_callback_atom_iter_delete Delete dag event iterator
 * @param a_atom_iter
 */
static void s_chain_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter )
{
    // TODO
}



/**
 * @brief s_chain_callback_datum_iter_create Create datum iterator
 * @param a_chain
 * @return
 */
static dap_chain_datum_iter_t* s_chain_callback_datum_iter_create(dap_chain_t * a_chain )
{
    return NULL; // TODO
}

/**
 * @brief s_chain_callback_datum_iter_get_first Get the first datum
 * @param a_datum_iter
 * @return
 */
static dap_chain_datum_t* s_chain_callback_datum_iter_get_first(dap_chain_datum_iter_t * a_datum_iter )
{
    return NULL; // TODO
}

/**
 * @brief s_chain_callback_datum_iter_get_next Get the next dag event datum
 * @param a_datum_iter
 * @return
 */
static dap_chain_datum_t* s_chain_callback_datum_iter_get_next( dap_chain_datum_iter_t * a_datum_iter )
{
    return NULL; // TODO
}

/**
 * @brief s_chain_callback_datum_iter_delete Delete dag event datum iterator
 * @param a_datum_iter
 */
static void s_chain_callback_datum_iter_delete(dap_chain_datum_iter_t * a_datum_iter )
{
    // TODO
}


