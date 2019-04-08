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
#include <uthash.h>

#include "dap_common.h"
#include "dap_chain_cs_dag.h"

#define LOG_TAG "dap_chain_cs_dag"

typedef struct dap_chain_cs_dag_event_item {
    dap_chain_hash_fast_t hash;
    dap_chain_cs_dag_event_t *event;
    UT_hash_handle hh;
} dap_chain_cs_dag_event_item_t;

typedef struct dap_chain_cs_dag_pvt {
    dap_chain_cs_dag_event_item_t * events;
    dap_chain_cs_dag_event_item_t * events_round_new;
    dap_chain_cs_dag_event_item_t * events_round_prev_lasts;
} dap_chain_cs_dag_pvt_t;

#define PVT(a) ((dap_chain_cs_dag_pvt_t *) a->_pvt )

// Atomic element organization callbacks
static int s_chain_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_t *);// Accept new event in dag
static int s_chain_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_t *);// Verify new event in dag
static size_t s_chain_callback_atom_get_size(dap_chain_atom_t *);// Get dag event size
static size_t s_chain_callback_atom_get_static_hdr_size(dap_chain_t *);// Get dag event header size

static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create(dap_chain_t * a_chain ); // Get the fisrt event from dag
static dap_chain_atom_t* s_chain_callback_atom_iter_get_first( dap_chain_atom_iter_t * a_atom_iter ); // Get the fisrt event from dag
static dap_chain_atom_t* s_chain_callback_atom_iter_get_next( dap_chain_atom_iter_t * a_atom_iter ); // Get the next event from dag
static void s_chain_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter ); // Get the fisrt event from dag

// Datum ops

static dap_chain_datum_iter_t* s_chain_callback_datum_iter_create(dap_chain_t * a_chain );
static void s_chain_callback_datum_iter_delete(dap_chain_datum_iter_t * a_iter );
static dap_chain_datum_t* s_chain_callback_datum_iter_get_first( dap_chain_datum_iter_t * a_datum_iter ); // Get the fisrt datum from dag
static dap_chain_datum_t* s_chain_callback_datum_iter_get_next( dap_chain_datum_iter_t * a_datum_iter ); // Get the next datum from dag



/**
 * @brief dap_chain_cs_dag_init
 * @return
 */
int dap_chain_cs_dag_init()
{
    dap_chain_class_add( "dag", dap_chain_cs_dag_new );

    return 0;
}

/**
 * @brief dap_chain_cs_dag_deinit
 */
void dap_chain_cs_dag_deinit()
{

}

/**
 * @brief dap_chain_cs_dag_new
 * @param a_chain
 * @param a_chain_cfg
 */
void dap_chain_cs_dag_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg)
{
    dap_chain_cs_dag_t * l_chain_cs_dag = DAP_NEW_Z(dap_chain_cs_dag_t);
    l_chain_cs_dag->_pvt = DAP_NEW_Z(dap_chain_cs_dag_pvt_t);
    l_chain_cs_dag->chain = a_chain;

    a_chain->callback_delete = dap_chain_cs_dag_delete;

    // Atom element callbacks
    a_chain->callback_atom_add = s_chain_callback_atom_add ;  // Accept new element in chain
    a_chain->callback_atom_verify = s_chain_callback_atom_add ;  // Verify new element in chain
    a_chain->callback_atom_get_size = s_chain_callback_atom_get_size; // Get dag event size
    a_chain->callback_atom_get_static_hdr_size = s_chain_callback_atom_get_static_hdr_size; // Get dag event hdr size

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
    a_chain->_inheritor = l_chain_cs_dag;

    log_it (L_NOTICE, "DAG chain initialized");
}

/**
 * @brief dap_chain_cs_dag_delete
 * @param a_dag
 * @return
 */
void dap_chain_cs_dag_delete(dap_chain_t * a_chain)
{
    dap_chain_cs_dag_t * l_dag = DAP_CHAIN_CS_DAG ( a_chain );
    if(l_dag->callback_delete )
        l_dag->callback_delete(l_dag);
    if(l_dag->_inheritor)
        DAP_DELETE(l_dag->_inheritor);
    if(l_dag->_pvt)
        DAP_DELETE(l_dag->_pvt);
    DAP_DELETE(l_dag);
}

/**
 * @brief s_chain_callback_atom_add Accept new event in dag
 * @param a_chain DAG object
 * @param a_atom
 * @return 0 if verified and added well, otherwise if not
 */
static int s_chain_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_t * a_atom)
{
    return -1; // TODO
}


/**
 * @brief s_chain_callback_atom_verify Verify atomic element
 * @param a_chain
 * @param a_atom
 * @return
 */
static int s_chain_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_t *  a_atom)
{
    return -1; // TODO
}

/**
 * @brief s_chain_callback_atom_get_size Get size of atomic element
 * @param a_atom
 * @return
 */
static size_t s_chain_callback_atom_get_size(dap_chain_atom_t * a_atom)
{
    return dap_chain_cs_dag_event_calc_size( (dap_chain_cs_dag_event_t * ) a_atom);
}

/**
 * @brief s_chain_callback_atom_get_static_hdr_size
 * @param a_chain
 * @return
 */
static size_t s_chain_callback_atom_get_static_hdr_size(dap_chain_t * a_chain)
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
