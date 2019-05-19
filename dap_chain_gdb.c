/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvindap_chain_global_dbblockchain
 * Copyright  (c) 2019
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
#include <stdbool.h>
#include <pthread.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_config.h"
#include "dap_chain_ledger.h"
#include "dap_chain_global_db.h"
#include "dap_chain_net.h"
#include "dap_chain_cs.h"
#include "dap_chain_gdb.h"

#define LOG_TAG "dap_chain_gdb"

#define CONSENSUS_NAME "nochains-gdb"

typedef struct dap_chain_gdb_private
{
    bool celled;
    char *group_tx;
    char *group_ledger;

    pthread_rwlock_t events_rwlock;
} dap_chain_gdb_private_t;

#define GDB_INTERNAL(a) ( (dap_chain_gdb_private_t* ) (a) ? a->_internal : NULL )
#define DAP_CHAIN_GDB(a) ( (dap_chain_gdb_t *) (a)->_inheritor)

// Atomic element organization callbacks
static int s_chain_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t); //    Accept new event in gdb
static int s_chain_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_ptr_t); //    Verify new event in gdb
static size_t s_chain_callback_atom_hdr_get_size(dap_chain_atom_ptr_t); //    Get gdb event size
static size_t s_chain_callback_atom_get_static_hdr_size(void); //    Get gdb event header size

static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create(dap_chain_t * a_chain);
static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create_from(dap_chain_t * a_chain,
        dap_chain_atom_ptr_t a);

// Delete iterator
static void s_chain_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter); //    Get the fisrt event from gdb

static dap_chain_atom_ptr_t s_chain_callback_atom_iter_find_by_hash(dap_chain_atom_iter_t * a_atom_iter,
        dap_chain_hash_fast_t * a_atom_hash);

// Get event(s) from gdb
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_first(dap_chain_atom_iter_t * a_atom_iter); //    Get the fisrt event from gdb
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_next(dap_chain_atom_iter_t * a_atom_iter); //    Get the next event from gdb
static dap_chain_atom_ptr_t *s_chain_callback_atom_iter_get_links(dap_chain_atom_iter_t * a_atom_iter,
        size_t * a_links_size_ptr); //    Get list of linked events
static dap_chain_atom_ptr_t *s_chain_callback_atom_iter_get_lasts(dap_chain_atom_iter_t * a_atom_iter,
        size_t * a_lasts_size_ptr); //    Get list of linked events

static size_t s_chain_callback_datums_pool_proc(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums,
        size_t a_datums_size);

/**
 * Stub for consensus
 */
static int s_cs_callback_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg)
{
    dap_chain_gdb_new(a_chain, a_chain_cfg);
    return 0;
}

/**
 * @brief dap_chain_cs_gdb_init
 * @return
 */
int dap_chain_gdb_init(void)
{
    dap_chain_cs_add(CONSENSUS_NAME, s_cs_callback_new);
    dap_chain_class_add("gdb", dap_chain_gdb_new);

    log_it(L_NOTICE, "Initialized GDB chain items organization class");
    return 0;
}

/**
 * @brief dap_chain_gdb_new
 * @param a_chain
 * @param a_chain_cfg
 */
int dap_chain_gdb_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg)
{
    dap_chain_gdb_t *l_gdb = DAP_NEW_Z(dap_chain_gdb_t);
    dap_chain_gdb_private_t *l_gdb_priv = DAP_NEW_Z(dap_chain_gdb_private_t);
    l_gdb->chain = a_chain;
    l_gdb->_internal = (void*) l_gdb_priv;
    a_chain->_inheritor = l_gdb;

    pthread_rwlock_init(&l_gdb_priv->events_rwlock, NULL);
    l_gdb_priv->group_tx = dap_strdup(dap_config_get_item_str(a_chain_cfg, CONSENSUS_NAME, "group_tx"));
    l_gdb_priv->group_ledger = dap_strdup(dap_config_get_item_str(a_chain_cfg, CONSENSUS_NAME, "group_ledger"));

    a_chain->callback_delete = dap_chain_gdb_delete;
    //dap_chain_cs_dag_t * l_dag = DAP_NEW_Z(dap_chain_cs_dag_t);
    //l_dag->_pvt = DAP_NEW_Z(dap_chain_cs_dag_pvt_t);
    //l_dag->chain = a_chain;

    // Atom element callbacks
    a_chain->callback_atom_add = s_chain_callback_atom_add; // Accept new element in chain
    a_chain->callback_atom_verify = s_chain_callback_atom_verify; // Verify new element in chain
    a_chain->callback_atom_get_size = s_chain_callback_atom_hdr_get_size; // Get dag event size
    a_chain->callback_atom_get_hdr_static_size = s_chain_callback_atom_get_static_hdr_size; // Get dag event hdr size

    a_chain->callback_atom_iter_create = s_chain_callback_atom_iter_create;
    a_chain->callback_atom_iter_create_from = s_chain_callback_atom_iter_create_from;
    a_chain->callback_atom_iter_delete = s_chain_callback_atom_iter_delete;

    a_chain->callback_atom_find_by_hash = s_chain_callback_atom_iter_find_by_hash;
    a_chain->callback_datums_pool_proc = s_chain_callback_datums_pool_proc;

    // Linear pass through
    a_chain->callback_atom_iter_get_first = s_chain_callback_atom_iter_get_first; // Get the fisrt element from chain
    a_chain->callback_atom_iter_get_next = s_chain_callback_atom_iter_get_next; // Get the next element from chain from the current one

    a_chain->callback_atom_iter_get_links = s_chain_callback_atom_iter_get_links; // Get the next element from chain from the current one
    a_chain->callback_atom_iter_get_lasts = s_chain_callback_atom_iter_get_lasts;

    return 0;
}

/**
 * @brief dap_chain_cs_gdb_delete
 * @param a_chain
 * @return
 */
void dap_chain_gdb_delete(dap_chain_t * a_chain)
{
    dap_chain_gdb_t * l_gdb = DAP_CHAIN_GDB(a_chain);
    dap_chain_gdb_private_t *l_gdb_priv = GDB_INTERNAL(l_gdb);

    pthread_rwlock_destroy(&l_gdb_priv->events_rwlock);
    DAP_DELETE(l_gdb_priv->group_tx);
    DAP_DELETE(l_gdb_priv->group_ledger);

    DAP_DELETE(l_gdb);
    a_chain->_inheritor = NULL;
}

static int compare_datum_items(const void * l_a, const void * l_b)
{
    dap_chain_datum_t *l_item_a = (dap_chain_datum_t*) l_a;
    dap_chain_datum_t *l_item_b = (dap_chain_datum_t*) l_b;
    if(l_item_a->header.ts_create == l_item_b->header.ts_create)
        return 0;
    if(l_item_a->header.ts_create < l_item_b->header.ts_create)
        return -1;
    return 1;
}

/**
 * Load ledger from mempool
 *
 * return 0 if OK otherwise  negative error code
 */
int dap_chain_gdb_ledger_load(dap_chain_gdb_t *l_gdb, dap_ledger_t *a_ledger, const char *a_net_name, const char *a_chain_name)
{
    // protect from reloading
    if(dap_chain_ledger_count(a_ledger) > 0)
        return 0;
    dap_chain_gdb_private_t *l_gdb_priv = GDB_INTERNAL(l_gdb);
    dap_list_t *l_datum_list = NULL, *l_list_tmp = NULL;

    // Read first transaction mempool group name
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    dap_chain_t * l_chain_base_tx = (l_net) ? dap_chain_net_get_chain_by_name(l_net, a_chain_name) : NULL;
    char * l_gdb_group_mempool_base_tx =
            (l_chain_base_tx) ? dap_chain_net_get_gdb_group_mempool(l_chain_base_tx) : NULL;

    // Read first transaction in mempool_groups from a_mempool_group_names_list
    size_t l_data_size = 0;
    dap_global_db_obj_t **data_ft = NULL;
    if(l_gdb_group_mempool_base_tx) {
        data_ft = dap_chain_global_db_gr_load(l_gdb_group_mempool_base_tx, &l_data_size);
        // make list of datums
        for(size_t i = 0; i < l_data_size; i++) {
            l_datum_list = dap_list_prepend(l_datum_list, data_ft[i]->value);
        }
    }

    //  Read the entire database into an array of size bytes
    dap_global_db_obj_t **data = dap_chain_global_db_gr_load(l_gdb_priv->group_ledger, &l_data_size);
    // make list of datums
    for(size_t i = 0; i < l_data_size; i++) {
        l_datum_list = dap_list_prepend(l_datum_list, data[i]->value);
    }
    // sort list by time
    l_datum_list = dap_list_sort(l_datum_list, (dap_callback_compare_t) compare_datum_items);
    l_list_tmp = l_datum_list;
    // add datum_tx from list to ledger
    while(l_list_tmp) {
        dap_chain_datum_t *l_datum = (dap_chain_datum_t*) l_list_tmp->data;
        if(l_datum->header.type_id == DAP_CHAIN_DATUM_TX) {
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*) l_datum->data;
            if(dap_chain_datum_tx_get_size(l_tx) == l_datum->header.data_size)
                dap_chain_ledger_tx_add(a_ledger,l_tx);
        }
        l_list_tmp = dap_list_next(l_list_tmp);
    }
    dap_chain_global_db_objs_delete(data);
    dap_list_free(l_datum_list);
    return 0;
}


/**
 * @brief s_chain_callback_datums_add
 * @param a_chain
 * @param a_datums
 * @param a_datums_size
 */
static int s_chain_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t a_atom)
{
    return 0;
}

/**
 * @brief s_chain_callback_atom_verify Verify atomic element
 * @param a_chain
 * @param a_atom
 * @return
 */
static int s_chain_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_ptr_t a_atom)
{
    return 0;
}

/**
 * @brief s_chain_callback_atom_get_size Get size of atomic element
 * @param a_atom
 * @return
 */
static size_t s_chain_callback_atom_hdr_get_size(dap_chain_atom_ptr_t a_atom)
{
    return 0;
}

/**
 * @brief s_chain_callback_atom_get_static_hdr_size
 * @param a_chain
 * @return
 */
static size_t s_chain_callback_atom_get_static_hdr_size()
{
    return 0;
}

/**
 * @brief s_chain_callback_atom_iter_create Create atomic element iterator
 * @param a_chain
 * @return
 */
static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create(dap_chain_t * a_chain)
{
    return 0;
}

/**
 * @brief s_chain_callback_atom_iter_create_from
 * @param a_chain
 * @param a_atom
 * @return
 */
static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create_from(dap_chain_t * a_chain,
        dap_chain_atom_ptr_t a_atom)
{
    return 0;
}

/**
 * @brief s_chain_callback_atom_iter_delete Delete dag event iterator
 * @param a_atom_iter
 */
static void s_chain_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter)
{
    DAP_DELETE(a_atom_iter);
}

/**
 * @brief s_chain_callback_atom_iter_find_by_hash
 * @param a_atom_iter
 * @param a_atom_hash
 * @return
 */
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_find_by_hash(dap_chain_atom_iter_t * a_atom_iter,
        dap_chain_hash_fast_t * a_atom_hash)
{
    return 0;
}

/**
 * @brief s_chain_callback_datums_add
 * @param a_chain
 * @param a_datums
 * @param a_datums_size
 */
static size_t s_chain_callback_datums_pool_proc(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums,
        size_t a_datums_count)
{
    return 0;
}

/**
 * @brief s_chain_callback_atom_iter_get_first Get the first dag event
 * @param a_atom_iter
 * @return
 */
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_first(dap_chain_atom_iter_t * a_atom_iter)
{
    return 0;
}
/**
 * @brief s_chain_callback_atom_iter_get_next Get the next dag event
 * @param a_atom_iter
 * @return
 */
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_next(dap_chain_atom_iter_t * a_atom_iter)
{
    return 0;
}

/**
 * @brief s_chain_callback_atom_iter_get_links
 * @param a_atom_iter
 * @param a_links_size_ptr
 * @return
 */
static dap_chain_atom_ptr_t* s_chain_callback_atom_iter_get_links(dap_chain_atom_iter_t * a_atom_iter,
        size_t * a_links_size_ptr)
{
    return 0;
}

/**
 * @brief s_chain_callback_atom_iter_get_lasts
 * @param a_atom_iter
 * @param a_lasts_size_ptr
 * @return
 */
static dap_chain_atom_ptr_t* s_chain_callback_atom_iter_get_lasts(dap_chain_atom_iter_t * a_atom_iter,
        size_t * a_lasts_size_ptr)
{
    return 0;
}

