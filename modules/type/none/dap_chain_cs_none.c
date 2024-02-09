/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvindap_global_dbblockchain
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
#include "utlist.h"

#include "dap_chain_net.h"
#include "dap_chain.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_config.h"
#include "dap_hash.h"
#include "dap_chain_cell.h"
#include "dap_chain_ledger.h"
#include "dap_global_db.h"
#include "dap_global_db_driver.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_none.h"

#define LOG_TAG "dap_chain_cs_none"

#define CONSENSUS_NAME "none"

typedef struct dap_nonconsensus_datum_hash_item {
    char key[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_t datum_data_hash;
    struct dap_nonconsensus_datum_hash_item *prev, *next;
} dap_nonconsensus_datum_hash_item_t;

typedef struct dap_nonconsensus_private {
    bool is_load_mode; // If load mode - not save when new atom adds
    char *group_datums;
    dap_chain_t *chain;
    pthread_cond_t load_cond;
    pthread_mutex_t load_mutex;
    dap_nonconsensus_datum_hash_item_t * hash_items;
} dap_nonconsensus_private_t;

#define PVT(a) ((a) ? (dap_nonconsensus_private_t *)(a)->_internal : NULL)

// Atomic element organization callbacks
static dap_chain_atom_verify_res_t s_nonconsensus_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t, size_t, dap_hash_fast_t *a_atom_hash); //    Accept new event in gdb
static dap_chain_atom_verify_res_t s_nonconsensus_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_ptr_t, size_t, dap_hash_fast_t *a_atom_hash); //    Verify new event in gdb
static size_t s_nonconsensus_callback_atom_get_static_hdr_size(void); //    Get gdb event header size

static dap_chain_atom_iter_t* s_nonconsensus_callback_atom_iter_create(dap_chain_t * a_chain, dap_chain_cell_id_t a_cell_id, bool a_with_treshold);
static dap_chain_atom_iter_t* s_nonconsensus_callback_atom_iter_create_from(dap_chain_t * a_chain,
        dap_chain_atom_ptr_t a, size_t a_atom_size);

// Delete iterator
static void s_nonconsensus_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter); //    Get the fisrt event from gdb

static dap_chain_atom_ptr_t s_nonconsensus_callback_atom_iter_find_by_hash(dap_chain_atom_iter_t * a_atom_iter,
        dap_chain_hash_fast_t * a_atom_hash, size_t * a_atom_size);

// Get event(s) from gdb
static dap_chain_atom_ptr_t s_nonconsensus_callback_atom_iter_get_first(dap_chain_atom_iter_t * a_atom_iter, size_t * a_atom_size); //    Get the fisrt event from gdb
static dap_chain_atom_ptr_t s_nonconsensus_callback_atom_iter_get_next(dap_chain_atom_iter_t * a_atom_iter, size_t * a_atom_size); //    Get the next event from gdb
static dap_chain_atom_ptr_t *s_nonconsensus_callback_atom_iter_get_links(dap_chain_atom_iter_t * a_atom_iter,
        size_t * a_links_size_ptr, size_t ** a_lasts_sizes_ptr); //    Get list of linked events
static dap_chain_atom_ptr_t *s_nonconsensus_callback_atom_iter_get_lasts(dap_chain_atom_iter_t * a_atom_iter,
        size_t * a_lasts_size_ptr, size_t ** a_lasts_sizes_ptr); //    Get list of linked events
static dap_chain_datum_t **s_nonconsensus_callback_atom_get_datum(dap_chain_atom_ptr_t a_atom, size_t a_atom_size, size_t *a_datums_count);
static dap_time_t s_nonconsensus_callback_atom_get_timestamp(dap_chain_atom_ptr_t a_atom) { return ((dap_chain_datum_t *)a_atom)->header.ts_create; }
static size_t s_nonconsensus_callback_datums_pool_proc(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums,
        size_t a_datums_size);
static void s_nonconsensus_ledger_load(dap_chain_t *a_chain);

// Datum ops
static dap_chain_datum_iter_t *s_nonconsensus_callback_datum_iter_create(dap_chain_t *a_chain);
static void s_nonconsensus_callback_datum_iter_delete(dap_chain_datum_iter_t *a_datum_iter);
static dap_chain_datum_t *s_nonconsensus_callback_datum_iter_get_first(dap_chain_datum_iter_t *a_datum_iter);
static dap_chain_datum_t *s_nonconsensus_callback_datum_iter_get_next(dap_chain_datum_iter_t *a_datum_iter);
static dap_chain_datum_t *s_nonconsensus_callback_datum_find_by_hash(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_datum_hash,
                                                                   dap_chain_hash_fast_t *a_atom_hash, int *a_ret_code);

static int s_cs_callback_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg);
static void s_nonconsensus_delete(dap_chain_t *a_chain);

/**
 * @brief dap_chain_cs_gdb_init
 * Initialize GDB chain items organization class
 * @return
 */
int dap_nonconsensus_init(void)
{
    dap_chain_cs_add(CONSENSUS_NAME, s_cs_callback_new); // It's a type and CS itself
    log_it(L_NOTICE, "Initialized GDB chain items organization class");
    return 0;
}

/**
 * @brief set PVT(DAP_NONCONSENSUS(a_chain))->is_load_mode = true
 *
 * @param a_chain dap_chain_t object
 */
static void s_nonconsensus_callback_purge(dap_chain_t *a_chain)
{
    PVT(DAP_NONCONSENSUS(a_chain))->is_load_mode = true;
}


static void s_nonconsensus_callback_mempool_notify(dap_store_obj_t *a_obj, void *a_arg)
{
    if (a_obj->type == DAP_GLOBAL_DB_OPTYPE_ADD)
        dap_chain_node_mempool_process_all(a_arg, false);
}

static void s_changes_callback_notify(dap_store_obj_t *a_obj, void *a_arg)
{
    dap_return_if_fail(a_obj->type == DAP_GLOBAL_DB_OPTYPE_ADD && a_obj->value_len && a_obj->value);
    dap_chain_t *l_chain = a_arg;
    if (a_obj->type == DAP_GLOBAL_DB_OPTYPE_DEL)
        return;
    dap_hash_fast_t l_hash = {};
    dap_hash_fast(a_obj->value, a_obj->value_len, &l_hash);
    s_nonconsensus_callback_atom_add(l_chain, (dap_chain_datum_t *)a_obj->value, a_obj->value_len, &l_hash);
}

/**
 * @brief configure chain gdb
 * Set atom element callbacks
 * @param a_chain dap_chain_t chain object
 * @param a_chain_cfg dap_config_t config object
 * @return int
 */
static int s_cs_callback_new(dap_chain_t *a_chain, dap_config_t UNUSED_ARG *a_chain_cfg)
{
    dap_nonconsensus_t *l_nochain = DAP_NEW_Z(dap_nonconsensus_t);
    if (!l_nochain) {
        log_it(L_CRITICAL, "Memory allocation error");
        return -1;
    }
    dap_nonconsensus_private_t *l_nochain_priv = DAP_NEW_Z(dap_nonconsensus_private_t);
    if (!l_nochain_priv) {
        log_it(L_CRITICAL, "Memory allocation error");
        DAP_DELETE(l_nochain);
        return -2;
    }
    l_nochain->chain = a_chain;
    l_nochain->_internal = (void*) l_nochain_priv;
    a_chain->_inheritor = l_nochain;

    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    l_nochain_priv->chain = a_chain;

    l_nochain_priv->group_datums = dap_chain_net_get_gdb_group_nochain_new(a_chain);
    // Add group prefix that will be tracking all changes
    dap_global_db_cluster_t *l_nonconsensus_cluster =
            dap_global_db_cluster_add(dap_global_db_instance_get_default(), l_net->pub.name,
                                      l_nochain_priv->group_datums, 0, true,
                                      DAP_GDB_MEMBER_ROLE_USER, DAP_CLUSTER_ROLE_EMBEDDED);
    if (!l_nonconsensus_cluster) {
        log_it(L_ERROR, "Can't create global DB cluster for synchronization");
        return -3;
    }
    dap_global_db_cluster_add_notify_callback(l_nonconsensus_cluster, s_changes_callback_notify, a_chain);
    dap_chain_add_mempool_notify_callback(a_chain, s_nonconsensus_callback_mempool_notify, a_chain);

    pthread_cond_init(&l_nochain_priv->load_cond, NULL);
    pthread_mutex_init(&l_nochain_priv->load_mutex, NULL);

    a_chain->callback_delete = s_nonconsensus_delete;
    a_chain->callback_purge = s_nonconsensus_callback_purge;

    // Atom element callbacks
    a_chain->callback_atom_add = s_nonconsensus_callback_atom_add; // Accept new element in chain
    a_chain->callback_atom_verify = s_nonconsensus_callback_atom_verify; // Verify new element in chain
    a_chain->callback_atom_get_hdr_static_size = s_nonconsensus_callback_atom_get_static_hdr_size; // Get dag event hdr size

    a_chain->callback_atom_iter_create = s_nonconsensus_callback_atom_iter_create;
    a_chain->callback_atom_iter_create_from = s_nonconsensus_callback_atom_iter_create_from;
    a_chain->callback_atom_iter_delete = s_nonconsensus_callback_atom_iter_delete;
    // Linear pass through
    a_chain->callback_atom_iter_get_first = s_nonconsensus_callback_atom_iter_get_first; // Get the fisrt element from chain
    a_chain->callback_atom_iter_get_next = s_nonconsensus_callback_atom_iter_get_next; // Get the next element from chain from the current one
    a_chain->callback_atom_find_by_hash = s_nonconsensus_callback_atom_iter_find_by_hash;

    a_chain->callback_atom_iter_get_links = s_nonconsensus_callback_atom_iter_get_links; // Get the next element from chain from the current one
    a_chain->callback_atom_iter_get_lasts = s_nonconsensus_callback_atom_iter_get_lasts;
    a_chain->callback_atom_get_datums = s_nonconsensus_callback_atom_get_datum;
    a_chain->callback_atom_get_timestamp = s_nonconsensus_callback_atom_get_timestamp;

    // Datum callbacks
    a_chain->callback_datum_iter_create = s_nonconsensus_callback_datum_iter_create;
    a_chain->callback_datum_iter_delete = s_nonconsensus_callback_datum_iter_delete;
    // Linear pass through
    a_chain->callback_datum_iter_get_first = s_nonconsensus_callback_datum_iter_get_first; // Get the fisrt datum from chain
    a_chain->callback_datum_iter_get_next = s_nonconsensus_callback_datum_iter_get_next; // Get the next datum from chain from the current one

    a_chain->callback_datum_find_by_hash = s_nonconsensus_callback_datum_find_by_hash;
    a_chain->callback_add_datums = s_nonconsensus_callback_datums_pool_proc;

    a_chain->callback_load_from_gdb = s_nonconsensus_ledger_load;

    return 0;
}

/**
 * @brief clear dap_nonconsensus_t object
 *
 * @param a_chain dap_chain_t chain object
 */
static void s_nonconsensus_delete(dap_chain_t *a_chain)
{
    dap_nonconsensus_t * l_nochain = DAP_NONCONSENSUS(a_chain);
    dap_nonconsensus_private_t *l_nochain_priv = PVT(l_nochain);

    DAP_DELETE(l_nochain_priv->group_datums);

    DAP_DELETE(l_nochain);
    if (a_chain)
        a_chain->_inheritor = NULL;
}

/**
 * @brief get group name for ledger
 *
 * @param a_chain dap_chain_t * chain object
 * @return const char*
 */
const char* dap_nonconsensus_get_group(dap_chain_t * a_chain)
{
    if(!a_chain)
        return NULL;
    dap_nonconsensus_t * l_nochain = DAP_NONCONSENSUS(a_chain);
    dap_nonconsensus_private_t *l_nochain_priv = PVT(l_nochain);
    return l_nochain_priv->group_datums;
}


/**
 * @brief compare_datum_items
 * @param l_a
 * @param l_b
 * @return
 */

/*static int compare_datum_items(const void * l_a, const void * l_b)
{
    const dap_chain_datum_t *l_item_a = (const dap_chain_datum_t*) l_a;
    const dap_chain_datum_t *l_item_b = (const dap_chain_datum_t*) l_b;
    if(l_item_a->header.ts_create == l_item_b->header.ts_create)
        return 0;
    if(l_item_a->header.ts_create < l_item_b->header.ts_create)
        return -1;
    return 1;
}*/

/**
 * @brief s_ledger_load_callback
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
static bool s_ledger_load_callback(UNUSED_ARG dap_global_db_instance_t *a_dbi,
                                   UNUSED_ARG int a_rc, UNUSED_ARG const char *a_group,
                                   UNUSED_ARG const size_t a_values_total, const size_t a_values_count,
                                   dap_global_db_obj_t *a_values, void *a_arg)
{
    assert(a_arg);
    dap_chain_t * l_chain = (dap_chain_t *) a_arg;
    assert(l_chain);
    dap_nonconsensus_t * l_nochain = DAP_NONCONSENSUS(l_chain);
    assert(l_nochain);
    dap_nonconsensus_private_t * l_nochain_pvt = PVT(l_nochain);
    assert(l_nochain_pvt);
    // make list of datums
    for(size_t i = 0; i < a_values_count; i++) {
        dap_global_db_obj_t *it = a_values + i;
        dap_hash_fast_t l_hash = {};
        dap_hash_fast(it->value, it->value_len, &l_hash);
        s_nonconsensus_callback_atom_add(l_chain, it->value, it->value_len, &l_hash);
        log_it(L_DEBUG,"Load mode, doesn't save item %s:%s", it->key, l_nochain_pvt->group_datums);
    }

    pthread_mutex_lock(&l_nochain_pvt->load_mutex);
    l_nochain_pvt->is_load_mode = false;
    pthread_cond_broadcast(&l_nochain_pvt->load_cond);
    pthread_mutex_unlock(&l_nochain_pvt->load_mutex);
    return true;
}

/**
 * @brief Load ledger from mempool
 *
 * @param a_gdb_group a_gdb_group char gdb group name
 * @param a_chain chain dap_chain_t object
 * @return int return 0 if OK otherwise  negative error code
 */
static void s_nonconsensus_ledger_load(dap_chain_t *a_chain)
{
    dap_nonconsensus_t * l_nochain = DAP_NONCONSENSUS(a_chain);
    dap_nonconsensus_private_t * l_nochain_pvt = PVT(l_nochain);
    // load ledger
    l_nochain_pvt->is_load_mode = true;
    //  Read the entire database into an array of size bytes
    pthread_mutex_lock(&l_nochain_pvt->load_mutex);
    dap_global_db_get_all(l_nochain_pvt->group_datums, 0, s_ledger_load_callback, a_chain);
    while (l_nochain_pvt->is_load_mode)
        pthread_cond_wait(&l_nochain_pvt->load_cond, &l_nochain_pvt->load_mutex);
    pthread_mutex_unlock(&l_nochain_pvt->load_mutex);
}

/**
 * @brief call s_nonconsensus_callback_atom_add for every dap_chain_datum_t objects in a_datums array
 *
 * @param a_chain dap_chain_t chain object (f.e. plasma)
 * @param a_datums dap_chain_datum array with dap_chain_datum objects
 * @param a_datums_count object counts in datums array
 * @return size_t
 */
static size_t s_nonconsensus_callback_datums_pool_proc(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums, size_t a_datums_count)
{
    for(size_t i = 0; i < a_datums_count; i++) {
        dap_chain_datum_t *l_datum = a_datums[i];
        dap_hash_fast_t l_datum_hash;
        char l_db_key[DAP_CHAIN_HASH_FAST_STR_SIZE];
        dap_hash_fast(l_datum->data, l_datum->header.data_size, &l_datum_hash);
        dap_chain_hash_fast_to_str(&l_datum_hash, l_db_key, sizeof(l_db_key));
        int l_rc = dap_chain_net_verify_datum_for_add(a_chain, l_datum, &l_datum_hash);
        if (l_rc != 0) {
            log_it(L_ERROR, "Verified datum %s not passed the check, code %d", l_db_key, l_rc);
            return i;
        }
        dap_global_db_set(PVT(DAP_NONCONSENSUS(a_chain))->group_datums, l_db_key, l_datum,
                          dap_chain_datum_size(l_datum), false, NULL, NULL);
    }
    return a_datums_count;
}

/**
 * @brief add atom to DB
 *
 * @param a_chain chaon object
 * @param a_atom pointer to atom
 * @param a_atom_size atom size
 * @return dap_chain_atom_verify_res_t
 */
static dap_chain_atom_verify_res_t s_nonconsensus_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t a_atom, size_t a_atom_size, dap_hash_fast_t *a_atom_hash)
{
    if (NULL == a_chain) {
        log_it(L_WARNING, "Arguments is NULL for s_nonconsensus_callback_atom_add");
        return ATOM_REJECT;
    }
    dap_nonconsensus_t * l_nochain = DAP_NONCONSENSUS(a_chain);
    dap_nonconsensus_private_t *l_nochain_priv = PVT(l_nochain);
    dap_chain_datum_t *l_datum = (dap_chain_datum_t*) a_atom;
    dap_hash_fast_t l_datum_hash = *a_atom_hash;
    if(dap_chain_datum_add(a_chain, l_datum, a_atom_size, &l_datum_hash))
        return ATOM_REJECT;

    dap_nonconsensus_datum_hash_item_t * l_hash_item = DAP_NEW_Z(dap_nonconsensus_datum_hash_item_t);
    if (!l_hash_item) {
        log_it(L_CRITICAL, "Memory allocation error");
        return ATOM_REJECT;
    }
    size_t l_datum_size = dap_chain_datum_size(l_datum);
    l_hash_item->datum_data_hash = l_datum_hash;
    dap_chain_hash_fast_to_str(&l_hash_item->datum_data_hash, l_hash_item->key, sizeof(l_hash_item->key));
    DL_APPEND(l_nochain_priv->hash_items, l_hash_item);
    if (!l_nochain_priv->is_load_mode && a_chain->atom_notifiers) {
        dap_list_t *l_iter;
        DL_FOREACH(a_chain->atom_notifiers, l_iter) {
            dap_chain_atom_notifier_t *l_notifier = (dap_chain_atom_notifier_t*)l_iter->data;
            l_notifier->callback(l_notifier->arg, a_chain, (dap_chain_cell_id_t){ }, (void*)l_datum, l_datum_size);
        }
    }
    return ATOM_ACCEPT;
}


/**
 * @brief Verify atomic element (currently simply return ATOM_ACCEPT)
 *
 * @param a_chain chain object
 * @param a_atom pointer to atom
 * @param a_atom_size size of atom
 * @return dap_chain_atom_verify_res_t
 */
static dap_chain_atom_verify_res_t s_nonconsensus_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_ptr_t a_atom, size_t a_atom_size, dap_hash_fast_t *a_atom_hash)
{
    (void) a_chain;
    (void) a_atom;
    (void) a_atom_size;
    return ATOM_ACCEPT;
}


/**
 * @brief return size of dap_chain_datum_t l_datum_null->header
 *
 * @return size_t
 */
static size_t s_nonconsensus_callback_atom_get_static_hdr_size()
{
    static dap_chain_datum_t *l_datum_null=NULL;
    return sizeof(l_datum_null->header);
}


/**
 * @brief Create atomic element iterator
 *
 * @param a_chain dap_chain_t a_chain
 * @return dap_chain_atom_iter_t*
 */
static dap_chain_atom_iter_t* s_nonconsensus_callback_atom_iter_create(dap_chain_t * a_chain, dap_chain_cell_id_t a_cell_id, bool a_with_treshold)
{
    dap_chain_atom_iter_t * l_iter = DAP_NEW_Z(dap_chain_atom_iter_t);
    if (!l_iter) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    l_iter->chain = a_chain;
    l_iter->cell_id = a_cell_id;
    l_iter->with_treshold = a_with_treshold;
    return l_iter;
}

/**
 * @brief create atom object (dap_chain_atom_iter_t)
 *
 * @param a_chain chain object
 * @param a_atom pointer to atom
 * @param a_atom_size size of atom
 * @return dap_chain_atom_iter_t*
 */
static dap_chain_atom_iter_t* s_nonconsensus_callback_atom_iter_create_from(dap_chain_t * a_chain,
        dap_chain_atom_ptr_t a_atom, size_t a_atom_size)
{
    dap_chain_atom_iter_t * l_iter = DAP_NEW_Z(dap_chain_atom_iter_t);
    if (!l_iter) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    l_iter->chain = a_chain;
    l_iter->cur = a_atom;
    l_iter->cur_size = a_atom_size;
    dap_hash_fast(a_atom, a_atom_size, l_iter->cur_hash);
    return l_iter;
}


/**
 * @brief Delete dag event iterator
 * execute DAP_DELETE(a_atom_iter)
 * @param a_atom_iter dap_chain_atom_iter_t object
 */
static void s_nonconsensus_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter)
{
    DAP_DEL_Z(a_atom_iter->cur_item);
    DAP_DEL_Z(a_atom_iter->cur_hash);
    DAP_DELETE(a_atom_iter);
}


/**
 * @brief get dap_chain_atom_ptr_t object form database by hash
 * @details Searchs by datum data hash, not for datum's hash itself
 * @param a_atom_iter dap_chain_atom_iter_t atom object
 * @param a_atom_hash dap_chain_hash_fast_t atom hash
 * @param a_atom_size size of atom object
 * @return dap_chain_atom_ptr_t
 */
static dap_chain_atom_ptr_t s_nonconsensus_callback_atom_iter_find_by_hash(dap_chain_atom_iter_t * a_atom_iter,
        dap_chain_hash_fast_t * a_atom_hash, size_t *a_atom_size)
{
    char l_key[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(a_atom_hash, l_key, sizeof(l_key));
    size_t l_ret_size;
    dap_chain_atom_ptr_t l_ret = NULL;
    dap_nonconsensus_t *l_nochain = DAP_NONCONSENSUS(a_atom_iter->chain);
    if (l_nochain) {
        l_ret = dap_global_db_get_sync(PVT(l_nochain)->group_datums, l_key, &l_ret_size, NULL, NULL);
        *a_atom_size = l_ret_size;
    }
    return l_ret;
}

/**
 * @brief Get the first dag event from database
 *
 * @param a_atom_iter ap_chain_atom_iter_t object
 * @param a_atom_size a_atom_size atom size
 * @return dap_chain_atom_ptr_t
 */
static dap_chain_atom_ptr_t s_nonconsensus_callback_atom_iter_get_first(dap_chain_atom_iter_t * a_atom_iter, size_t *a_atom_size)
{
    if (!a_atom_iter)
        return NULL;
    if (a_atom_iter->cur_item) { /* Iterator creates copies, free them at delete routine! */
        DAP_DEL_Z(a_atom_iter->cur);
        DAP_DEL_Z(a_atom_iter->cur_hash);
    }
    dap_chain_datum_t * l_datum = NULL;
    dap_nonconsensus_datum_hash_item_t *l_item = PVT(DAP_NONCONSENSUS(a_atom_iter->chain))->hash_items;
    a_atom_iter->cur_item = l_item;
    if (a_atom_iter->cur_item) {
        size_t l_datum_size = 0;
        l_datum = (dap_chain_datum_t*)dap_global_db_get_sync(PVT(DAP_NONCONSENSUS(a_atom_iter->chain))->group_datums,
                                                             l_item->key, &l_datum_size, NULL, NULL);
        a_atom_iter->cur = l_datum;
        a_atom_iter->cur_size = l_datum_size;
        a_atom_iter->cur_hash = DAP_NEW_Z(dap_hash_fast_t);
        dap_chain_hash_fast_from_str(l_item->key, a_atom_iter->cur_hash);
        if (a_atom_size)
            *a_atom_size = l_datum_size;
    } else {
        a_atom_iter->cur_size = 0;
        if (a_atom_size)
            *a_atom_size = 0;
    }
    return l_datum;
}


/**
 * @brief Get the next dag event from database
 *
 * @param a_atom_iter dap_chain_atom_iter_t
 * @param a_atom_size size_t a_atom_size
 * @return dap_chain_atom_ptr_t
 */
static dap_chain_atom_ptr_t s_nonconsensus_callback_atom_iter_get_next(dap_chain_atom_iter_t *a_atom_iter, size_t *a_atom_size)
{
    dap_chain_datum_t * l_datum = NULL;
    dap_nonconsensus_datum_hash_item_t *l_item = (dap_nonconsensus_datum_hash_item_t*)a_atom_iter->cur_item;
    if (l_item)
        l_item = l_item->next;
    a_atom_iter->cur_item = l_item;
    if (a_atom_iter->cur_item ){
        size_t l_datum_size =0;
        l_datum = (dap_chain_datum_t *)dap_global_db_get_sync(PVT(DAP_NONCONSENSUS(a_atom_iter->chain))->group_datums, l_item->key, &l_datum_size, NULL, NULL);
        if (a_atom_iter->cur) // This iterator should clean up data for it because its allocate it
            DAP_DELETE(a_atom_iter->cur);
        a_atom_iter->cur = l_datum;
        a_atom_iter->cur_size = l_datum_size;
        dap_chain_hash_fast_from_str(l_item->key, a_atom_iter->cur_hash);
        if (a_atom_size)
            *a_atom_size = l_datum_size;
    } else {
        DAP_DEL_Z(a_atom_iter->cur_hash);
        DAP_DEL_Z(a_atom_iter->cur);
        a_atom_iter->cur_size = 0;
        if (a_atom_size)
            *a_atom_size = 0;
    }
    return l_datum;
}

/**
 * @brief return null in current implementation
 *
 * @param a_atom_iter
 * @param a_links_size_ptr
 * @param a_links_sizes_ptr
 * @return dap_chain_atom_ptr_t*
 */
static dap_chain_atom_ptr_t* s_nonconsensus_callback_atom_iter_get_links(dap_chain_atom_iter_t * a_atom_iter,
        size_t * a_links_size_ptr, size_t **a_links_sizes_ptr)
{
    (void) a_atom_iter;
    (void) a_links_size_ptr;
    (void) a_links_sizes_ptr;
    return NULL;
}

/**
 * @brief return null in current implementation
 *
 * @param a_atom_iter
 * @param a_lasts_size_ptr
 * @param a_links_sizes_ptr
 * @return dap_chain_atom_ptr_t*
 */
static dap_chain_atom_ptr_t* s_nonconsensus_callback_atom_iter_get_lasts(dap_chain_atom_iter_t * a_atom_iter,
        size_t * a_lasts_size_ptr,  size_t **a_links_sizes_ptr)
{
    (void) a_atom_iter;
    (void) a_lasts_size_ptr;
    (void) a_links_sizes_ptr;
    return NULL;
}

/**
 * @brief get new datum object from atom
 *
 * @param a_atom atom object
 * @param a_atom_size atom size
 * @param a_datums_count count of datums
 * @return dap_chain_datum_t**
 */
static dap_chain_datum_t **s_nonconsensus_callback_atom_get_datum(dap_chain_atom_ptr_t a_atom, size_t a_atom_size, size_t *a_datums_count)
{
    UNUSED(a_atom_size);
    if (a_atom){
        dap_chain_datum_t *l_datum = (dap_chain_datum_t *)a_atom;
        if (l_datum){
            dap_chain_datum_t **l_datums = DAP_NEW(dap_chain_datum_t *);
            if (!l_datums) {
                log_it(L_CRITICAL, "Memory allocation error");
                return NULL;
            }
            if (a_datums_count)
                *a_datums_count = 1;
            l_datums[0] = l_datum;
            return l_datums;
        }else
            return NULL;
    }else
        return NULL;
}

static dap_chain_datum_iter_t *s_nonconsensus_callback_datum_iter_create(dap_chain_t *a_chain)
{
    dap_chain_datum_iter_t *l_ret = DAP_NEW_Z(dap_chain_datum_iter_t);
    if (!l_ret) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    l_ret->chain = a_chain;
    return l_ret;
}

static void s_nonconsensus_callback_datum_iter_delete(dap_chain_datum_iter_t *a_datum_iter)
{
    if (a_datum_iter->cur_item) {
        DAP_DEL_Z(a_datum_iter->cur);
        DAP_DEL_Z(a_datum_iter->cur_hash);
    }
    DAP_DELETE(a_datum_iter);
}

static dap_chain_datum_t *s_nonconsensus_callback_datum_iter_get_first(dap_chain_datum_iter_t *a_datum_iter)
{
    if (!a_datum_iter)
        return NULL;
    if (a_datum_iter->cur_item) { /* Iterator creates copies, free them at delete routine! */
        DAP_DEL_Z(a_datum_iter->cur);
        DAP_DEL_Z(a_datum_iter->cur_hash);
    }
    dap_chain_datum_t * l_datum = NULL;
    dap_nonconsensus_datum_hash_item_t *l_item = PVT(DAP_NONCONSENSUS(a_datum_iter->chain))->hash_items;
    a_datum_iter->cur_item = l_item;
    if (a_datum_iter->cur_item) {
        size_t l_datum_size = 0;
        l_datum = (dap_chain_datum_t*)dap_global_db_get_sync(PVT(DAP_NONCONSENSUS(a_datum_iter->chain))->group_datums,
                                                             l_item->key, &l_datum_size, NULL, NULL);
        a_datum_iter->cur = l_datum;
        a_datum_iter->cur_size = l_datum_size;
        a_datum_iter->cur_hash = DAP_NEW_Z(dap_hash_fast_t);
        dap_chain_hash_fast_from_str(l_item->key, a_datum_iter->cur_hash);
        a_datum_iter->cur_atom_hash = a_datum_iter->cur_hash;
    } else
        a_datum_iter->cur_size = 0;
    return l_datum;
}

static dap_chain_datum_t *s_nonconsensus_callback_datum_iter_get_next(dap_chain_datum_iter_t *a_datum_iter)
{
    if (!a_datum_iter)
        return NULL;
    dap_chain_datum_t *l_datum = NULL;
    dap_nonconsensus_datum_hash_item_t *l_item = (dap_nonconsensus_datum_hash_item_t*)a_datum_iter->cur_item;
    if (l_item)
        l_item = l_item->next;
    a_datum_iter->cur_item = l_item;
    if (a_datum_iter->cur_item) {
        size_t l_datum_size = 0;
        l_datum = (dap_chain_datum_t*)dap_global_db_get_sync(PVT(DAP_NONCONSENSUS(a_datum_iter->chain))->group_datums,
                                                             l_item->key, &l_datum_size, NULL, NULL);
        DAP_DEL_Z(a_datum_iter->cur);
        a_datum_iter->cur = l_datum;
        a_datum_iter->cur_size = l_datum_size;
        a_datum_iter->cur_hash = DAP_NEW_Z(dap_hash_fast_t);
        dap_chain_hash_fast_from_str(l_item->key, a_datum_iter->cur_hash);
        a_datum_iter->cur_atom_hash = a_datum_iter->cur_hash;
    } else {
        DAP_DEL_Z(a_datum_iter->cur_hash);
        DAP_DEL_Z(a_datum_iter->cur);
        a_datum_iter->cur_size = 0;
    }
    return l_datum;
}

static dap_chain_datum_t *s_nonconsensus_callback_datum_find_by_hash(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_datum_hash,
                                                                   dap_chain_hash_fast_t *a_atom_hash, int *a_ret_code)
{
    dap_nonconsensus_datum_hash_item_t *l_item;
    DL_FOREACH(PVT(DAP_NONCONSENSUS(a_chain))->hash_items, l_item) {
        if (dap_hash_fast_compare(a_datum_hash, &l_item->datum_data_hash)) {
            if (a_atom_hash)
                *a_atom_hash = l_item->datum_data_hash;
            if (a_ret_code)
                *a_ret_code = 0;
            size_t l_datum_size = 0;
            // Memory leak here until assumed allocated memory returned in other data storage types
            return (dap_chain_datum_t *)dap_global_db_get_sync(PVT(DAP_NONCONSENSUS(a_chain))->group_datums,
                                                                 l_item->key, &l_datum_size, NULL, NULL);
        }
    }
    return NULL;
}
