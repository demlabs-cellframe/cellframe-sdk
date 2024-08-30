/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvindap_global_dbblockchain
 * Copyright  (c) 2019
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
    dap_nonconsensus_datum_hash_item_t * hash_items;
} dap_nonconsensus_private_t;

#define PVT(a) ((a) ? (dap_nonconsensus_private_t *)(a)->_internal : NULL)

// Atomic element organization callbacks
static dap_chain_atom_verify_res_t s_nonconsensus_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t, size_t, dap_hash_fast_t *a_atom_hash, bool a_atom_new); //    Accept new event in gdb
static dap_chain_atom_verify_res_t s_nonconsensus_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_ptr_t, size_t, dap_hash_fast_t *a_atom_hash); //    Verify new event in gdb
static size_t s_nonconsensus_callback_atom_get_static_hdr_size(void); //    Get gdb event header size

static dap_chain_atom_iter_t* s_nonconsensus_callback_atom_iter_create(dap_chain_t * a_chain, dap_chain_cell_id_t a_cell_id, dap_hash_fast_t *a_hash_from);

// Delete iterator
static void s_nonconsensus_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter); //    Get the fisrt event from gdb

static dap_chain_atom_ptr_t s_nonconsensus_callback_atom_iter_find_by_hash(dap_chain_atom_iter_t * a_atom_iter,
        dap_chain_hash_fast_t * a_atom_hash, size_t * a_atom_size);

// Get event(s) from gdb
static dap_chain_atom_ptr_t s_nonconsensus_callback_atom_iter_get(dap_chain_atom_iter_t *a_atom_iter, dap_chain_iter_op_t a_operation, size_t *a_atom_size);
static dap_chain_atom_ptr_t *s_nonconsensus_callback_atom_iter_get_links(dap_chain_atom_iter_t *a_atom_iter, size_t *a_links_size_ptr, size_t **a_lasts_sizes_ptr); //    Get list of linked events
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
static uint64_t s_nonconsensus_callback_get_count_atom(dap_chain_t *a_chain);
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
    if (dap_store_obj_get_type(a_obj) == DAP_GLOBAL_DB_OPTYPE_ADD)
        dap_chain_node_mempool_process_all(a_arg, false);
}

static void s_changes_callback_notify(dap_store_obj_t *a_obj, void *a_arg)
{
    dap_return_if_fail(a_obj->value_len && a_obj->value);
    dap_chain_t *l_chain = a_arg;
    if (dap_store_obj_get_type(a_obj) == DAP_GLOBAL_DB_OPTYPE_DEL)
        return;
    dap_hash_fast_t l_hash = {};
    dap_chain_hash_fast_from_hex_str(a_obj->key, &l_hash);
    s_nonconsensus_callback_atom_add(l_chain, (dap_chain_datum_t *)a_obj->value, a_obj->value_len, &l_hash, false);
}

int s_nonconsensus_callback_created(dap_chain_t *a_chain, dap_config_t UNUSED_ARG *a_chain_cfg)
{
    dap_chain_add_mempool_notify_callback(a_chain, s_nonconsensus_callback_mempool_notify, a_chain);
    return 0;
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
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -1;
    }
    dap_nonconsensus_private_t *l_nochain_priv = DAP_NEW_Z(dap_nonconsensus_private_t);
    if (!l_nochain_priv) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
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
            dap_global_db_cluster_add(dap_global_db_instance_get_default(),
                                      l_net->pub.name, dap_guuid_compose(l_net->pub.id.uint64, 0),
                                      l_nochain_priv->group_datums, 0,
                                      true, DAP_GDB_MEMBER_ROLE_USER, DAP_CLUSTER_TYPE_EMBEDDED);
    if (!l_nonconsensus_cluster) {
        log_it(L_ERROR, "Can't create global DB cluster for synchronization");
        return -3;
    }
    dap_global_db_cluster_add_notify_callback(l_nonconsensus_cluster, s_changes_callback_notify, a_chain);

    a_chain->callback_delete = s_nonconsensus_delete;
    a_chain->callback_purge = s_nonconsensus_callback_purge;

    // Atom element callbacks
    a_chain->callback_atom_add = s_nonconsensus_callback_atom_add; // Accept new element in chain
    a_chain->callback_atom_verify = s_nonconsensus_callback_atom_verify; // Verify new element in chain
    a_chain->callback_atom_get_hdr_static_size = s_nonconsensus_callback_atom_get_static_hdr_size; // Get dag event hdr size

    a_chain->callback_atom_iter_create = s_nonconsensus_callback_atom_iter_create;
    a_chain->callback_atom_iter_delete = s_nonconsensus_callback_atom_iter_delete;
    a_chain->callback_atom_iter_get = s_nonconsensus_callback_atom_iter_get; // Linear pass through
    a_chain->callback_atom_find_by_hash = s_nonconsensus_callback_atom_iter_find_by_hash;

    a_chain->callback_atom_iter_get_links = s_nonconsensus_callback_atom_iter_get_links; // Get the next element from chain from the current one

    a_chain->callback_atom_get_datums = s_nonconsensus_callback_atom_get_datum;
    a_chain->callback_atom_get_timestamp = s_nonconsensus_callback_atom_get_timestamp;
    // Get atom count in chain
    a_chain->callback_count_atom = s_nonconsensus_callback_get_count_atom;
    // Datum callbacks
    a_chain->callback_datum_iter_create = s_nonconsensus_callback_datum_iter_create;
    a_chain->callback_datum_iter_delete = s_nonconsensus_callback_datum_iter_delete;
    // Linear pass through
    a_chain->callback_datum_iter_get_first = s_nonconsensus_callback_datum_iter_get_first; // Get the fisrt datum from chain
    a_chain->callback_datum_iter_get_next = s_nonconsensus_callback_datum_iter_get_next; // Get the next datum from chain from the current one

    a_chain->callback_datum_find_by_hash = s_nonconsensus_callback_datum_find_by_hash;
    a_chain->callback_add_datums = s_nonconsensus_callback_datums_pool_proc;

    a_chain->callback_load_from_gdb = s_nonconsensus_ledger_load;
    a_chain->callback_created = s_nonconsensus_callback_created;

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
 * @brief Load ledger from mempool
 *
 * @param a_gdb_group a_gdb_group char gdb group name
 * @param a_chain chain dap_chain_t object
 * @return int return 0 if OK otherwise  negative error code
 */
static void s_nonconsensus_ledger_load(dap_chain_t *a_chain)
{
    dap_nonconsensus_t *l_nochain = DAP_NONCONSENSUS(a_chain);
    dap_nonconsensus_private_t *l_nochain_pvt = PVT(l_nochain);
    size_t l_values_count = 0;
    //  Read the entire database into an array of size bytes
    dap_global_db_obj_t *l_values = dap_global_db_get_all_sync(l_nochain_pvt->group_datums, &l_values_count);
    // make list of datums
    for (size_t i = 0; l_values && i < l_values_count; i++) {
        dap_global_db_obj_t *it = l_values + i;
        // load ledger
        dap_hash_fast_t l_hash = {};
        dap_chain_hash_fast_from_hex_str(it->key, &l_hash);
        s_nonconsensus_callback_atom_add(a_chain, it->value, it->value_len, &l_hash, false);
        log_it(L_DEBUG,"Load mode, doesn't save item %s:%s", it->key, l_nochain_pvt->group_datums);
    }
    dap_global_db_objs_delete(l_values, l_values_count);
    l_nochain_pvt->is_load_mode = false;
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
        dap_chain_datum_calc_hash(l_datum, &l_datum_hash);
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
static dap_chain_atom_verify_res_t s_nonconsensus_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t a_atom, size_t a_atom_size, dap_hash_fast_t *a_atom_hash, bool UNUSED_ARG a_atom_new)
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
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
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
            l_notifier->callback(l_notifier->arg, a_chain, (dap_chain_cell_id_t){ }, &l_hash_item->datum_data_hash, (void*)l_datum, l_datum_size);
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
static dap_chain_atom_iter_t* s_nonconsensus_callback_atom_iter_create(dap_chain_t * a_chain, dap_chain_cell_id_t a_cell_id, dap_hash_fast_t *a_hash_from)
{
    dap_chain_atom_iter_t * l_iter = DAP_NEW_Z(dap_chain_atom_iter_t);
    if (!l_iter) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    l_iter->chain = a_chain;
    l_iter->cell_id = a_cell_id;
    if (a_hash_from)
        s_nonconsensus_callback_atom_iter_find_by_hash(l_iter, a_hash_from, NULL);
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
        if (a_atom_size)
            *a_atom_size = l_ret_size;
    }
    //TODO set a_atom_iter item field
    return l_ret;
}

/**
 * @brief Get the first dag event from database
 *
 * @param a_atom_iter ap_chain_atom_iter_t object
 * @param a_atom_size a_atom_size atom size
 * @return dap_chain_atom_ptr_t
 */
static dap_chain_atom_ptr_t s_nonconsensus_callback_atom_iter_get(dap_chain_atom_iter_t *a_atom_iter, dap_chain_iter_op_t a_operation, size_t *a_atom_size)
{
    dap_return_val_if_fail(a_atom_iter, NULL);
    if (a_atom_iter->cur_item) { /* Iterator creates copies, free them at delete routine! */
        DAP_DEL_Z(a_atom_iter->cur);
        DAP_DEL_Z(a_atom_iter->cur_hash);
    }
    dap_nonconsensus_datum_hash_item_t *l_head = PVT(DAP_NONCONSENSUS(a_atom_iter->chain))->hash_items;
    switch (a_operation) {
    case DAP_CHAIN_ITER_OP_FIRST:
        a_atom_iter->cur_item = l_head;
        break;
    case DAP_CHAIN_ITER_OP_LAST:
        a_atom_iter->cur_item = l_head ? l_head->prev : NULL;
        break;
    case DAP_CHAIN_ITER_OP_NEXT:
        if (a_atom_iter->cur_item)
            a_atom_iter->cur_item = ((dap_nonconsensus_datum_hash_item_t *)a_atom_iter->cur_item)->next;
        break;
    case DAP_CHAIN_ITER_OP_PREV:
        if (a_atom_iter->cur_item)
            a_atom_iter->cur_item = ((dap_nonconsensus_datum_hash_item_t *)a_atom_iter->cur_item)->prev->next
                    ? ((dap_nonconsensus_datum_hash_item_t *)a_atom_iter->cur_item)->prev
                    : NULL;
        break;
    }
    if (a_atom_iter->cur_item) {
        dap_nonconsensus_datum_hash_item_t *l_item = a_atom_iter->cur_item;

        a_atom_iter->cur = dap_global_db_get_sync(PVT(DAP_NONCONSENSUS(a_atom_iter->chain))->group_datums,
                                                  l_item->key, &a_atom_iter->cur_size, NULL, NULL);
        a_atom_iter->cur_hash = DAP_NEW_Z(dap_hash_fast_t);
        dap_chain_hash_fast_from_str(l_item->key, a_atom_iter->cur_hash);
    } else
        *a_atom_iter = (dap_chain_atom_iter_t) { .chain = a_atom_iter->chain,
                                                 .cell_id = a_atom_iter->cell_id };
    if (a_atom_size)
        *a_atom_size = a_atom_iter->cur_size;
    return a_atom_iter->cur;
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
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
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

static uint64_t s_nonconsensus_callback_get_count_atom(dap_chain_t *a_chain)
{
    dap_return_val_if_fail(a_chain, 0);
    dap_nonconsensus_datum_hash_item_t *l_head = PVT(DAP_NONCONSENSUS(a_chain))->hash_items;
    dap_nonconsensus_datum_hash_item_t *tmp;
    uint64_t l_counter;
    DL_COUNT(l_head, tmp, l_counter);
    return l_counter;
}

static dap_chain_datum_iter_t *s_nonconsensus_callback_datum_iter_create(dap_chain_t *a_chain)
{
    dap_chain_datum_iter_t *l_ret = DAP_NEW_Z(dap_chain_datum_iter_t);
    if (!l_ret) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
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
