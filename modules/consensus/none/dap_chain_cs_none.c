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

typedef struct dap_chain_gdb_datum_hash_item{
    char key[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_t datum_data_hash;
    uint8_t padding[2];
    struct dap_chain_gdb_datum_hash_item *prev, *next;
} dap_chain_gdb_datum_hash_item_t;

typedef struct dap_chain_gdb_private
{
    bool celled;
    bool is_load_mode; // If load mode - not save when new atom adds
    uint8_t padding[7];
    char *group_datums;

    dap_chain_t *chain;

    pthread_cond_t load_cond;
    pthread_mutex_t load_mutex;
    dap_chain_gdb_datum_hash_item_t * hash_items;
} dap_chain_gdb_private_t;

#define PVT(a) ( (a) ? (dap_chain_gdb_private_t* ) (a)->_internal : NULL)

// Atomic element organization callbacks
static dap_chain_atom_verify_res_t s_chain_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t, size_t); //    Accept new event in gdb
static dap_chain_atom_verify_res_t s_chain_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_ptr_t, size_t); //    Verify new event in gdb
static size_t s_chain_callback_atom_get_static_hdr_size(void); //    Get gdb event header size

static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create(dap_chain_t * a_chain, dap_chain_cell_id_t a_cell_id, bool a_with_treshold);
static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create_from(dap_chain_t * a_chain,
        dap_chain_atom_ptr_t a, size_t a_atom_size);

// Delete iterator
static void s_chain_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter); //    Get the fisrt event from gdb

static dap_chain_atom_ptr_t s_chain_callback_atom_iter_find_by_hash(dap_chain_atom_iter_t * a_atom_iter,
        dap_chain_hash_fast_t * a_atom_hash, size_t * a_atom_size);

// Get event(s) from gdb
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_first(dap_chain_atom_iter_t * a_atom_iter, size_t * a_atom_size); //    Get the fisrt event from gdb
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_next(dap_chain_atom_iter_t * a_atom_iter, size_t * a_atom_size); //    Get the next event from gdb
static dap_chain_atom_ptr_t *s_chain_callback_atom_iter_get_links(dap_chain_atom_iter_t * a_atom_iter,
        size_t * a_links_size_ptr, size_t ** a_lasts_sizes_ptr); //    Get list of linked events
static dap_chain_atom_ptr_t *s_chain_callback_atom_iter_get_lasts(dap_chain_atom_iter_t * a_atom_iter,
        size_t * a_lasts_size_ptr, size_t ** a_lasts_sizes_ptr); //    Get list of linked events
static dap_chain_datum_t **s_chain_callback_atom_get_datum(dap_chain_atom_ptr_t a_atom, size_t a_atom_size, size_t *a_datums_count);
static dap_time_t s_chain_callback_atom_get_timestamp(dap_chain_atom_ptr_t a_atom) { return ((dap_chain_datum_t *)a_atom)->header.ts_create; }
static size_t s_chain_callback_datums_pool_proc(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums,
        size_t a_datums_size);
static void s_chain_gdb_ledger_load(dap_chain_t *a_chain);

/**
 * @brief stub for consensus
 *
 * @param a_chain chain object
 * @param a_chain_cfg chain config object
 * @return int
 */
static int s_cs_callback_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg)
{
    return dap_chain_gdb_new(a_chain, a_chain_cfg);
}


/**
 * @brief dap_chain_cs_gdb_init
 * Initialize GDB chain items organization class
 * @return
 */
int dap_chain_gdb_init(void)
{
    dap_chain_cs_add(CONSENSUS_NAME, s_cs_callback_new);
    dap_chain_cs_type_add(CONSENSUS_NAME, dap_chain_gdb_new);

    log_it(L_NOTICE, "Initialized GDB chain items organization class");
    return 0;
}

/**
 * @brief if current network in ONLINE state send to all connected node
 * executes, when you add data to gdb chain (class=gdb in chain config)
 * @param a_arg arguments. Can be network object (dap_chain_net_t)
 * @param a_op_code object type (f.e. l_net->type from dap_store_obj)
 * @param a_group group, for example "chain-gdb.home21-network.chain-F"
 * @param a_key key hex value, f.e. 0x12EFA084271BAA5EEE93B988E73444B76B4DF5F63DADA4B300B051E29C2F93
 * @param a_value buffer with data
 * @param a_value_len buffer size
 */
static void s_history_callback_notify(dap_global_db_context_t *a_context, dap_store_obj_t *a_obj, void *a_arg)
{
    if (a_arg){
        dap_chain_gdb_t * l_gdb = (dap_chain_gdb_t *) a_arg;
        dap_chain_net_t *l_net = dap_chain_net_by_id( l_gdb->chain->net_id);
        log_it(L_DEBUG,"%s.%s: op_code='%c' group=\"%s\" key=\"%s\" value_size=%zu",l_net->pub.name,
               l_gdb->chain->name, a_obj->type, a_obj->group, a_obj->key, a_obj->value_len);
        s_chain_callback_atom_add(l_gdb->chain, a_obj->value, a_obj->value_len);
        dap_chain_net_sync_gdb_broadcast(a_context, a_obj, l_net);
    }
}

/**
 * @brief set PVT(DAP_CHAIN_GDB(a_chain))->is_load_mode = true
 *
 * @param a_chain dap_chain_t object
 */
static void s_dap_chain_gdb_callback_purge(dap_chain_t *a_chain)
{
    PVT(DAP_CHAIN_GDB(a_chain))->is_load_mode = true;
}


static void s_callback_memepool_notify(dap_global_db_context_t *a_context UNUSED_ARG, dap_store_obj_t *a_obj, void *a_arg)
{
    if (a_obj->type == DAP_DB$K_OPTYPE_ADD)
        dap_chain_node_mempool_process_all(a_arg, false);
}

/**
 * @brief configure chain gdb
 * Set atom element callbacks
 * @param a_chain dap_chain_t chain object
 * @param a_chain_cfg dap_config_t config object
 * @return int
 */
int dap_chain_gdb_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg)
{
    dap_chain_gdb_t *l_gdb = DAP_NEW_Z(dap_chain_gdb_t);
    if (!l_gdb) {
        log_it(L_ERROR, "Memory allocation error in %s, line %d", __PRETTY_FUNCTION__, __LINE__);
        return -1;
    }
    dap_chain_gdb_private_t *l_gdb_priv = DAP_NEW_Z(dap_chain_gdb_private_t);
    if (!l_gdb_priv) {
        log_it(L_ERROR, "Memory allocation error in %s, line %d", __PRETTY_FUNCTION__, __LINE__);
        DAP_DELETE(l_gdb);
        return -1;
    }
    l_gdb->chain = a_chain;
    l_gdb->_internal = (void*) l_gdb_priv;
    a_chain->_inheritor = l_gdb;

    l_gdb_priv->celled = dap_config_get_item_bool_default(a_chain_cfg, CONSENSUS_NAME, "celled",false);

    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    l_gdb_priv->chain = a_chain;

    if(!l_gdb_priv->celled){
        l_gdb_priv->group_datums = dap_strdup_printf( "chain-gdb.%s.chain-%016"DAP_UINT64_FORMAT_X,l_net->pub.name,
                                                  a_chain->id.uint64);
    }else {
        // here is not work because dap_chain_net_load() not yet fully performed
        l_gdb_priv->group_datums = dap_strdup_printf("chain-gdb.%s.chain-%016"DAP_UINT64_FORMAT_X".cell-%016"DAP_UINT64_FORMAT_X,
                                                      l_net->pub.name, a_chain->id.uint64, a_chain->cells->id.uint64);
    }

    // Add group prefix that will be tracking all changes
    dap_global_db_add_sync_group(l_net->pub.name, "chain-gdb", s_history_callback_notify, l_gdb);

    dap_chain_add_mempool_notify_callback(a_chain, s_callback_memepool_notify, a_chain);

    pthread_cond_init(&l_gdb_priv->load_cond, NULL);
    pthread_mutex_init(&l_gdb_priv->load_mutex, NULL);

    a_chain->callback_delete = dap_chain_gdb_delete;
    a_chain->callback_purge = s_dap_chain_gdb_callback_purge;

    // Atom element callbacks
    a_chain->callback_atom_add = s_chain_callback_atom_add; // Accept new element in chain
    a_chain->callback_atom_verify = s_chain_callback_atom_verify; // Verify new element in chain
    a_chain->callback_atom_get_hdr_static_size = s_chain_callback_atom_get_static_hdr_size; // Get dag event hdr size

    a_chain->callback_atom_iter_create = s_chain_callback_atom_iter_create;
    a_chain->callback_atom_iter_create_from = s_chain_callback_atom_iter_create_from;
    a_chain->callback_atom_iter_delete = s_chain_callback_atom_iter_delete;

    a_chain->callback_atom_find_by_hash = s_chain_callback_atom_iter_find_by_hash;
    a_chain->callback_add_datums = s_chain_callback_datums_pool_proc;

    // Linear pass through
    a_chain->callback_atom_iter_get_first = s_chain_callback_atom_iter_get_first; // Get the fisrt element from chain
    a_chain->callback_atom_iter_get_next = s_chain_callback_atom_iter_get_next; // Get the next element from chain from the current one

    a_chain->callback_atom_iter_get_links = s_chain_callback_atom_iter_get_links; // Get the next element from chain from the current one
    a_chain->callback_atom_iter_get_lasts = s_chain_callback_atom_iter_get_lasts;
    a_chain->callback_atom_get_datums = s_chain_callback_atom_get_datum;
    a_chain->callback_atom_get_timestamp = s_chain_callback_atom_get_timestamp;

    a_chain->callback_load_from_gdb = s_chain_gdb_ledger_load;

    return 0;
}

/**
 * @brief clear dap_chain_gdb_t object
 *
 * @param a_chain dap_chain_t chain object
 */
void dap_chain_gdb_delete(dap_chain_t * a_chain)
{
    dap_chain_gdb_t * l_gdb = DAP_CHAIN_GDB(a_chain);
    dap_chain_gdb_private_t *l_gdb_priv = PVT(l_gdb);

    DAP_DELETE(l_gdb_priv->group_datums);

    DAP_DELETE(l_gdb);
    if (a_chain)
        a_chain->_inheritor = NULL;
}

/**
 * @brief get group name for ledger
 *
 * @param a_chain dap_chain_t * chain object
 * @return const char*
 */
const char* dap_chain_gdb_get_group(dap_chain_t * a_chain)
{
    if(!a_chain)
        return NULL;
    dap_chain_gdb_t * l_gdb = DAP_CHAIN_GDB(a_chain);
    dap_chain_gdb_private_t *l_gdb_priv = PVT(l_gdb);
    return l_gdb_priv->group_datums;
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
static void s_ledger_load_callback(UNUSED_ARG dap_global_db_context_t *a_global_db_context,
                                   UNUSED_ARG int a_rc, UNUSED_ARG const char *a_group,
                                   UNUSED_ARG const size_t a_values_total, const size_t a_values_count,
                                   dap_global_db_obj_t *a_values, void *a_arg)
{
    assert(a_arg);
    dap_chain_t * l_chain = (dap_chain_t *) a_arg;
    assert(l_chain);
    dap_chain_gdb_t * l_gdb = DAP_CHAIN_GDB(l_chain);
    assert(l_gdb);
    dap_chain_gdb_private_t * l_gdb_pvt = PVT(l_gdb);
    assert(l_gdb_pvt);
    // make list of datums
    for(size_t i = 0; i < a_values_count; i++) {
        dap_global_db_obj_t *it = a_values + i;
        s_chain_callback_atom_add(l_chain, it->value, it->value_len);
        log_it(L_DEBUG,"Load mode, doesn't save item %s:%s", it->key, l_gdb_pvt->group_datums);
    }

    pthread_mutex_lock(&l_gdb_pvt->load_mutex);
    l_gdb_pvt->is_load_mode = false;
    pthread_cond_broadcast(&l_gdb_pvt->load_cond);
    pthread_mutex_unlock(&l_gdb_pvt->load_mutex);
}

/**
 * @brief Load ledger from mempool
 *
 * @param a_gdb_group a_gdb_group char gdb group name
 * @param a_chain chain dap_chain_t object
 * @return int return 0 if OK otherwise  negative error code
 */
static void s_chain_gdb_ledger_load(dap_chain_t *a_chain)
{
    dap_chain_gdb_t * l_gdb = DAP_CHAIN_GDB(a_chain);
    dap_chain_gdb_private_t * l_gdb_pvt = PVT(l_gdb);
    // load ledger
    l_gdb_pvt->is_load_mode = true;
    //  Read the entire database into an array of size bytes
    pthread_mutex_lock(&l_gdb_pvt->load_mutex);
    dap_global_db_get_all(l_gdb_pvt->group_datums, 0, s_ledger_load_callback, a_chain);
    while (l_gdb_pvt->is_load_mode)
        pthread_cond_wait(&l_gdb_pvt->load_cond, &l_gdb_pvt->load_mutex);
    pthread_mutex_unlock(&l_gdb_pvt->load_mutex);
}

/**
 * @brief call s_chain_callback_atom_add for every dap_chain_datum_t objects in a_datums array
 *
 * @param a_chain dap_chain_t chain object (f.e. plasma)
 * @param a_datums dap_chain_datum array with dap_chain_datum objects
 * @param a_datums_count object counts in datums array
 * @return size_t
 */
static size_t s_chain_callback_datums_pool_proc(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums, size_t a_datums_count)
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
        dap_global_db_set(PVT(DAP_CHAIN_GDB(a_chain))->group_datums, l_db_key, l_datum,
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
static dap_chain_atom_verify_res_t s_chain_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t a_atom, size_t a_atom_size)
{
    if (NULL == a_chain) {
        log_it(L_WARNING, "Arguments is NULL for s_chain_callback_atom_add");
        return ATOM_REJECT;
    }
    dap_chain_gdb_t * l_gdb = DAP_CHAIN_GDB(a_chain);
    dap_chain_gdb_private_t *l_gdb_priv = PVT(l_gdb);
    dap_chain_datum_t *l_datum = (dap_chain_datum_t*) a_atom;
    dap_hash_fast_t l_datum_hash;
    dap_hash_fast(l_datum->data, l_datum->header.data_size, &l_datum_hash);
    if(dap_chain_datum_add(a_chain, l_datum, a_atom_size, &l_datum_hash))
        return ATOM_REJECT;

    dap_chain_gdb_datum_hash_item_t * l_hash_item = DAP_NEW_Z(dap_chain_gdb_datum_hash_item_t);
    if (!l_hash_item) {
        log_it(L_ERROR, "Memory allocation error in %s, line %d", __PRETTY_FUNCTION__, __LINE__);
        return ATOM_REJECT;
    }
    size_t l_datum_size = dap_chain_datum_size(l_datum);
    dap_hash_fast(l_datum->data,l_datum->header.data_size,&l_hash_item->datum_data_hash );
    dap_chain_hash_fast_to_str(&l_hash_item->datum_data_hash, l_hash_item->key, sizeof(l_hash_item->key));
    DL_APPEND(l_gdb_priv->hash_items, l_hash_item);
    if (!l_gdb_priv->is_load_mode && a_chain->atom_notifiers) {
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
static dap_chain_atom_verify_res_t s_chain_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_ptr_t a_atom, size_t a_atom_size)
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
static size_t s_chain_callback_atom_get_static_hdr_size()
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
static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create(dap_chain_t * a_chain, dap_chain_cell_id_t a_cell_id, bool a_with_treshold)
{
    dap_chain_atom_iter_t * l_iter = DAP_NEW_Z(dap_chain_atom_iter_t);
    if (!l_iter) {
        log_it(L_ERROR, "Memory allocation error in %s, line %d", __PRETTY_FUNCTION__, __LINE__);
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
static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create_from(dap_chain_t * a_chain,
        dap_chain_atom_ptr_t a_atom, size_t a_atom_size)
{
    dap_chain_atom_iter_t * l_iter = DAP_NEW_Z(dap_chain_atom_iter_t);
    if (!l_iter) {
        log_it(L_ERROR, "Memory allocation error in %s, line %d", __PRETTY_FUNCTION__, __LINE__);
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
static void s_chain_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter)
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
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_find_by_hash(dap_chain_atom_iter_t * a_atom_iter,
        dap_chain_hash_fast_t * a_atom_hash, size_t *a_atom_size)
{
    char l_key[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(a_atom_hash, l_key, sizeof(l_key));
    size_t l_ret_size;
    dap_chain_atom_ptr_t l_ret = NULL;
    dap_chain_gdb_t *l_gdb = DAP_CHAIN_GDB(a_atom_iter->chain);
    if (l_gdb) {
        l_ret = dap_global_db_get_sync(PVT(l_gdb)->group_datums, l_key, &l_ret_size, NULL, NULL);
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
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_first(dap_chain_atom_iter_t * a_atom_iter, size_t *a_atom_size)
{
    if (!a_atom_iter)
        return NULL;
    if (a_atom_iter->cur_item) { /* Iterator creates copies, free them at delete routine! */
        DAP_DEL_Z(a_atom_iter->cur);
        DAP_DEL_Z(a_atom_iter->cur_hash);
    }
    dap_chain_datum_t * l_datum = NULL;
    dap_chain_gdb_datum_hash_item_t *l_item = PVT(DAP_CHAIN_GDB(a_atom_iter->chain))->hash_items;
    a_atom_iter->cur_item = l_item;
    if (a_atom_iter->cur_item) {
        size_t l_datum_size = 0;
        l_datum = (dap_chain_datum_t*)dap_global_db_get_sync(PVT(DAP_CHAIN_GDB(a_atom_iter->chain))->group_datums,
                                                             l_item->key, &l_datum_size, NULL, NULL);
        DAP_DEL_Z(a_atom_iter->cur);
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
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_next(dap_chain_atom_iter_t *a_atom_iter, size_t *a_atom_size)
{
    dap_chain_datum_t * l_datum = NULL;
    dap_chain_gdb_datum_hash_item_t *l_item = (dap_chain_gdb_datum_hash_item_t*)a_atom_iter->cur_item;
    if (l_item)
        l_item = l_item->next;
    a_atom_iter->cur_item = l_item;
    if (a_atom_iter->cur_item ){
        size_t l_datum_size =0;
        l_datum = (dap_chain_datum_t *)dap_global_db_get_sync(PVT(DAP_CHAIN_GDB(a_atom_iter->chain))->group_datums, l_item->key, &l_datum_size, NULL, NULL);
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
static dap_chain_atom_ptr_t* s_chain_callback_atom_iter_get_links(dap_chain_atom_iter_t * a_atom_iter,
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
static dap_chain_atom_ptr_t* s_chain_callback_atom_iter_get_lasts(dap_chain_atom_iter_t * a_atom_iter,
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
static dap_chain_datum_t **s_chain_callback_atom_get_datum(dap_chain_atom_ptr_t a_atom, size_t a_atom_size, size_t *a_datums_count)
{
    UNUSED(a_atom_size);
    if (a_atom){
        dap_chain_datum_t *l_datum = (dap_chain_datum_t *)a_atom;
        if (l_datum){
            dap_chain_datum_t **l_datums = DAP_NEW(dap_chain_datum_t *);
            if (!l_datums) {
                log_it(L_ERROR, "Memory allocation error in %s, line %d", __PRETTY_FUNCTION__, __LINE__);
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
