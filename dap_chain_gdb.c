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

#include "utlist.h"

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_config.h"
#include "dap_hash.h"
#include "dap_chain_ledger.h"
#include "dap_chain_global_db.h"
#include "dap_chain_global_db_driver.h"
#include "dap_chain_net.h"
#include "dap_chain_cs.h"
#include "dap_chain_gdb.h"

#define LOG_TAG "dap_chain_gdb"

#define CONSENSUS_NAME "gdb"

typedef struct dap_chain_gdb_datum_hash_item{
    char key[70];
    dap_chain_hash_fast_t datum_data_hash;
    uint8_t padding[2];
    struct dap_chain_gdb_datum_hash_item * prev;
    struct dap_chain_gdb_datum_hash_item * next;
} dap_chain_gdb_datum_hash_item_t;

typedef struct dap_chain_gdb_private
{
    bool celled;
    bool is_load_mode; // If load mode - not save when new atom adds
    uint8_t padding[7];
    char *group_datums;

    dap_chain_t *chain;

    dap_chain_gdb_datum_hash_item_t * hash_items;
} dap_chain_gdb_private_t;

#define PVT(a) ( (a) ? (dap_chain_gdb_private_t* ) (a)->_internal : NULL)

static int dap_chain_gdb_ledger_load(dap_chain_gdb_t *a_gdb, dap_chain_net_t *a_net);

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
static size_t s_chain_callback_datums_pool_proc_with_group(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums,
        size_t a_datums_size, const char *a_group);


/**
 * Stub for consensus
 */
static int s_cs_callback_new(dap_chain_t * a_chain, dap_config_t * a_chain_cfg)
{
    return dap_chain_gdb_new(a_chain, a_chain_cfg);
}


/**
 * @brief dap_chain_cs_gdb_init
 * @return
 */
int dap_chain_gdb_init(void)
{
    dap_chain_cs_add(CONSENSUS_NAME, s_cs_callback_new);
    dap_chain_class_add(CONSENSUS_NAME, dap_chain_gdb_new);

    log_it(L_NOTICE, "Initialized GDB chain items organization class");
    return 0;
}

/**
 * @brief s_history_callback_notify
 * @param a_arg
 * @param a_op_code
 * @param a_prefix
 * @param a_group
 * @param a_key
 * @param a_value
 * @param a_value_len
 */
static void s_history_callback_notify(void * a_arg, const char a_op_code, const char * a_prefix, const char * a_group,
        const char * a_key, const void * a_value, const size_t a_value_size)
{
    (void) a_value;
    (void) a_prefix;
    if (a_arg){
        dap_chain_gdb_t * l_gdb = (dap_chain_gdb_t *) a_arg;
        dap_chain_net_t *l_net = dap_chain_net_by_id( l_gdb->chain->net_id);
        log_it(L_DEBUG,"%s.%s: op_code='%c' group=\"%s\" key=\"%s\" value_size=%u",l_net->pub.name,
               l_gdb->chain->name, a_op_code, a_group, a_key, a_value_size);
    }
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

    l_gdb_priv->celled = dap_config_get_item_bool_default(a_chain_cfg, CONSENSUS_NAME, "celled",false);

    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    l_gdb_priv->chain = a_chain;

    if(!l_gdb_priv->celled){
        l_gdb_priv->group_datums = dap_strdup_printf( "chain-gdb.%s.chain-%016llX",l_net->pub.name,
                                                  a_chain->id.uint64);
    }else {
        // here is not work because dap_chain_net_load() not yet fully performed
        l_gdb_priv->group_datums = dap_strdup_printf( "chain-gdb.%s.chain-%016llX.cell-%016llX",l_net->pub.name,
                                                  a_chain->id.uint64, l_net->pub.cell_id.uint64);
    }

    // Add group prefix that will be tracking all changes
    dap_chain_global_db_add_history_group_prefix("chain-gdb");

    dap_chain_global_db_add_history_callback_notify("chain-gdb", s_history_callback_notify,l_gdb);

    // load ledger
    l_gdb_priv->is_load_mode = true;
    dap_chain_gdb_ledger_load(l_gdb, l_net);
    l_gdb_priv->is_load_mode = false;

    a_chain->callback_delete = dap_chain_gdb_delete;

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
    a_chain->callback_datums_pool_proc_with_group = s_chain_callback_datums_pool_proc_with_group;

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
    dap_chain_gdb_private_t *l_gdb_priv = PVT(l_gdb);

    DAP_DELETE(l_gdb_priv->group_datums);

    DAP_DELETE(l_gdb);
    a_chain->_inheritor = NULL;
}

/**
 * @brief dap_chain_gdb_get_group
 * @param a_chain
 * @return group name for ledger
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
static int compare_datum_items(const void * l_a, const void * l_b)
{
    const dap_chain_datum_t *l_item_a = (const dap_chain_datum_t*) l_a;
    const dap_chain_datum_t *l_item_b = (const dap_chain_datum_t*) l_b;
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
static int dap_chain_gdb_ledger_load(dap_chain_gdb_t *a_gdb, dap_chain_net_t *a_net)
{
    dap_chain_gdb_private_t *l_gdb_priv = PVT(a_gdb);
    dap_list_t *l_datum_list = NULL, *l_list_tmp = NULL;
    // protect from reloading
    if(dap_chain_ledger_count( a_net->pub.ledger ) > 0)
        return 0;

    size_t l_data_size = 0;


    //  Read the entire database into an array of size bytes
    dap_global_db_obj_t **data = dap_chain_global_db_gr_load(l_gdb_priv->group_datums , &l_data_size);
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
        s_chain_callback_atom_add(a_gdb->chain,l_datum);
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
static size_t s_chain_callback_datums_pool_proc(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums,
        size_t a_datums_count)
{
    for(size_t i = 0; i < a_datums_count; i++) {
        dap_chain_datum_t * l_datum = a_datums[i];
        s_chain_callback_atom_add(a_chain, l_datum );
    }
    return a_datums_count;
}

static size_t s_chain_callback_datums_pool_proc_with_group(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums,
        size_t a_datums_count, const char *a_group)
{
    if(dap_strcmp(dap_chain_gdb_get_group(a_chain), a_group))
        return 0;
    s_chain_callback_datums_pool_proc(a_chain, a_datums, a_datums_count);
}

/**
 * @brief s_chain_callback_datums_add
 * @param a_chain
 * @param a_datums
 * @param a_datums_size
 */
static int s_chain_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t a_atom)
{
    dap_chain_gdb_t * l_gdb = DAP_CHAIN_GDB(a_chain);
    dap_chain_gdb_private_t *l_gdb_priv = PVT(l_gdb);
    dap_chain_datum_t *l_datum = (dap_chain_datum_t*) a_atom;
    switch (l_datum->header.type_id) {
        case DAP_CHAIN_DATUM_TOKEN_DECL:{
            dap_chain_datum_token_t *l_token = (dap_chain_datum_token_t*) l_datum->data;
            dap_chain_ledger_token_add(a_chain->ledger,l_token, l_datum->header.data_size);
        }break;
        case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
            dap_chain_datum_token_emission_t *l_token_emission = (dap_chain_datum_token_emission_t*) l_datum->data;
            dap_chain_ledger_token_emission_add(a_chain->ledger, l_token_emission, l_datum->header.data_size);
        }break;
        case DAP_CHAIN_DATUM_TX:{
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*) l_datum->data;
            //if ( !l_gdb_priv->is_load_mode ) // If its not load module but mempool proc
            //    l_tx->header.ts_created = time(NULL);
            //if(dap_chain_datum_tx_get_size(l_tx) == l_datum->header.data_size){
                 dap_chain_ledger_tx_add(a_chain->ledger, l_tx);
            //}else
            //    return -2;
        }break;
        default: return -1;
    }

    dap_chain_gdb_datum_hash_item_t * l_hash_item = DAP_NEW_Z(dap_chain_gdb_datum_hash_item_t);
    size_t l_datum_size = dap_chain_datum_size(l_datum);
    dap_hash_fast(l_datum->data,l_datum->header.data_size,&l_hash_item->datum_data_hash );
    dap_chain_hash_fast_to_str(&l_hash_item->datum_data_hash,l_hash_item->key,sizeof(l_hash_item->key)-1);
    if ( !l_gdb_priv->is_load_mode ){
        dap_chain_global_db_gr_set(l_hash_item->key, l_datum, l_datum_size, l_gdb_priv->group_datums);
    }else
        log_it(L_DEBUG,"Load mode, doesnt save item %s:%s", l_hash_item->key, l_gdb_priv->group_datums);

    DL_APPEND(l_gdb_priv->hash_items, l_hash_item);
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
    (void) a_chain;
    (void) a_atom;
    return 0;
}

/**
 * @brief s_chain_callback_atom_get_size Get size of atomic element
 * @param a_atom
 * @return
 */
static size_t s_chain_callback_atom_hdr_get_size(dap_chain_atom_ptr_t a_atom)
{ 
    return ((dap_chain_datum_t *) a_atom)->header.data_size +sizeof (((dap_chain_datum_t *) a_atom)->header);
}

/**
 * @brief s_chain_callback_atom_get_static_hdr_size
 * @param a_chain
 * @return
 */
static size_t s_chain_callback_atom_get_static_hdr_size()
{
    static dap_chain_datum_t *l_datum_null=NULL;
    return sizeof(l_datum_null->header);
}

/**
 * @brief s_chain_callback_atom_iter_create Create atomic element iterator
 * @param a_chain
 * @return
 */
static dap_chain_atom_iter_t* s_chain_callback_atom_iter_create(dap_chain_t * a_chain)
{
    dap_chain_atom_iter_t * l_iter = DAP_NEW_Z(dap_chain_atom_iter_t);
    l_iter->chain = a_chain;
    return l_iter;
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
    dap_chain_atom_iter_t * l_iter = DAP_NEW_Z(dap_chain_atom_iter_t);
    l_iter->chain = a_chain;
    l_iter->cur = a_atom;
    return l_iter;
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
 * @details Searchs by datum data hash, not for datum's hash itself
 * @param a_atom_iter
 * @param a_atom_hash
 * @return
 */
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_find_by_hash(dap_chain_atom_iter_t * a_atom_iter,
        dap_chain_hash_fast_t * a_atom_hash)
{
    char * l_key = dap_chain_hash_fast_to_str_new(a_atom_hash);
    size_t l_ret_size;
    dap_chain_atom_ptr_t l_ret;
    dap_chain_gdb_t * l_gdb = DAP_CHAIN_GDB(a_atom_iter->chain );
    l_ret = dap_chain_global_db_gr_get(l_key,&l_ret_size,
                                       PVT ( l_gdb )->group_datums  );
    return l_ret;
}

/**
 * @brief s_chain_callback_atom_iter_get_first Get the first dag event
 * @param a_atom_iter
 * @return
 */
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_first(dap_chain_atom_iter_t * a_atom_iter)
{
    dap_chain_datum_t * l_datum = NULL;
    a_atom_iter->cur_item = PVT ( DAP_CHAIN_GDB(a_atom_iter->chain) )->hash_items;
    if (a_atom_iter->cur_item ){
        dap_chain_gdb_datum_hash_item_t * l_item = PVT ( DAP_CHAIN_GDB(a_atom_iter->chain) )->hash_items;
        size_t l_datum_size =0;
        l_datum= (dap_chain_datum_t*) dap_chain_global_db_gr_get(l_item->key,&l_datum_size,PVT(DAP_CHAIN_GDB(a_atom_iter->chain))->group_datums );
        if (a_atom_iter->cur) // This iterator should clean up data for it because its allocate it
            DAP_DELETE( a_atom_iter->cur);
        a_atom_iter->cur = l_datum;
    }
    return l_datum;
}

/**
 * @brief s_chain_callback_atom_iter_get_next Get the next dag event
 * @param a_atom_iter
 * @return
 */
static dap_chain_atom_ptr_t s_chain_callback_atom_iter_get_next(dap_chain_atom_iter_t * a_atom_iter)
{
    dap_chain_datum_t * l_datum = NULL;
    a_atom_iter->cur_item = a_atom_iter->cur_item?
                ((dap_chain_gdb_datum_hash_item_t*) a_atom_iter->cur_item)->next : NULL;
    if (a_atom_iter->cur_item ){
        size_t l_datum_size =0;
        l_datum= (dap_chain_datum_t*) dap_chain_global_db_gr_get(
                                ((dap_chain_gdb_datum_hash_item_t*) a_atom_iter->cur_item)->key,
                                &l_datum_size, PVT(DAP_CHAIN_GDB(a_atom_iter->chain))->group_datums );
        if (a_atom_iter->cur) // This iterator should clean up data for it because its allocate it
            DAP_DELETE( a_atom_iter->cur);
        a_atom_iter->cur = l_datum;
    }
    return l_datum;
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
    (void) a_atom_iter;
    (void) a_links_size_ptr;
    return NULL;
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
    (void) a_atom_iter;
    (void) a_lasts_size_ptr;
    return NULL;
}

