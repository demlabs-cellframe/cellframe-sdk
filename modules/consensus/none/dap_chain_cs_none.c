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

#include "dap_chain_net.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_config.h"
#include "dap_hash.h"
#include "dap_chain_cell.h"
#include "dap_chain_ledger.h"
#include "dap_chain_global_db.h"
#include "dap_chain_global_db_driver.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_none.h"

#define LOG_TAG "dap_chain_cs_none"

#define CONSENSUS_NAME "none"

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

static size_t s_chain_callback_datums_pool_proc(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums,
        size_t a_datums_size);
static size_t s_chain_callback_datums_pool_proc_with_group(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums,
        size_t a_datums_size, const char *a_group);


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
static void s_history_callback_notify(void * a_arg, const char a_op_code, const char * a_group,
        const char * a_key, const void * a_value, const size_t a_value_size)
{
    if (a_arg){
        dap_chain_gdb_t * l_gdb = (dap_chain_gdb_t *) a_arg;
        dap_chain_net_t *l_net = dap_chain_net_by_id( l_gdb->chain->net_id);
        log_it(L_DEBUG,"%s.%s: op_code='%c' group=\"%s\" key=\"%s\" value_size=%zu",l_net->pub.name,
               l_gdb->chain->name, a_op_code, a_group, a_key, a_value_size);
        dap_chain_net_sync_gdb_broadcast((void *)l_net, a_op_code, a_group, a_key, a_value, a_value_size);
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
                                                  a_chain->id.uint64, a_chain->cells->id.uint64);
    }

    // Add group prefix that will be tracking all changes
    dap_chain_global_db_add_sync_group(l_net->pub.name, "chain-gdb", s_history_callback_notify, l_gdb);

    // load ledger
    l_gdb_priv->is_load_mode = true;
    dap_chain_gdb_ledger_load(l_gdb_priv->group_datums, a_chain);

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
    a_chain->callback_add_datums_with_group = s_chain_callback_datums_pool_proc_with_group;

    // Linear pass through
    a_chain->callback_atom_iter_get_first = s_chain_callback_atom_iter_get_first; // Get the fisrt element from chain
    a_chain->callback_atom_iter_get_next = s_chain_callback_atom_iter_get_next; // Get the next element from chain from the current one

    a_chain->callback_atom_iter_get_links = s_chain_callback_atom_iter_get_links; // Get the next element from chain from the current one
    a_chain->callback_atom_iter_get_lasts = s_chain_callback_atom_iter_get_lasts;
    a_chain->callback_atom_get_datums = s_chain_callback_atom_get_datum;

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
 * @brief Load ledger from mempool
 * 
 * @param a_gdb_group a_gdb_group char gdb group name
 * @param a_chain chain dap_chain_t object
 * @return int return 0 if OK otherwise  negative error code
 */
int dap_chain_gdb_ledger_load(char *a_gdb_group, dap_chain_t *a_chain)
{
    size_t l_data_size = 0;
    //  Read the entire database into an array of size bytes
    dap_global_db_obj_t *data = dap_chain_global_db_gr_load(a_gdb_group, &l_data_size);
    // make list of datums
    for(size_t i = 0; i < l_data_size; i++) {
        s_chain_callback_atom_add(a_chain, data[i].value, data[i].value_len);
    }
    dap_chain_global_db_objs_delete(data, l_data_size);
    PVT(DAP_CHAIN_GDB(a_chain))->is_load_mode = false;
    return 0;
}

/**
 * @brief call s_chain_callback_atom_add for every dap_chain_datum_t objects in a_datums array
 * 
 * @param a_chain dap_chain_t chain object (f.e. plasma)
 * @param a_datums dap_chain_datum array with dap_chain_datum objects
 * @param a_datums_count object counts in datums array
 * @return size_t 
 */
static size_t s_chain_callback_datums_pool_proc(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums,
        size_t a_datums_count)
{
    for(size_t i = 0; i < a_datums_count; i++) {
        dap_chain_datum_t * l_datum = a_datums[i];
        s_chain_callback_atom_add(a_chain, l_datum,dap_chain_datum_size(l_datum) );
    }
    return a_datums_count;
}

/**
 * @brief call s_chain_callback_atom_add for every dap_chain_datum_t objects in a_datums array only if chain contains specific group (chain-gdb.home21-network.chain-F)
 * 
 * @param a_chain dap_chain_t chain object (f.e. plasma)
 * @param a_datums dap_chain_datum array with dap_chain_datum objects
 * @param a_datums_count object counts in datums array
 * @param a_group group name
 * @return size_t 
 */
static size_t s_chain_callback_datums_pool_proc_with_group(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums,
        size_t a_datums_count, const char *a_group)
{
    if(dap_strcmp(dap_chain_gdb_get_group(a_chain), a_group))
        return 0;
    return s_chain_callback_datums_pool_proc(a_chain, a_datums, a_datums_count);
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
    dap_chain_gdb_t * l_gdb = DAP_CHAIN_GDB(a_chain);
    dap_chain_gdb_private_t *l_gdb_priv = PVT(l_gdb);
    dap_chain_datum_t *l_datum = (dap_chain_datum_t*) a_atom;
    if ( a_atom_size < l_datum->header.data_size+ sizeof (l_datum->header) ){
        log_it(L_INFO,"Corrupted atom rejected: wrong size %zd not equel or less atom size %zd",l_datum->header.data_size+ sizeof (l_datum->header),
               a_atom_size);
        return ATOM_REJECT;
    }
    switch (l_datum->header.type_id) {
        case DAP_CHAIN_DATUM_TOKEN_DECL:{
            if (dap_chain_ledger_token_load(a_chain->ledger, (dap_chain_datum_token_t *)l_datum->data, l_datum->header.data_size))
                return ATOM_REJECT;
        }break;
        case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
            if (dap_chain_ledger_token_emission_load(a_chain->ledger, l_datum->data, l_datum->header.data_size))
                return ATOM_REJECT;
        }break;
        case DAP_CHAIN_DATUM_TX:{
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*) l_datum->data;
            // TODO process with different codes from ledger to work with ledger thresholds
            if (dap_chain_ledger_tx_load(a_chain->ledger, l_tx, NULL) != 1)
                return ATOM_REJECT;
        }break;
        case DAP_CHAIN_DATUM_CA:{
            if ( dap_cert_chain_file_save(l_datum, a_chain->net_name) < 0 )
                return ATOM_REJECT;
        }break;
        case DAP_CHAIN_DATUM_SIGNER:
		break;
        case DAP_CHAIN_DATUM_CUSTOM:
        break;
        default:
            return ATOM_REJECT;
    }

    dap_chain_gdb_datum_hash_item_t * l_hash_item = DAP_NEW_Z(dap_chain_gdb_datum_hash_item_t);
    size_t l_datum_size = dap_chain_datum_size(l_datum);
    dap_hash_fast(l_datum->data,l_datum->header.data_size,&l_hash_item->datum_data_hash );
    dap_chain_hash_fast_to_str(&l_hash_item->datum_data_hash,l_hash_item->key,sizeof(l_hash_item->key)-1);
    if (!l_gdb_priv->is_load_mode) {
	dap_chain_global_db_gr_set(l_hash_item->key, l_datum, l_datum_size, l_gdb_priv->group_datums);
    } else
        log_it(L_DEBUG,"Load mode, doesn't save item %s:%s", l_hash_item->key, l_gdb_priv->group_datums);

    DL_APPEND(l_gdb_priv->hash_items, l_hash_item);
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
    if (a_atom_iter->cur_item)
        DAP_DELETE(a_atom_iter->cur_item);
    DAP_DELETE(a_atom_iter->cur_hash);
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
    char * l_key = dap_chain_hash_fast_to_str_new(a_atom_hash);
    size_t l_ret_size;
    dap_chain_atom_ptr_t l_ret;
    dap_chain_gdb_t * l_gdb = DAP_CHAIN_GDB(a_atom_iter->chain );
    l_ret = dap_chain_global_db_gr_get(l_key,&l_ret_size,
                                       PVT ( l_gdb )->group_datums  );
    *a_atom_size = l_ret_size;
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
    dap_chain_datum_t * l_datum = NULL;
    dap_chain_gdb_datum_hash_item_t *l_item = PVT(DAP_CHAIN_GDB(a_atom_iter->chain))->hash_items;
    a_atom_iter->cur_item = l_item;
    if (a_atom_iter->cur_item ){
        size_t l_datum_size =0;
        l_datum= (dap_chain_datum_t*) dap_chain_global_db_gr_get(l_item->key, &l_datum_size,
                                                                 PVT(DAP_CHAIN_GDB(a_atom_iter->chain))->group_datums );
        if (a_atom_iter->cur) // This iterator should clean up data for it because its allocate it
            DAP_DELETE( a_atom_iter->cur);
        a_atom_iter->cur = l_datum;
        a_atom_iter->cur_size = l_datum_size;
        a_atom_iter->cur_hash = DAP_NEW_Z(dap_hash_fast_t);
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
        l_datum = (dap_chain_datum_t *)dap_chain_global_db_gr_get(l_item->key, &l_datum_size,
                                                                  PVT(DAP_CHAIN_GDB(a_atom_iter->chain))->group_datums);
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
        dap_chain_datum_t * l_datum = a_atom;
        if (l_datum){
            dap_chain_datum_t **l_datums = DAP_NEW(dap_chain_datum_t *);
            if (a_datums_count)
                *a_datums_count = 1;
            l_datums[0] = l_datum;
            return l_datums;
        }else
            return NULL;
    }else
        return NULL;
}
