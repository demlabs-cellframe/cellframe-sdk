/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
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
#include <sys/types.h>
#include <dirent.h>
#if defined(DAP_OS_LINUX) && !defined(DAP_OS_ANDROID)
#include <stdc-predef.h>
#endif
#include <unistd.h>
#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_decree.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_config.h"
#include "dap_chain.h"
#include "dap_cert.h"
#include "dap_chain_cell.h"
#include "dap_chain_cs.h"
#include "dap_cert_file.h"
#include "dap_chain_ch.h"
#include "dap_stream_ch_gossip.h"
#include "dap_notify_srv.h"
#include <uthash.h>
#include <pthread.h>
#include "json.h"

#define LOG_TAG "chain"

typedef struct dap_chain_item_id {
    dap_chain_id_t id;
    dap_chain_net_id_t net_id;
}  dap_chain_item_id_t;

typedef struct dap_chain_item {
    dap_chain_item_id_t item_id;
    dap_chain_t *chain;
    UT_hash_handle hh;
} dap_chain_item_t;

typedef struct dap_chain_datum_notifier {
    dap_chain_callback_datum_notify_t callback;
    dap_proc_thread_t *proc_thread;
    void *arg;
} dap_chain_datum_notifier_t;

typedef struct dap_chain_datum_removed_notifier {
    dap_chain_callback_datum_removed_notify_t callback;
    dap_proc_thread_t *proc_thread;
    void *arg;
} dap_chain_datum_removed_notifier_t;

typedef struct dap_chain_blockchain_timer_notifier {
    dap_chain_callback_blockchain_timer_t callback;
    void *arg;
} dap_chain_blockchain_timer_notifier_t;


static pthread_rwlock_t s_chain_items_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static dap_chain_item_t *s_chain_items = NULL;

int s_prepare_env();

/**
 * @brief dap_chain_init
 * @return
 */
int dap_chain_init(void)
{
    // Cell sharding init
    dap_chain_cell_init();
    dap_chain_cs_init();
    //dap_chain_show_hash_blocks_file(g_gold_hash_blocks_file);
    //dap_chain_show_hash_blocks_file(g_silver_hash_blocks_file);
    return 0;
}

/**
 * @brief dap_chain_deinit
 */
void dap_chain_deinit(void)
{
    dap_chain_item_t * l_item = NULL, *l_tmp = NULL;
    HASH_ITER(hh, s_chain_items, l_item, l_tmp) {
          dap_chain_delete(l_item->chain);
          DAP_DELETE(l_item);
    }
}

/**
 * @brief 
 * create dap chain object
 * @param a_ledger dap_ledger_t ledger object
 * @param a_chain_net_name blockchain network name
 * @param a_chain_name chain name
 * @param a_chain_net_id 
 * @param a_chain_id chain id
 * @return dap_chain_t* 
 */
dap_chain_t *dap_chain_create(const char *a_chain_net_name, const char *a_chain_name, dap_chain_net_id_t a_chain_net_id, dap_chain_id_t a_chain_id)
{
    dap_chain_item_t *l_chain_item = NULL;
    dap_chain_item_id_t l_id = { a_chain_id, a_chain_net_id };
    pthread_rwlock_wrlock(&s_chain_items_rwlock);
    HASH_FIND(hh, s_chain_items, &l_id, sizeof(dap_chain_item_id_t), l_chain_item);
    if (l_chain_item) {
        log_it(L_ERROR, "Chain id %"DAP_UINT64_FORMAT_U" in net %"DAP_UINT64_FORMAT_U" already exists",
                        a_chain_id.uint64, a_chain_net_id.uint64);
        return pthread_rwlock_unlock(&s_chain_items_rwlock), NULL;
    }
    dap_chain_t *l_ret = DAP_NEW(dap_chain_t);
    if ( !l_ret ) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return pthread_rwlock_unlock(&s_chain_items_rwlock), NULL;
    }
    *l_ret = (dap_chain_t) {
        .rwlock     = PTHREAD_RWLOCK_INITIALIZER,
        .id         = a_chain_id,
        .net_id     = a_chain_net_id,
        .name       = dap_strdup(a_chain_name),
        .net_name   = dap_strdup(a_chain_net_name),
        .is_mapped  = dap_config_get_item_bool_default(g_config, "ledger", "mapped", true),
        .cell_rwlock= PTHREAD_RWLOCK_INITIALIZER,
        ._pvt       = DAP_NEW_Z(dap_chain_pvt_t)
    };

    l_chain_item = DAP_NEW(dap_chain_item_t);
    *l_chain_item = (dap_chain_item_t) {
        .item_id    = l_id,
        .chain      = l_ret
    };

    HASH_ADD(hh, s_chain_items, item_id, sizeof(dap_chain_item_id_t), l_chain_item);
    pthread_rwlock_unlock(&s_chain_items_rwlock);
    return l_ret;
}

/**
 * @brief
 * delete dap chain object
 * @param a_chain dap_chain_t object
 */
void dap_chain_delete(dap_chain_t *a_chain)
{
    dap_chain_item_t * l_item = NULL;
    dap_chain_item_id_t l_chain_item_id = {
        .id     = a_chain->id,
        .net_id = a_chain->net_id,
    };

    pthread_rwlock_wrlock(&s_chain_items_rwlock);
    HASH_FIND(hh, s_chain_items, &l_chain_item_id, sizeof(dap_chain_item_id_t), l_item);
    if (l_item) {
       HASH_DEL(s_chain_items, l_item);
       DAP_DELETE(l_item);
    } else {
       log_it(L_WARNING,"Trying to remove non-existent 0x%16"DAP_UINT64_FORMAT_X":0x%16"DAP_UINT64_FORMAT_X" chain",
              a_chain->id.uint64, a_chain->net_id.uint64);
    }
    pthread_rwlock_unlock(&s_chain_items_rwlock);
    dap_list_free_full(a_chain->atom_notifiers, NULL);
    dap_list_free_full(a_chain->datum_notifiers, NULL);
    dap_list_free_full(a_chain->datum_removed_notifiers, NULL);
    dap_list_free_full(a_chain->blockchain_timers, NULL);
    dap_list_free_full(a_chain->atom_confirmed_notifiers, NULL);
    if (a_chain->callback_delete)
        a_chain->callback_delete(a_chain);
    dap_config_close(a_chain->config);
    if (DAP_CHAIN_PVT(a_chain)) {
        DAP_DEL_MULTY(DAP_CHAIN_PVT(a_chain)->file_storage_dir, DAP_CHAIN_PVT(a_chain));
    }
    DAP_DEL_MULTY(a_chain->name, a_chain->net_name, a_chain->datum_types, a_chain->autoproc_datum_types,
                  a_chain->authorized_nodes_addrs, a_chain->_inheritor);
    pthread_rwlock_destroy(&a_chain->rwlock);
    pthread_rwlock_destroy(&a_chain->cell_rwlock);
    DAP_DELETE(a_chain);
}

/**
 * @brief dap_chain_get_atom_by_hash
 * @param a_chain
 * @param a_atom_hash
 * @param a_atom_size
 * @return
 */
dap_chain_atom_ptr_t dap_chain_get_atom_by_hash(dap_chain_t * a_chain, dap_chain_hash_fast_t * a_atom_hash, size_t * a_atom_size)
{
    dap_chain_atom_ptr_t l_ret = NULL;
    dap_chain_cell_t *l_cell, *l_iter_tmp;
    HASH_ITER(hh, a_chain->cells, l_cell, l_iter_tmp) {
        dap_chain_atom_iter_t * l_iter = a_chain->callback_atom_iter_create(a_chain, l_cell->id, 0);
        l_ret = a_chain->callback_atom_find_by_hash(l_iter, a_atom_hash, a_atom_size);
        a_chain->callback_atom_iter_delete(l_iter);
        if (l_ret)
            break;
    }
    return l_ret;
}

/**
 * @brief dap_chain_find_by_id
 * @param a_chain_net_id
 * @param a_chain_id
 * @param a_cell_id
 * @return
 */
dap_chain_t * dap_chain_find_by_id(dap_chain_net_id_t a_chain_net_id,dap_chain_id_t a_chain_id)
{
    dap_chain_item_id_t l_chain_item_id = {
        .id = a_chain_id,
        .net_id = a_chain_net_id,
    };
    dap_chain_item_t * l_ret_item = NULL;
    pthread_rwlock_rdlock(&s_chain_items_rwlock);
    HASH_FIND(hh,s_chain_items,&l_chain_item_id,sizeof(dap_chain_item_id_t),l_ret_item);
    pthread_rwlock_unlock(&s_chain_items_rwlock);
    return l_ret_item ? l_ret_item->chain : NULL;
}

/**
 * @brief s_chain_type_from_str
 * get dap_chain_type_t value by str value a_type_str
 * @param a_type_str str values:token,emission,transaction,ca
 * @return dap_chain_type_t 
 */
static dap_chain_type_t s_chain_type_from_str(const char *a_type_str)
{
    if(!dap_strcmp(a_type_str, "token")) {
        return CHAIN_TYPE_TOKEN;
    }
    if(!dap_strcmp(a_type_str, "emission")) {
        return CHAIN_TYPE_EMISSION;
    }
    if(!dap_strcmp(a_type_str, "transaction")) {
        return CHAIN_TYPE_TX;
    }
    if(!dap_strcmp(a_type_str, "ca")) {
        return CHAIN_TYPE_CA;
    }
    if(!dap_strcmp(a_type_str, "signer")) {
	    return CHAIN_TYPE_SIGNER;
    }
    if (!dap_strcmp(a_type_str, "decree"))
        return CHAIN_TYPE_DECREE;
    if (!dap_strcmp(a_type_str, "anchor"))
        return CHAIN_TYPE_ANCHOR;
    return CHAIN_TYPE_INVALID;
}


/**
 * @brief s_chain_type_convert
 * convert dap_chain_type_t to  DAP_CNAIN* constants
 * @param a_type - dap_chain_type_t a_type [CHAIN_TYPE_TOKEN, CHAIN_TYPE_EMISSION, CHAIN_TYPE_TX]
 * @return uint16_t 
 */
static uint16_t s_chain_type_convert(dap_chain_type_t a_type)
{
    switch (a_type) {
    case CHAIN_TYPE_TOKEN: 
        return DAP_CHAIN_DATUM_TOKEN;
    case CHAIN_TYPE_EMISSION:
        return DAP_CHAIN_DATUM_TOKEN_EMISSION;
    case CHAIN_TYPE_TX:
        return DAP_CHAIN_DATUM_TX;
    case CHAIN_TYPE_CA:
        return DAP_CHAIN_DATUM_CA;
	case CHAIN_TYPE_SIGNER:
		return DAP_CHAIN_DATUM_SIGNER;
    case CHAIN_TYPE_DECREE:
        return DAP_CHAIN_DATUM_DECREE;
    case CHAIN_TYPE_ANCHOR:
        return DAP_CHAIN_DATUM_ANCHOR;
    default:
        return DAP_CHAIN_DATUM_CUSTOM;
    }
}

/**
 * @brief s_datum_type_from_str
 * get datum type (DAP_CHAIN_DATUM_TOKEN, DAP_CHAIN_DATUM_TOKEN_EMISSION, DAP_CHAIN_DATUM_TX) by str value
 * @param a_type_str datum type in string value (token,emission,transaction)
 * @return uint16_t 
 */
static uint16_t s_datum_type_from_str(const char *a_type_str)
{
    return s_chain_type_convert(s_chain_type_from_str(a_type_str));
}
/**
 * @brief s_datum_type_convert
 * convert uint16_t to  dap_chain_type_t
 * @param a_type - uint16_t a_type [DAP_CHAIN_DATUM_TOKEN, DAP_CHAIN_DATUM_TOKEN_EMISSION, DAP_CHAIN_DATUM_TX]
 * @return dap_chain_type_t 
 */

static dap_chain_type_t s_datum_type_convert(uint16_t a_type)
{
    switch (a_type) {
    case DAP_CHAIN_DATUM_TOKEN: 
        return CHAIN_TYPE_TOKEN;
    case DAP_CHAIN_DATUM_TOKEN_EMISSION:
        return CHAIN_TYPE_EMISSION;
    case DAP_CHAIN_DATUM_TX:
        return CHAIN_TYPE_TX;
    case DAP_CHAIN_DATUM_CA:
        return CHAIN_TYPE_CA;
	case DAP_CHAIN_DATUM_SIGNER:
		return CHAIN_TYPE_SIGNER;
    case DAP_CHAIN_DATUM_DECREE:
        return CHAIN_TYPE_DECREE;
    case DAP_CHAIN_DATUM_ANCHOR:
        return CHAIN_TYPE_ANCHOR;
    default:
        return CHAIN_TYPE_INVALID;
    }
}

/**
 * @brief s_chain_in_chain_types
 * looks for a type (chain_type) in an array of types (*chain_types)
 * @param chain_type		- the type we are looking for
 * @param *chain_types		- array of types in which we are looking for
 * @param chain_types_count	- number of elements in the array *chain_types
 * @return true or false
 */
static bool s_chain_in_chain_types(dap_chain_type_t chain_type, dap_chain_type_t *chain_types, uint16_t chain_types_count)
{
	for (uint16_t i = 0; i < chain_types_count; i++)
		if (chain_types[i] == chain_type)
			return (true);
	return (false);
}

/**
 * @brief s_datum_in_chain_types
 * looks for a type (chain_type) in an array of types (*chain_types)
 * @param datum_type		- the type we are looking for
 * @param *chain_types		- array of types in which we are looking for
 * @param chain_types_count	- number of elements in the array *chain_types
 * @return true or false
 */
static bool s_datum_in_chain_types(uint16_t datum_type, dap_chain_type_t *chain_types, uint16_t chain_types_count)
{
	for (uint16_t i = 0; i < chain_types_count; i++)
		if (s_chain_type_convert(chain_types[i]) == datum_type)
			return (true);
	return (false);
}

/**
 * @brief dap_chain_load_from_cfg
 * Loading chain from config file
 * @param a_chain_net_name - chain name, taken from config, for example - "home21-network"
 * @param a_chain_net_id - dap_chain_net_id_t chain network identification
 * @param a_chain_cfg_name chain config name, for example "network/home21-network/chain-0"
 * @return dap_chain_t* 
 */
dap_chain_t *dap_chain_load_from_cfg(const char *a_chain_net_name, dap_chain_net_id_t a_chain_net_id, dap_config_t *a_cfg)
{
    if (!a_chain_net_name || !a_cfg)
        return NULL;
    dap_chain_id_t l_chain_id = { };
    const char *l_chain_name    = dap_config_get_item_str(a_cfg, "chain", "name"),
               *l_chain_id_str  = dap_config_get_item_str(a_cfg, "chain", "id");
    if (!l_chain_name || !l_chain_id_str || dap_chain_id_parse(l_chain_id_str, &l_chain_id) )
        return log_it(L_ERROR, "Invalid chain name and/or id, fix \"%s\"", a_cfg->path), NULL;

    log_it (L_INFO, "Loading chain %s, id 0x%016"DAP_UINT64_FORMAT_x": \"%s\" for net \"%s\" from config \"%s\"",
                    l_chain_name, l_chain_id.uint64, l_chain_id_str, a_chain_net_name, a_cfg->path);

    dap_chain_t *l_chain = dap_chain_create(a_chain_net_name, l_chain_name, a_chain_net_id, l_chain_id);
    if (!l_chain)
        return log_it(L_ERROR, "Can't create this chain!"), NULL;
    if ( dap_chain_cs_create(l_chain, a_cfg) )
        return log_it (L_ERROR, "Can't init consensus \"%s\" for chain \"%s\"",
                                dap_config_get_item_str_default(a_cfg, "chain", "consensus", "<unknown>"), l_chain_name),
            dap_chain_delete(l_chain), NULL;

    log_it (L_INFO, "Consensus %s initialized for chain id 0x%016"DAP_UINT64_FORMAT_x,
                    dap_config_get_item_str(a_cfg, "chain", "consensus"), l_chain_id.uint64);

    if ( dap_config_get_item_str_default(a_cfg, "files", "storage_dir", NULL) )
    {
        DAP_CHAIN_PVT(l_chain)->file_storage_dir = dap_config_get_item_path( a_cfg, "files", "storage_dir" );
        if (!dap_dir_test(DAP_CHAIN_PVT(l_chain)->file_storage_dir))
            dap_mkdir_with_parents(DAP_CHAIN_PVT(l_chain)->file_storage_dir);
    } else
        log_it (L_INFO, "Not set file storage path, will not stored in files");

    if (!l_chain->cells)
        dap_chain_cell_create_fill( l_chain, (dap_chain_cell_id_t){ .uint64 = 0 } );
    l_chain->config = a_cfg;
    l_chain->load_priority = dap_config_get_item_uint16_default(a_cfg, "chain", "load_priority", 100);

    uint16_t l_datum_types_count = 0, l_default_datum_types_count = 0, i, j;
    const char  **l_datum_types = dap_config_get_array_str(a_cfg, "chain", "datum_types", &l_datum_types_count),
                **l_default_datum_types = dap_config_get_array_str(a_cfg, "chain", "default_datum_types", &l_default_datum_types_count);

    if ( l_datum_types && l_datum_types_count )
    {
        l_chain->datum_types = DAP_NEW_Z_COUNT(dap_chain_type_t, l_datum_types_count);
        if ( !l_chain->datum_types )
            return log_it(L_CRITICAL, "%s", c_error_memory_alloc), dap_chain_delete(l_chain), NULL;

        for (i = 0; i < l_datum_types_count; i++)
        {
            dap_chain_type_t l_chain_type = s_chain_type_from_str(l_datum_types[i]);
            if (l_chain_type != CHAIN_TYPE_INVALID)
                l_chain->datum_types[l_chain->datum_types_count++] = l_chain_type;
        }
    } else
        log_it(L_WARNING, "Can't read chain datum types for chain %s", l_chain_id_str);

    // add default datum types present
    if ( l_default_datum_types && l_default_datum_types_count )
    {
        l_chain->default_datum_types = DAP_NEW_Z_COUNT(dap_chain_type_t, l_default_datum_types_count);
        if ( !l_chain->default_datum_types ) {
            return log_it(L_CRITICAL, "%s", c_error_memory_alloc), dap_chain_delete(l_chain), NULL;
        }
        for (i = 0; i < l_default_datum_types_count; i++)
        {
            dap_chain_type_t l_chain_type = s_chain_type_from_str(l_default_datum_types[i]);
            if (l_chain_type != CHAIN_TYPE_INVALID
            && s_chain_in_chain_types(l_chain_type, l_chain->datum_types, l_chain->datum_types_count))// <<--- check this chain_type in readed datum_types
                l_chain->default_datum_types[l_chain->default_datum_types_count++] = l_chain_type;
        }
    } else
        log_it(L_WARNING, "Can't read chain default datum types for chain %s", l_chain_id_str);

    l_datum_types = dap_config_get_array_str(a_cfg, "chain", "mempool_auto_types", &l_datum_types_count);
    // add datum types for autoproc
    if (l_datum_types && l_datum_types_count)
    {
        l_chain->autoproc_datum_types = DAP_NEW_Z_COUNT(uint16_t, l_chain->datum_types_count);
        if ( !l_chain->autoproc_datum_types ) {
            return log_it(L_CRITICAL, "%s", c_error_memory_alloc), dap_chain_delete(l_chain), NULL;
        }
        for (i = 0; i < l_datum_types_count; i++)
        {
            if (!dap_strcmp(l_datum_types[i], "all") && l_chain->datum_types_count)
            {
                for (j = 0; j < l_chain->datum_types_count; j++)
                    l_chain->autoproc_datum_types[j] = s_chain_type_convert(l_chain->datum_types[j]);
                l_chain->autoproc_datum_types_count = l_chain->datum_types_count;
                break;
            }
            uint16_t l_chain_type = s_datum_type_from_str(l_datum_types[i]);
            if (l_chain_type != DAP_CHAIN_DATUM_CUSTOM
            &&	s_datum_in_chain_types(l_chain_type, l_chain->datum_types, l_chain->datum_types_count))// <<--- check this chain_datum_type in readed datum_types
                l_chain->autoproc_datum_types[l_chain->autoproc_datum_types_count++] = l_chain_type;
        }
    } else
        log_it(L_WARNING, "Can't read chain mempool auto types for chain %s", l_chain_id_str);
    if (l_chain->id.uint64 == 0) {  // for zerochain only
        if (dap_config_stream_addrs_parse(a_cfg, "chain", "authorized_nodes_addrs", &l_chain->authorized_nodes_addrs, &l_chain->authorized_nodes_count)) {
            dap_chain_delete(l_chain);
            return NULL;
        }
        if (!l_chain->authorized_nodes_count)
            log_it(L_WARNING, "Can't read PoA nodes addresses");
    }
    return l_chain;
}


/**
 * @brief dap_chain_has_file_store
 * @param a_chain
 * @return
 */
bool dap_chain_has_file_store(dap_chain_t * a_chain)
{
    return  DAP_CHAIN_PVT(a_chain)->file_storage_dir != NULL;
}


/**
 * @brief get type of chain
 *
 * @param l_chain
 * @return char*
 */
const char *dap_chain_get_cs_type(dap_chain_t *l_chain)
{
    if (!l_chain){
        log_it(L_DEBUG, "dap_get_chain_type. Chain object is 0");
        return NULL;
    }
    return (const char *)DAP_CHAIN_PVT(l_chain)->cs_name;
}

/**
 * @brief dap_chain_save_all
 * @param l_chain
 * @return
 */
int dap_chain_save_all(dap_chain_t *l_chain)
{
    int l_ret = 0;
    pthread_rwlock_rdlock(&l_chain->cell_rwlock);
    dap_chain_cell_t *l_item = NULL, *l_item_tmp = NULL;
    HASH_ITER(hh,l_chain->cells,l_item,l_item_tmp){
        if(dap_chain_cell_file_update(l_item) <= 0)
            l_ret++;
    }
    pthread_rwlock_unlock(&l_chain->cell_rwlock);
    return l_ret;
}

//send chain load_progress data to notify socket
bool download_notify_callback(dap_chain_t* a_chain) {
    json_object* l_chain_info = json_object_new_object();
    json_object_object_add(l_chain_info, "class", json_object_new_string("chain_init"));
    json_object_object_add(l_chain_info, "net", json_object_new_string(a_chain->net_name));
    json_object_object_add(l_chain_info, "chain_id", json_object_new_uint64(a_chain->id.uint64));
    json_object_object_add(l_chain_info, "load_progress", json_object_new_int(a_chain->load_progress));
    dap_notify_server_send_mt(json_object_get_string(l_chain_info));
    log_it(L_DEBUG, "Loading net \"%s\", chain \"%s\", ID 0x%016"DAP_UINT64_FORMAT_x " [%d%%]",
                    a_chain->net_name, a_chain->name, a_chain->id.uint64, a_chain->load_progress);
    json_object_put(l_chain_info);
    return true;
}

/**
 * @brief dap_chain_load_all
 * @param l_chain
 * @return
 */
int dap_chain_load_all(dap_chain_t *a_chain)
{
    int l_ret = 0;
    if (!a_chain)
        return -2;
    if (a_chain->callback_load_from_gdb) {
        a_chain->is_mapped = false;
        a_chain->callback_load_from_gdb(a_chain);
        return 0;
    }
    char *l_storage_dir = DAP_CHAIN_PVT(a_chain)->file_storage_dir;
    if (!l_storage_dir)
        return 0;
    DIR *l_dir = opendir(l_storage_dir);
    if (!l_dir) {
        log_it(L_ERROR, "Cannot open directory %s", DAP_CHAIN_PVT(a_chain)->file_storage_dir);
        return -3;
    }
    for (struct dirent *l_dir_entry = readdir(l_dir); l_dir_entry != NULL; l_dir_entry = readdir(l_dir)) {
        const char * l_filename = l_dir_entry->d_name;
        const char l_suffix[] = ".dchaincell";
        size_t l_suffix_len = strlen(l_suffix);
        if (!strncmp(l_filename + strlen(l_filename) - l_suffix_len, l_suffix, l_suffix_len)) {
            uint64_t l_cell_id_uint64 = 0;
            sscanf(l_filename, "%"DAP_UINT64_FORMAT_x".dchaincell", &l_cell_id_uint64);
            dap_chain_cell_t *l_cell = dap_chain_cell_create_fill(a_chain, (dap_chain_cell_id_t){ .uint64 = l_cell_id_uint64 });
            dap_timerfd_t* l_download_notify_timer = dap_timerfd_start(5000, (dap_timerfd_callback_t)download_notify_callback, a_chain);
            l_ret += dap_chain_cell_load(a_chain, l_cell);
            if ( DAP_CHAIN_PVT(a_chain)->need_reorder ) {
#ifdef DAP_OS_WINDOWS
                strcat(l_cell->file_storage_path, ".new");
                if (remove(l_cell->file_storage_path) == -1) {
                    log_it(L_ERROR, "File %s doesn't exist", l_cell->file_storage_path);
                }
                *(l_cell->file_storage_path + strlen(l_cell->file_storage_path) - 4) = '\0';
#else
                const char *l_filename_backup = dap_strdup_printf("%s.unsorted", l_cell->file_storage_path);
                if (remove(l_filename_backup) == -1) {
                    log_it(L_ERROR, "File %s doesn't exist", l_filename_backup);
                }
                if (rename(l_cell->file_storage_path, l_filename_backup)) {
                    log_it(L_ERROR, "Couldn't rename %s to %s", l_cell->file_storage_path, l_filename_backup);
                }
                DAP_DELETE(l_filename_backup);
#endif
            }
            dap_timerfd_delete_mt(l_download_notify_timer->worker, l_download_notify_timer->esocket_uuid);
            download_notify_callback(a_chain);
        }
    }
    closedir(l_dir);
    return l_ret;
}

/**
 * @brief dap_chain_init_net_cfg_name
 * @param a_chain_net_cfg_name
 * @return
 */
dap_chain_t * dap_chain_init_net_cfg_name(const char * a_chain_net_cfg_name)
{
    UNUSED( a_chain_net_cfg_name);
    return NULL;
}



/**
 * @brief dap_chain_close
 * @param a_chain
 */
void dap_chain_close(dap_chain_t * a_chain)
{
    if(a_chain){
        if(a_chain->callback_delete)
            a_chain->callback_delete(a_chain);
    }else
        log_it(L_WARNING,"Tried to close null pointer");
}


/**
 * @brief dap_chain_info_dump_log
 * @param a_chain
 */
void dap_chain_info_dump_log(dap_chain_t * a_chain)
{
    UNUSED(a_chain);
}

/**
 * @brief Add a callback to monitor changes in the chain
 * @param a_chain
 * @param a_callback
 * @param a_arg
 */
void dap_chain_add_callback_notify(dap_chain_t *a_chain, dap_chain_callback_notify_t a_callback, dap_proc_thread_t *a_thread, void *a_callback_arg)
{
    if(!a_chain){
        log_it(L_ERROR, "NULL chain passed to dap_chain_add_callback_notify()");
        return;
    }
    if(!a_callback){
        log_it(L_ERROR, "NULL callback passed to dap_chain_add_callback_notify()");
        return;
    }
    dap_chain_atom_notifier_t * l_notifier = DAP_NEW_Z(dap_chain_atom_notifier_t);
    if (l_notifier == NULL){
        log_it(L_ERROR, "Can't allocate memory for notifier in dap_chain_add_callback_notify()");
        return;
    }

    l_notifier->callback = a_callback;
    l_notifier->proc_thread = a_thread;
    l_notifier->arg = a_callback_arg;
    pthread_rwlock_wrlock(&a_chain->rwlock);
    a_chain->atom_notifiers = dap_list_append(a_chain->atom_notifiers, l_notifier);
    pthread_rwlock_unlock(&a_chain->rwlock);
}

int dap_chain_add_callback_timer(dap_chain_t *a_chain, dap_chain_callback_blockchain_timer_t a_callback, void *a_callback_arg)
{
    dap_return_val_if_fail(a_chain && a_callback, -1);
    dap_chain_blockchain_timer_notifier_t *l_notifier = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_blockchain_timer_notifier_t, -2);
    l_notifier->callback = a_callback;
    l_notifier->arg = a_callback_arg;
    pthread_rwlock_wrlock(&a_chain->rwlock);
    a_chain->blockchain_timers = dap_list_append(a_chain->blockchain_timers, l_notifier);
    pthread_rwlock_unlock(&a_chain->rwlock);
    return 0;
}


/**
 * @brief Add a callback to monitor adding new atom into index
 * @param a_chain
 * @param a_callback
 * @param a_arg
 */
void dap_chain_add_callback_datum_index_notify(dap_chain_t *a_chain, dap_chain_callback_datum_notify_t a_callback, dap_proc_thread_t *a_thread, void *a_callback_arg)
{
    if(!a_chain){
        log_it(L_ERROR, "NULL chain passed to dap_chain_add_callback_notify()");
        return;
    }
    if(!a_callback){
        log_it(L_ERROR, "NULL callback passed to dap_chain_add_callback_notify()");
        return;
    }
    dap_chain_datum_notifier_t * l_notifier = DAP_NEW_Z(dap_chain_datum_notifier_t);
    if (l_notifier == NULL){
        log_it(L_ERROR, "Can't allocate memory for notifier in dap_chain_add_callback_notify()");
        return;
    }

    l_notifier->callback = a_callback;
    l_notifier->proc_thread = a_thread;
    l_notifier->arg = a_callback_arg;
    pthread_rwlock_wrlock(&a_chain->rwlock);
    a_chain->datum_notifiers = dap_list_append(a_chain->datum_notifiers, l_notifier);
    pthread_rwlock_unlock(&a_chain->rwlock);
}

/**
 * @brief Add a callback to monitor adding new atom into index
 * @param a_chain
 * @param a_callback
 * @param a_arg
 */
void dap_chain_add_callback_datum_removed_from_index_notify(dap_chain_t *a_chain, dap_chain_callback_datum_removed_notify_t a_callback, dap_proc_thread_t *a_thread, void *a_callback_arg)
{
    if(!a_chain){
        log_it(L_ERROR, "NULL chain passed to dap_chain_add_callback_notify()");
        return;
    }
    if(!a_callback){
        log_it(L_ERROR, "NULL callback passed to dap_chain_add_callback_notify()");
        return;
    }
    dap_chain_datum_removed_notifier_t * l_notifier = DAP_NEW_Z(dap_chain_datum_removed_notifier_t);
    if (l_notifier == NULL){
        log_it(L_ERROR, "Can't allocate memory for notifier in dap_chain_add_callback_notify()");
        return;
    }

    l_notifier->callback = a_callback;
    l_notifier->proc_thread = a_thread;
    l_notifier->arg = a_callback_arg;
    pthread_rwlock_wrlock(&a_chain->rwlock);
    a_chain->datum_removed_notifiers = dap_list_append(a_chain->datum_removed_notifiers, l_notifier);
    pthread_rwlock_unlock(&a_chain->rwlock);
}

/**
 * @brief Add a callback to monitor blocks received enough confirmations
 * @param a_chain
 * @param a_callback
 * @param a_arg
 */
void dap_chain_atom_confirmed_notify_add(dap_chain_t *a_chain, dap_chain_callback_notify_t a_callback, void *a_arg, uint64_t a_conf_cnt)
{
    if(!a_chain){
        log_it(L_ERROR, "NULL chain passed to dap_chain_add_callback_notify()");
        return;
    }
    if(!a_callback){
        log_it(L_ERROR, "NULL callback passed to dap_chain_add_callback_notify()");
        return;
    }
    dap_chain_atom_confirmed_notifier_t * l_notifier = DAP_NEW_Z(dap_chain_atom_confirmed_notifier_t);
    if (l_notifier == NULL){
        log_it(L_ERROR, "Can't allocate memory for notifier in dap_chain_add_callback_notify()");
        return;
    }
    l_notifier->block_notify_cnt = a_conf_cnt;
    l_notifier->callback = a_callback;
    l_notifier->arg = a_arg;
    pthread_rwlock_wrlock(&a_chain->rwlock);
    a_chain->atom_confirmed_notifiers = dap_list_append(a_chain->atom_confirmed_notifiers, l_notifier);
    pthread_rwlock_unlock(&a_chain->rwlock);
}

/**
 * @brief dap_chain_get_last_atom_hash
 * @param a_chain
 * @param a_atom_hash
 * @return
 */
bool dap_chain_get_atom_last_hash_num(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, dap_hash_fast_t *a_atom_hash, uint64_t *a_atom_num)
{
    dap_return_val_if_fail(a_atom_hash || a_atom_num, false);
    dap_chain_atom_iter_t *l_iter = a_chain->callback_atom_iter_create(a_chain, a_cell_id, NULL);
    if (!l_iter)
        return false;
    a_chain->callback_atom_iter_get(l_iter, DAP_CHAIN_ITER_OP_LAST, NULL);
    if (a_atom_hash)
        *a_atom_hash = l_iter->cur_hash ? *l_iter->cur_hash : (dap_hash_fast_t){0};
    if (a_atom_num)
        *a_atom_num = l_iter->cur_num;
    a_chain->callback_atom_iter_delete(l_iter);
    return true;
}

struct chain_thread_notifier {
    dap_chain_callback_notify_t callback;
    void *callback_arg;
    dap_chain_t *chain;
    dap_chain_cell_id_t cell_id;
    dap_hash_fast_t hash;
    void *atom;
    size_t atom_size;
    dap_time_t atom_time;
};

struct chain_thread_datum_notifier {
    dap_chain_callback_datum_notify_t callback;
    void *callback_arg;
    dap_chain_t *chain;
    dap_chain_cell_id_t cell_id;
    dap_hash_fast_t hash;
    dap_hash_fast_t atom_hash;
    void *datum;
    uint32_t action;
    dap_chain_net_srv_uid_t uid;
    size_t datum_size;
    int ret_code;
};

struct chain_thread_datum_removed_notifier {
    dap_chain_callback_datum_removed_notify_t callback;
    void *callback_arg;
    dap_chain_t *chain;
    dap_chain_cell_id_t cell_id;
    dap_hash_fast_t hash;
    dap_chain_datum_t *datum;
    int ret_code;
};

static bool s_notify_atom_on_thread(void *a_arg)
{
    struct chain_thread_notifier *l_arg = a_arg;
    assert(l_arg->atom && l_arg->callback);
    l_arg->callback(l_arg->callback_arg, l_arg->chain, l_arg->cell_id, &l_arg->hash, l_arg->atom, l_arg->atom_size, l_arg->atom_time);
    if ( !l_arg->chain->is_mapped )
        DAP_DELETE(l_arg->atom);
    DAP_DELETE(l_arg);
    return false;
}

static bool s_notify_datum_on_thread(void *a_arg)
{
    struct chain_thread_datum_notifier *l_arg = a_arg;
    assert(l_arg->datum && l_arg->callback);
    l_arg->callback(l_arg->callback_arg, &l_arg->hash, &l_arg->atom_hash, l_arg->datum, l_arg->datum_size, l_arg->ret_code, l_arg->action, l_arg->uid);
    if ( !l_arg->chain->is_mapped )
        DAP_DELETE(l_arg->datum);
    DAP_DELETE(l_arg);
    return false;
}


static bool s_notify_datum_removed_on_thread(void *a_arg)
{
    struct chain_thread_datum_removed_notifier *l_arg = a_arg;
    assert(l_arg->callback);
    l_arg->callback(l_arg->callback_arg, &l_arg->hash, l_arg->datum);
    DAP_DELETE(l_arg);
    return false;
}

ssize_t dap_chain_atom_save(dap_chain_cell_t *a_chain_cell, const uint8_t *a_atom, size_t a_atom_size, dap_hash_fast_t *a_new_atom_hash)
{
    dap_return_val_if_fail(a_chain_cell && a_chain_cell->chain, -1);
    dap_chain_t *l_chain = a_chain_cell->chain;

    if (a_new_atom_hash) { // Atom is new and need to be distributed for the net
        dap_cluster_t *l_net_cluster = dap_cluster_find(dap_guuid_compose(l_chain->net_id.uint64, 0));
        if (l_net_cluster) {
            size_t l_pkt_size = a_atom_size + sizeof(dap_chain_ch_pkt_t);
            dap_chain_ch_pkt_t *l_pkt = dap_chain_ch_pkt_new(l_chain->net_id, l_chain->id,
                                                             a_chain_cell->id, a_atom, a_atom_size,
                                                             DAP_CHAIN_CH_PKT_VERSION_CURRENT);
            if (l_pkt) {
                dap_gossip_msg_issue(l_net_cluster, DAP_CHAIN_CH_ID, l_pkt, l_pkt_size, a_new_atom_hash);
                DAP_DELETE(l_pkt);
            }
        }
    }
    return dap_chain_cell_file_append(a_chain_cell, a_atom, a_atom_size);
}

/**
 * @brief dap_cert_chain_file_save
 * @param datum
 */
int dap_cert_chain_file_save(dap_chain_datum_t *datum, char *net_name)
{
    const char *s_system_chain_ca_dir = dap_config_get_item_str(g_config, "resources", "chain_ca_folder");
    if(dap_strlen(s_system_chain_ca_dir) == 0) {
        log_it(L_ERROR, "Not found 'chain_ca_folder' in .cfg file");
        return -1;
    }
    dap_cert_t *cert = dap_cert_mem_load(datum->data, datum->header.data_size);
    if(!cert) {
        log_it(L_ERROR, "Can't load cert, size: %d", datum->header.data_size);
        return -1;
    }
    const char *cert_name = cert->name;
    size_t cert_path_length = dap_strlen(net_name) + dap_strlen(cert_name) + 9 + dap_strlen(s_system_chain_ca_dir);
    char cert_path[cert_path_length];
    snprintf(cert_path, cert_path_length, "%s/%s/%s.dcert", s_system_chain_ca_dir, net_name, cert_name);
    // In cert_path resolve all `..` and `.`s
    char *cert_path_c = dap_canonicalize_path(cert_path, NULL);
    // Protect the ca folder from using "/.." in cert_name
    if(dap_strncmp(s_system_chain_ca_dir, cert_path_c, dap_strlen(s_system_chain_ca_dir))) {
        log_it(L_ERROR, "Cert path '%s' is not in ca dir: %s", cert_path_c, s_system_chain_ca_dir);
        dap_cert_delete(cert);
        DAP_DELETE(cert_path_c);
        return -1;
    }
    int l_ret = dap_cert_file_save(cert, cert_path_c);
    dap_cert_delete(cert);
    DAP_DELETE(cert_path_c);
    return l_ret;
}

const char* dap_chain_get_path(dap_chain_t *a_chain)
{
    return DAP_CHAIN_PVT(a_chain)->file_storage_dir;
}

void dap_chain_atom_notify(dap_chain_cell_t *a_chain_cell, dap_hash_fast_t *a_hash, const uint8_t *a_atom, size_t a_atom_size, dap_time_t a_atom_time)
{
#ifdef DAP_CHAIN_BLOCKS_TEST
    return;
#endif

    if (a_chain_cell->id.uint64 == 0)
        a_chain_cell->chain->blockchain_time = a_atom_time;
    dap_list_t *l_iter;
    DL_FOREACH(a_chain_cell->chain->blockchain_timers, l_iter) {
        dap_chain_blockchain_timer_notifier_t *l_notifier = l_iter->data;
        l_notifier->callback(a_chain_cell->chain, a_atom_time, l_notifier->arg, false);
    }
    DL_FOREACH(a_chain_cell->chain->atom_notifiers, l_iter) {
        dap_chain_atom_notifier_t *l_notifier = (dap_chain_atom_notifier_t*)l_iter->data;
        struct chain_thread_notifier *l_arg = DAP_NEW_Z(struct chain_thread_notifier);
        if (!l_arg) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            continue;
        }
        *l_arg = (struct chain_thread_notifier) {
            .callback = l_notifier->callback, .callback_arg = l_notifier->arg,
            .chain = a_chain_cell->chain,     .cell_id = a_chain_cell->id,
            .hash = *a_hash,
            .atom = a_chain_cell->chain->is_mapped ? (byte_t*)a_atom : DAP_DUP_SIZE((byte_t*)a_atom, a_atom_size),
            .atom_size = a_atom_size,
            .atom_time = a_atom_time
        };
        dap_proc_thread_callback_add_pri(l_notifier->proc_thread, s_notify_atom_on_thread, l_arg, DAP_QUEUE_MSG_PRIORITY_LOW);
    }
}

void dap_chain_atom_remove_notify(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, dap_time_t a_prev_atom_time)
{
#ifdef DAP_CHAIN_BLOCKS_TEST
    return;
#endif
    if (a_cell_id.uint64 == 0)
        a_chain->blockchain_time = a_prev_atom_time;
    dap_list_t *l_iter;
    DL_FOREACH(a_chain->blockchain_timers, l_iter) {
        dap_chain_blockchain_timer_notifier_t *l_notifier = l_iter->data;
        l_notifier->callback(a_chain, a_prev_atom_time, l_notifier->arg, true);
    }
}


void dap_chain_datum_notify(dap_chain_cell_t *a_chain_cell,  dap_hash_fast_t *a_hash, dap_hash_fast_t *a_atom_hash, const uint8_t *a_datum, size_t a_datum_size, int a_ret_code, uint32_t a_action, dap_chain_net_srv_uid_t a_uid)
{
#ifdef DAP_CHAIN_BLOCKS_TEST
    return;
#endif

    dap_list_t *l_iter;
    DL_FOREACH(a_chain_cell->chain->datum_notifiers, l_iter) {
        dap_chain_datum_notifier_t *l_notifier = (dap_chain_datum_notifier_t*)l_iter->data;
        struct chain_thread_datum_notifier *l_arg = DAP_NEW_Z(struct chain_thread_datum_notifier);
        if (!l_arg) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            continue;
        }
        *l_arg = (struct chain_thread_datum_notifier) {
            .callback = l_notifier->callback, .callback_arg = l_notifier->arg,
            .chain = a_chain_cell->chain,     .cell_id = a_chain_cell->id,
            .hash = *a_hash,
            .atom_hash = *a_atom_hash,
            .datum = a_chain_cell->chain->is_mapped ? (byte_t*)a_datum
                                                    : DAP_DUP_SIZE((byte_t *)a_datum, a_datum_size),
            .datum_size = a_datum_size,
            .ret_code = a_ret_code,
            .action = a_action,
            .uid =  a_uid};
        dap_proc_thread_callback_add_pri(l_notifier->proc_thread, s_notify_datum_on_thread, l_arg, DAP_QUEUE_MSG_PRIORITY_LOW);
    }
}

void dap_chain_datum_removed_notify(dap_chain_cell_t *a_chain_cell,  dap_hash_fast_t *a_hash, dap_chain_datum_t *a_datum) {
#ifdef DAP_CHAIN_BLOCKS_TEST
    return;
#endif

    if ( !a_chain_cell->chain->datum_removed_notifiers )
        return;
    dap_list_t *l_iter;
    DL_FOREACH(a_chain_cell->chain->datum_removed_notifiers, l_iter) {
        dap_chain_datum_removed_notifier_t *l_notifier = (dap_chain_datum_removed_notifier_t*)l_iter->data;
        struct chain_thread_datum_removed_notifier *l_arg = DAP_NEW_Z(struct chain_thread_datum_removed_notifier);
        if (!l_arg) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            continue;
        }
        *l_arg = (struct chain_thread_datum_removed_notifier) {
            .callback = l_notifier->callback, .callback_arg = l_notifier->arg,
            .chain = a_chain_cell->chain,     .cell_id = a_chain_cell->id,
            .hash = *a_hash, .datum = a_datum};
        dap_proc_thread_callback_add_pri(l_notifier->proc_thread, s_notify_datum_removed_on_thread, l_arg, DAP_QUEUE_MSG_PRIORITY_LOW);
    }
}

void dap_chain_atom_add_from_threshold(dap_chain_t *a_chain) {
    if ( !a_chain->callback_atom_add_from_treshold )
        return;
    dap_chain_atom_ptr_t l_atom_treshold = NULL;
    do {
        size_t l_atom_treshold_size;
        l_atom_treshold = a_chain->callback_atom_add_from_treshold(a_chain, &l_atom_treshold_size);
    } while(l_atom_treshold);
}

const char *dap_chain_type_to_str(const dap_chain_type_t a_default_chain_type)
{
    switch (a_default_chain_type) {
        case CHAIN_TYPE_TOKEN:
            return "token";
        case CHAIN_TYPE_EMISSION:
            return "emission";
        case CHAIN_TYPE_TX:
            return "transaction";
        case CHAIN_TYPE_CA:
            return "ca";
        case CHAIN_TYPE_SIGNER:
            return "signer";
        case CHAIN_TYPE_DECREE:
            return "decree";
        case CHAIN_TYPE_ANCHOR:
            return "anchor";
        default:
            return "custom";
    }
}

const char *dap_datum_type_to_str(uint16_t a_datum_type)
{
    return dap_chain_type_to_str(s_datum_type_convert(a_datum_type));
}
