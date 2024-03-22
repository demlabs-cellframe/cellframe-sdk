/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Demlabs Application Protocol) the open source project

    DAP (Demlabs Application Protocol) is free software: you can redistribute it and/or modify
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
#include "dap_chain_pvt.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_config.h"
#include "dap_chain.h"
#include "dap_cert.h"
#include "dap_chain_cs.h"
#include "dap_cert_file.h"
#include <uthash.h>
#include <pthread.h>

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

static pthread_rwlock_t s_chain_items_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static dap_chain_item_t *s_chain_items = NULL;

int s_prepare_env();

/**
 * @brief dap_chain_init
 * @return
 */
int dap_chain_init(void)
{
    dap_cert_init();
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
    dap_chain_t *l_ret = DAP_NEW_Z(dap_chain_t);
    if ( !l_ret ) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;   
    }
    *l_ret = (dap_chain_t) {
            .rwlock     = PTHREAD_RWLOCK_INITIALIZER,
            .id         = a_chain_id,
            .net_id     = a_chain_net_id,
            .name       = dap_strdup(a_chain_name),
            .net_name   = dap_strdup(a_chain_net_name),
            .cell_rwlock    = PTHREAD_RWLOCK_INITIALIZER,
            .atom_notifiers = NULL
    };
    DAP_CHAIN_PVT_LOCAL_NEW(l_ret);

    dap_chain_item_t *l_ret_item = DAP_NEW_Z(dap_chain_item_t);
    if (!l_ret_item) {
        DAP_DELETE(l_ret->name);
        DAP_DELETE(l_ret->net_name);
        DAP_DELETE(l_ret);
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    *l_ret_item = (dap_chain_item_t) {
            .item_id    = { a_chain_id, a_chain_net_id },
            .chain      = l_ret
    };
    pthread_rwlock_wrlock(&s_chain_items_rwlock);
    HASH_ADD(hh, s_chain_items, item_id, sizeof(dap_chain_item_id_t), l_ret_item);
    pthread_rwlock_unlock(&s_chain_items_rwlock);
    return l_ret;
}

/**
 * @brief
 * delete dap chain object
 * @param a_chain dap_chain_t object
 */
void dap_chain_delete(dap_chain_t * a_chain)
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
    DAP_DEL_Z(a_chain->name);
    DAP_DEL_Z(a_chain->net_name);
    if (DAP_CHAIN_PVT(a_chain)){
        DAP_DEL_Z(DAP_CHAIN_PVT(a_chain)->file_storage_dir);
        DAP_DELETE(DAP_CHAIN_PVT(a_chain));
    }
    DAP_DELETE(a_chain->datum_types);
    DAP_DELETE(a_chain->autoproc_datum_types);
    if (a_chain->callback_delete)
        a_chain->callback_delete(a_chain);
    DAP_DEL_Z(a_chain->_inheritor);
    pthread_rwlock_destroy(&a_chain->rwlock);
    pthread_rwlock_destroy(&a_chain->cell_rwlock);
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
    return CHAIN_TYPE_LAST;
}

/**
 * @brief s_datum_type_from_str
 * get datum type (DAP_CHAIN_DATUM_TOKEN_DECL, DAP_CHAIN_DATUM_TOKEN_EMISSION, DAP_CHAIN_DATUM_TX) by str value
 * @param a_type_str datum type in string value (token,emission,transaction)
 * @return uint16_t 
 */
static uint16_t s_datum_type_from_str(const char *a_type_str)
{
    if(!dap_strcmp(a_type_str, "token")) {
        return DAP_CHAIN_DATUM_TOKEN_DECL;
    }
    if(!dap_strcmp(a_type_str, "emission")) {
        return DAP_CHAIN_DATUM_TOKEN_EMISSION;
    }
    if(!dap_strcmp(a_type_str, "transaction")) {
        return DAP_CHAIN_DATUM_TX;
    }
    if(!dap_strcmp(a_type_str, "ca")) {
        return DAP_CHAIN_DATUM_CA;
    }
    if (!dap_strcmp(a_type_str, "signer")) {
        return DAP_CHAIN_DATUM_SIGNER;
    }
    if (!dap_strcmp(a_type_str, "decree"))
        return DAP_CHAIN_DATUM_DECREE;
    if (!dap_strcmp(a_type_str, "anchor"))
        return DAP_CHAIN_DATUM_ANCHOR;
    return DAP_CHAIN_DATUM_CUSTOM;
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
        return DAP_CHAIN_DATUM_TOKEN_DECL;
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
dap_chain_t *dap_chain_load_from_cfg(const char *a_chain_net_name, dap_chain_net_id_t a_chain_net_id, const char *a_chain_cfg_name)
{
    log_it (L_DEBUG, "Loading chain from config \"%s\"", a_chain_cfg_name);

    if (a_chain_net_name)
	{
        dap_config_t *l_cfg = dap_config_open(a_chain_cfg_name);
        if (l_cfg)
		{
            dap_chain_t		*l_chain		= NULL;
            dap_chain_id_t	l_chain_id		= {};
            const char		*l_chain_id_str	= NULL;
            const char 		*l_chain_name	= NULL;

            // Recognize chains id
            if ( (l_chain_id_str = dap_config_get_item_str(l_cfg,"chain","id")) != NULL ) {
                if (dap_chain_id_parse(l_chain_id_str, &l_chain_id) != 0) {
                    dap_config_close(l_cfg);
                    return NULL;
                }
            } else {
                log_it (L_ERROR, "Wasn't found chain id string in config");
                dap_config_close(l_cfg);
                return NULL;
            }

            log_it (L_NOTICE, "Chain id 0x%016"DAP_UINT64_FORMAT_x"  ( \"%s\" )", l_chain_id.uint64, l_chain_id_str);

            // Read chain name
            if ( ( l_chain_name = dap_config_get_item_str(l_cfg,"chain","name") ) == NULL )
			{
                log_it (L_ERROR,"Can't read chain net name %s", l_chain_id_str);
                dap_config_close(l_cfg);
                return NULL;
            }

            l_chain =  dap_chain_create(a_chain_net_name, l_chain_name, a_chain_net_id, l_chain_id);
            if ( dap_chain_cs_create(l_chain, l_cfg) == 0 ) {

                log_it (L_NOTICE, "Consensus initialized for chain id 0x%016"DAP_UINT64_FORMAT_x, l_chain_id.uint64);

                if ( dap_config_get_item_str_default(l_cfg, "files","storage_dir", NULL) )
				{
                    DAP_CHAIN_PVT(l_chain)->file_storage_dir = (char*)dap_config_get_item_path( l_cfg , "files","storage_dir" );
                } else
                    log_it (L_INFO, "Not set file storage path, will not stored in files");

                if (!l_chain->cells)
				{
                    dap_chain_cell_id_t l_cell_id = {.uint64 = 0};
                    dap_chain_cell_create_fill(l_chain, l_cell_id);
                }
            } else {
                log_it (L_ERROR, "Can't init consensus \"%s\"",dap_config_get_item_str_default( l_cfg , "chain","consensus","NULL"));
                dap_chain_delete(l_chain);
                l_chain = NULL;
            }

            if (l_chain)
			{
				// load priority for chain
				l_chain->load_priority = dap_config_get_item_uint16_default(l_cfg, "chain", "load_priority", 100);

				char**		l_datum_types				= NULL;
				char**		l_default_datum_types		= NULL;
				uint16_t	l_datum_types_count			= 0;
				uint16_t	l_default_datum_types_count = 0;
				uint16_t	l_count_recognized			= 0;

				//		l_datum_types			=	(read chain datum types)
				//	||	l_default_datum_types	=	(read chain default datum types if datum types readed and if present default datum types)

				if (	(l_datum_types			= dap_config_get_array_str(l_cfg, "chain", "datum_types", &l_datum_types_count)) 					== NULL
				||		(l_default_datum_types	= dap_config_get_array_str(l_cfg, "chain", "default_datum_types", &l_default_datum_types_count))	== NULL )
				{
					if (!l_datum_types)
						log_it(L_WARNING, "Can't read chain datum types for chain %s", l_chain_id_str);
					else
						log_it(L_WARNING, "Can't read chain DEFAULT datum types for chain %s", l_chain_id_str);
					//dap_config_close(l_cfg);
					//return NULL;
				}

				// add datum types
                if (l_datum_types && l_datum_types_count > 0)
				{
					l_chain->datum_types = DAP_NEW_SIZE(dap_chain_type_t, l_datum_types_count * sizeof(dap_chain_type_t)); // TODO: pls check counter for recognized types before memory allocation!
                    if ( !l_chain->datum_types ) {
                        DAP_DELETE(l_chain);
                        log_it(L_CRITICAL, "Memory allocation error");
                        return NULL;
                    }
                    l_count_recognized = 0;
					for (uint16_t i = 0; i < l_datum_types_count; i++)
					{
						dap_chain_type_t l_chain_type = s_chain_type_from_str(l_datum_types[i]);
						if (l_chain_type != CHAIN_TYPE_LAST)
						{
							l_chain->datum_types[l_count_recognized] = l_chain_type;
							l_count_recognized++;
						}
					}
					l_chain->datum_types_count = l_count_recognized;
				} else
					l_chain->datum_types_count = 0;

				// add default datum types present
				if (l_default_datum_types && l_default_datum_types_count > 0)
				{
					l_chain->default_datum_types = DAP_NEW_SIZE(dap_chain_type_t, l_default_datum_types_count * sizeof(dap_chain_type_t)); // TODO: pls check counter for recognized types before memory allocation!
                    if ( !l_chain->default_datum_types ) {
                        if (l_chain->datum_types)
                            DAP_DELETE(l_chain->datum_types);
                        DAP_DELETE(l_chain);
                        log_it(L_CRITICAL, "Memory allocation error");
                        return NULL;
                    }
                    l_count_recognized = 0;
					for (uint16_t i = 0; i < l_default_datum_types_count; i++)
					{
						dap_chain_type_t l_chain_type = s_chain_type_from_str(l_default_datum_types[i]);
						if (l_chain_type != CHAIN_TYPE_LAST
						&& s_chain_in_chain_types(l_chain_type, l_chain->datum_types, l_chain->datum_types_count))// <<--- check this chain_type in readed datum_types
						{
							l_chain->default_datum_types[l_count_recognized] = l_chain_type;
							l_count_recognized++;
						}
					}
					l_chain->default_datum_types_count = l_count_recognized;
				} else
					l_chain->default_datum_types_count = 0;

				if ((l_datum_types = dap_config_get_array_str(l_cfg, "chain", "mempool_auto_types", &l_datum_types_count)) == NULL)
					log_it(L_WARNING, "Can't read chain mempool auto types for chain %s", l_chain_id_str);

				// add datum types for autoproc
				if (l_datum_types && l_datum_types_count)
				{
					l_chain->autoproc_datum_types = DAP_NEW_Z_SIZE(uint16_t, l_chain->datum_types_count * sizeof(uint16_t)); // TODO: pls check counter for recognized types before memory allocation!
                    if ( !l_chain->autoproc_datum_types ) {
                        log_it(L_CRITICAL, "Memory allocation error");
                        if (l_chain->datum_types)
                            DAP_DELETE(l_chain->datum_types);
                        if (l_chain->default_datum_types)
                            DAP_DELETE(l_chain->default_datum_types);
                        DAP_DELETE(l_chain);
                        return NULL;
                    }
                    l_count_recognized = 0;
					for (uint16_t i = 0; i < l_datum_types_count; i++)
					{
						if (!dap_strcmp(l_datum_types[i], "all") && l_chain->datum_types_count)
						{
							for (int j = 0; j < l_chain->datum_types_count; j++)
								l_chain->autoproc_datum_types[j] = s_chain_type_convert(l_chain->datum_types[j]);
							l_count_recognized = l_chain->datum_types_count;
							break;
						}
						uint16_t l_chain_type = s_datum_type_from_str(l_datum_types[i]);
						if (l_chain_type != DAP_CHAIN_DATUM_CUSTOM
						&&	s_datum_in_chain_types(l_chain_type, l_chain->datum_types, l_chain->datum_types_count))// <<--- check this chain_datum_type in readed datum_types
						{
							l_chain->autoproc_datum_types[l_count_recognized] = l_chain_type;
							l_count_recognized++;
						}
					}
					l_chain->autoproc_datum_types_count = l_count_recognized;
				} else
					l_chain->autoproc_datum_types_count = 0;
			}
            dap_config_close(l_cfg);
            return l_chain;
        } else
            return NULL;

    } else {
        log_it (L_WARNING, "NULL net_id string");
        return NULL;
    }
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
        a_chain->callback_load_from_gdb(a_chain);
        return 0;
    }
    char *l_storage_dir = DAP_CHAIN_PVT(a_chain)->file_storage_dir;
    if (!l_storage_dir)
        return 0;
    if (!dap_dir_test(l_storage_dir)) {
        dap_mkdir_with_parents(l_storage_dir);
    }
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
            dap_chain_cell_t *l_cell = dap_chain_cell_create_fill2(a_chain, l_filename);
            l_ret += dap_chain_cell_load(a_chain, l_cell);
            if (DAP_CHAIN_PVT(a_chain)->need_reorder) {
                const char *l_filename_backup = dap_strdup_printf("%s.unsorted", l_cell->file_storage_path);
                if (remove(l_filename_backup) == -1) {
                    log_it(L_ERROR, "File %s doesn't exist", l_filename_backup);
                }
                if (rename(l_cell->file_storage_path, l_filename_backup)) {
                    log_it(L_ERROR, "Couldn't rename %s to %s", l_cell->file_storage_path, l_filename_backup);
                }
                DAP_DELETE(l_filename_backup);
            }
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
void dap_chain_add_callback_notify(dap_chain_t * a_chain, dap_chain_callback_notify_t a_callback, void * a_callback_arg)
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
    l_notifier->arg = a_callback_arg;
    pthread_rwlock_wrlock(&a_chain->rwlock);
    a_chain->atom_notifiers = dap_list_append(a_chain->atom_notifiers, l_notifier);
    pthread_rwlock_unlock(&a_chain->rwlock);
}


/**
 * @brief dap_chain_get_last_atom_hash
 * @param a_chain
 * @param a_atom_hash
 * @return
 */
bool dap_chain_get_atom_last_hash(dap_chain_t *a_chain, dap_hash_fast_t *a_atom_hash, dap_chain_cell_id_t a_cel_id)
{
    bool l_ret = false;
    dap_chain_atom_iter_t *l_atom_iter = a_chain->callback_atom_iter_create(a_chain, a_cel_id, 0);
    dap_chain_atom_ptr_t * l_lasts_atom;
    size_t l_lasts_atom_count = 0;
    size_t* l_lasts_atom_size = NULL;
    l_lasts_atom = a_chain->callback_atom_iter_get_lasts(l_atom_iter, &l_lasts_atom_count, &l_lasts_atom_size);
    if (l_lasts_atom && l_lasts_atom_count) {
        assert(l_lasts_atom_size[0]);
        assert(l_lasts_atom[0]);
        if(a_atom_hash){
            dap_hash_fast(l_lasts_atom[0], l_lasts_atom_size[0], a_atom_hash);
            if(dap_log_level_get() <= L_DEBUG) {
                char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_chain_hash_fast_to_str(a_atom_hash, l_hash_str, sizeof(l_hash_str));
                log_it(L_DEBUG, "Send sync chain request from %s to infinity",l_hash_str);
            }
        }
        l_ret = true;
    }
    a_chain->callback_atom_iter_delete(l_atom_iter);
    return l_ret;
}

ssize_t dap_chain_atom_save(dap_chain_t *a_chain, const uint8_t *a_atom, size_t a_atom_size, dap_chain_cell_id_t a_cell_id)
{
    dap_chain_cell_t *l_cell = dap_chain_cell_find_by_id(a_chain, a_cell_id);
    if (!l_cell) {
        log_it(L_INFO, "Creating cell 0x%016"DAP_UINT64_FORMAT_X, a_cell_id.uint64);
        l_cell = dap_chain_cell_create_fill(a_chain, a_cell_id);
        if (!l_cell) {
            log_it(L_ERROR, "Can't create cell with id 0x%"DAP_UINT64_FORMAT_x" to save event...", a_cell_id.uint64);
            return -7;
        }
    }
    ssize_t l_res = dap_chain_cell_file_append(l_cell, a_atom, a_atom_size);
    if (a_chain->atom_notifiers) {
        dap_list_t *l_iter;
        DL_FOREACH(a_chain->atom_notifiers, l_iter) {
            dap_chain_atom_notifier_t *l_notifier = (dap_chain_atom_notifier_t*)l_iter->data;
            l_notifier->callback(l_notifier->arg, a_chain, l_cell->id, (void*)a_atom, a_atom_size);
        }
    }
    if (a_chain->callback_atom_add_from_treshold) {
        dap_chain_atom_ptr_t l_atom_treshold;
        do {
            size_t l_atom_treshold_size;
            l_atom_treshold = a_chain->callback_atom_add_from_treshold(a_chain, &l_atom_treshold_size);
            if (l_atom_treshold) {
                if (dap_chain_cell_file_append(l_cell, l_atom_treshold, l_atom_treshold_size) > 0)
                    log_it(L_INFO, "Added atom from treshold");
                else
                    log_it(L_ERROR, "Can't add atom from treshold");
            }
        } while(l_atom_treshold);
    }
    return l_res;
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
    char *cert_path_c = dap_canonicalize_filename(cert_path, NULL);
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
//  if ( access( l_cert_path, F_OK ) != -1 ) {
//      log_it (L_ERROR, "File %s is already exists.", l_cert_path);
//      return -1;
//  } else
    return l_ret;
}

const char* dap_chain_get_path(dap_chain_t *a_chain){
    return DAP_CHAIN_PVT(a_chain)->file_storage_dir;
}
