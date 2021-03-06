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
#include <dap_chain_ledger.h>
#include <sys/types.h>
#include <dirent.h>
#ifdef DAP_OS_LINUX
#include <stdc-predef.h>
#endif
#include <unistd.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_config.h"
#include "dap_chain_pvt.h"
#include "dap_chain.h"
#include "dap_chain_ledger.h"
#include "dap_cert.h"
#include "dap_chain_cs.h"
#include "dap_chain_vf.h"
#include <uthash.h>
#include <pthread.h>

#define LOG_TAG "chain"

typedef struct dap_chain_item_id {
    dap_chain_id_t id;
    dap_chain_net_id_t net_id;
}  dap_chain_item_id_t;

typedef struct dap_chain_item {
    dap_chain_item_id_t item_id;
    dap_chain_t * chain;
   UT_hash_handle hh;
} dap_chain_item_t;

static pthread_rwlock_t s_chain_items_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static dap_chain_item_t * s_chain_items = NULL;

int s_prepare_env();

/**
 * @brief dap_chain_init
 * @return
 */
int dap_chain_init(void)
{
    /*if (dap_cert_init() != 0) {
        log_it(L_CRITICAL,"Can't chain certificate storage module");
        return -4;
    }*/

    uint16_t l_ca_folders_size = 0;
    char ** l_ca_folders;
    l_ca_folders = dap_config_get_array_str(g_config, "resources", "ca_folders", &l_ca_folders_size);
    for (uint16_t i=0; i < l_ca_folders_size; i++) {
        dap_cert_add_folder(l_ca_folders[i]);
    }
    // Cell sharding init
    dap_chain_cell_init();
    dap_chain_ledger_init();
    dap_chain_cs_init();

    dap_chain_vf_init();
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
    dap_chain_ledger_deinit();

}


/**
 * @brief dap_chain_deinit
 * note: require dap_chain_enum_unlock() after
 */
dap_chain_t* dap_chain_enum(void** a_item)
{
    // if a_item == 0x1 then first item
    dap_chain_item_t *l_item_start = ( *a_item == (void*) 0x1) ? s_chain_items : (dap_chain_item_t*) *a_item;
    dap_chain_item_t *l_item = NULL;
    dap_chain_item_t *l_item_tmp = NULL;
    pthread_rwlock_rdlock(&s_chain_items_rwlock);
    HASH_ITER(hh, l_item_start, l_item, l_item_tmp) {
        *a_item = l_item_tmp;
        return l_item->chain;
    }
    return NULL ;
}

/**
 * @brief dap_chain_enum_unlock
 */
void dap_chain_enum_unlock(void)
{
    pthread_rwlock_unlock(&s_chain_items_rwlock);
}

/**
 * @brief dap_chain_create
 * @param a_chain_net_name
 * @param a_chain_name
 * @param a_chain_net_id
 * @param a_chain_id
 * @return
 */
dap_chain_t * dap_chain_create(dap_ledger_t* a_ledger, const char * a_chain_net_name, const char * a_chain_name, dap_chain_net_id_t a_chain_net_id, dap_chain_id_t a_chain_id )
{
    dap_chain_t * l_ret = DAP_NEW_Z(dap_chain_t);
    DAP_CHAIN_PVT_LOCAL_NEW(l_ret);
    memcpy(l_ret->id.raw,a_chain_id.raw,sizeof(a_chain_id));
    memcpy(l_ret->net_id.raw,a_chain_net_id.raw,sizeof(a_chain_net_id));
    l_ret->name = strdup (a_chain_name);
    l_ret->net_name = strdup (a_chain_net_name);
    l_ret->ledger = a_ledger;
    pthread_rwlock_init(&l_ret->atoms_rwlock,NULL);

    dap_chain_item_t * l_ret_item = DAP_NEW_Z(dap_chain_item_t);
    l_ret_item->chain = l_ret;
    memcpy(l_ret_item->item_id.id.raw ,a_chain_id.raw,sizeof(a_chain_id));
    memcpy(l_ret_item->item_id.net_id.raw ,a_chain_net_id.raw,sizeof(a_chain_net_id));
    pthread_rwlock_wrlock(&s_chain_items_rwlock);
    HASH_ADD(hh,s_chain_items,item_id,sizeof(dap_chain_item_id_t),l_ret_item);
    pthread_rwlock_unlock(&s_chain_items_rwlock);
    return l_ret;
}

/**
 * @brief dap_chain_delete
 * @param a_chain
 */
void dap_chain_delete(dap_chain_t * a_chain)
{
    dap_chain_item_t * l_item = NULL;
    dap_chain_item_id_t l_chain_item_id = {
        .id = a_chain->id,
        .net_id = a_chain->net_id,
    };
    pthread_rwlock_wrlock(&s_chain_items_rwlock);
    HASH_FIND(hh,s_chain_items,&l_chain_item_id,sizeof(dap_chain_item_id_t),l_item);

    if( l_item){
       HASH_DEL(s_chain_items, l_item);
       if (a_chain->callback_delete )
           a_chain->callback_delete(a_chain);
       if ( a_chain->name)
           DAP_DELETE (a_chain->name);
       if ( a_chain->net_name)
           DAP_DELETE (a_chain->net_name);
       if (a_chain->_pvt ){
           DAP_DELETE(DAP_CHAIN_PVT(a_chain)->file_storage_dir);
           DAP_DELETE(a_chain->_pvt);
       }
       if (a_chain->_inheritor )
           DAP_DELETE(a_chain->_inheritor);
       DAP_DELETE(l_item);
    }else
       log_it(L_WARNING,"Trying to remove non-existent 0x%16llX:0x%16llX chain",a_chain->id.uint64,
              a_chain->net_id.uint64);
    a_chain->datum_types_count = 0;
    DAP_DELETE(a_chain->datum_types);
    a_chain->autoproc_datum_types_count = 0;
    DAP_DELETE(a_chain->autoproc_datum_types);
    pthread_rwlock_destroy(&a_chain->atoms_rwlock);
    pthread_rwlock_unlock(&s_chain_items_rwlock);
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
    dap_chain_atom_iter_t * l_iter = a_chain->callback_atom_iter_create(a_chain);
    dap_chain_atom_ptr_t *l_ret = a_chain->callback_atom_find_by_hash(l_iter, a_atom_hash, a_atom_size);
    a_chain->callback_atom_iter_delete(l_iter);
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
    return CHAIN_TYPE_LAST;
}

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
    return DAP_CHAIN_DATUM_CUSTOM;
}

static uint16_t s_chain_type_convert(dap_chain_type_t a_type)
{
    switch (a_type) {
    case CHAIN_TYPE_TOKEN:
        return DAP_CHAIN_DATUM_TOKEN_DECL;
    case CHAIN_TYPE_EMISSION:
        return DAP_CHAIN_DATUM_TOKEN_EMISSION;
    case CHAIN_TYPE_TX:
        return DAP_CHAIN_DATUM_TX;
    default:
        return DAP_CHAIN_DATUM_CUSTOM;
    }
}

/**
 * @brief dap_chain_load_from_cfg
 * @param a_chain_net_name
 * @param a_chain_net_id
 * @param a_chain_cfg_path
 * @return
 */
dap_chain_t * dap_chain_load_from_cfg(dap_ledger_t* a_ledger, const char * a_chain_net_name,dap_chain_net_id_t a_chain_net_id, const char * a_chain_cfg_name)
{
    log_it (L_DEBUG, "Loading chain from config \"%s\"", a_chain_cfg_name);
    if ( a_chain_net_name){
        dap_config_t * l_cfg = dap_config_open(a_chain_cfg_name);
        if (l_cfg) {
            dap_chain_t * l_chain = NULL;
            dap_chain_id_t l_chain_id = {{0}};
            uint64_t l_chain_id_u = 0;
            const char * l_chain_id_str = NULL;
            const char * l_chain_name = NULL;

            // Recognize chains id
            if ( (l_chain_id_str = dap_config_get_item_str(l_cfg,"chain","id")) != NULL ){
                if ( sscanf(l_chain_id_str,"0x%"DAP_UINT64_FORMAT_X,& l_chain_id_u ) !=1 ){
                    if ( sscanf(l_chain_id_str,"0x%"DAP_UINT64_FORMAT_x,&l_chain_id_u) !=1 ) {
                        if ( sscanf(l_chain_id_str,"%"DAP_UINT64_FORMAT_u,&l_chain_id_u ) !=1 ){
                            log_it (L_ERROR,"Can't recognize '%s' string as chain net id, hex or dec",l_chain_id_str);
                            dap_config_close(l_cfg);
                            return NULL;
                        }
                    }
                }
            }
            l_chain_id.uint64 = l_chain_id_u;


            if (l_chain_id_str ) {
                log_it (L_NOTICE, "Chain id 0x%016"DAP_UINT64_FORMAT_x"  ( \"%s\" )",l_chain_id.uint64 , l_chain_id_str) ;
            }else {
                log_it (L_ERROR,"Wasn't recognized '%s' string as chain net id, hex or dec",l_chain_id_str);
                dap_config_close(l_cfg);
                return NULL;

            }
            // Read chain name
            if ( ( l_chain_name = dap_config_get_item_str(l_cfg,"chain","name") ) == NULL ){
                log_it (L_ERROR,"Can't read chain net name ",l_chain_id_str);
                dap_config_close(l_cfg);
                return NULL;
            }

            l_chain =  dap_chain_create(a_ledger,a_chain_net_name,l_chain_name, a_chain_net_id,l_chain_id);
            if ( dap_chain_cs_create(l_chain, l_cfg) == 0 ) {
                log_it (L_NOTICE,"Consensus initialized for chain id 0x%016llX",
                        l_chain_id.uint64 );

                if ( dap_config_get_item_str_default(l_cfg , "files","storage_dir",NULL ) ) {
                    DAP_CHAIN_PVT ( l_chain)->file_storage_dir = strdup (
                                dap_config_get_item_str( l_cfg , "files","storage_dir" ) ) ;
                    if ( dap_chain_load_all( l_chain ) != 0 ){
                        dap_chain_save_all( l_chain );
                        log_it (L_NOTICE, "Loaded chain files");
                    }else {
                        dap_chain_save_all( l_chain );
                        log_it (L_NOTICE, "Initialized chain files");
                    }
                } else{
                    log_it (L_INFO, "Not set file storage path, will not stored in files");
                    //dap_chain_delete(l_chain);
                    //l_chain = NULL;
                }

            }else{
                log_it (L_ERROR, "Can't init consensus \"%s\"",dap_config_get_item_str_default( l_cfg , "chain","consensus","NULL"));
                dap_chain_delete(l_chain);
                l_chain = NULL;
            }
            // Read chain datum types
            char** l_datum_types = NULL;
            uint16_t l_datum_types_count = 0;
            if((l_datum_types = dap_config_get_array_str(l_cfg, "chain", "datum_types", &l_datum_types_count)) == NULL) {
                log_it(L_WARNING, "Can't read chain datum types ", l_chain_id_str);
                //dap_config_close(l_cfg);
                //return NULL;
            }
            // add datum types
            if(l_chain && l_datum_types_count > 0) {
                l_chain->datum_types = DAP_NEW_SIZE(dap_chain_type_t, l_datum_types_count * sizeof(dap_chain_type_t));
                uint16_t l_count_recognized = 0;
                for(uint16_t i = 0; i < l_datum_types_count; i++) {
                    dap_chain_type_t l_chain_type = s_chain_type_from_str(l_datum_types[i]);
                    if (l_chain_type != CHAIN_TYPE_LAST) {
                        l_chain->datum_types[l_count_recognized] = l_chain_type;
                        l_count_recognized++;
                    }
                }
                l_chain->datum_types_count = l_count_recognized;
            }
            if((l_datum_types = dap_config_get_array_str(l_cfg, "chain", "mempool_auto_types", &l_datum_types_count)) == NULL) {
                log_it(L_WARNING, "Can't read chain mempool auto types ", l_chain_id_str);
            }
            // add datum types
            if(l_chain && l_datum_types_count) {
                l_chain->autoproc_datum_types = DAP_NEW_SIZE(uint16_t, l_datum_types_count * sizeof(uint16_t));
                uint16_t l_count_recognized = 0;
                for(uint16_t i = 0; i < l_datum_types_count; i++) {
                    if (!strcmp(l_datum_types[i], "all")) {
                        l_chain->autoproc_datum_types = DAP_REALLOC(l_chain->autoproc_datum_types, l_chain->datum_types_count * sizeof(uint16_t));
                        for (int j = 0; j < l_chain->datum_types_count; j++) {
                            l_chain->autoproc_datum_types[j] = s_chain_type_convert(l_chain->datum_types[j]);
                        }
                        l_count_recognized = l_chain->datum_types_count;
                        break;
                    }
                    uint16_t l_chain_type = s_datum_type_from_str(l_datum_types[i]);
                    if (l_chain_type != DAP_CHAIN_DATUM_CUSTOM) {
                        l_chain->autoproc_datum_types[l_count_recognized] = l_chain_type;
                        l_count_recognized++;
                    }
                }
                l_chain->autoproc_datum_types_count = l_count_recognized;
            }
            dap_config_close(l_cfg);
            return l_chain;
        }else
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
int dap_chain_save_all (dap_chain_t * l_chain)
{
    int ret = -1;
    pthread_rwlock_rdlock(&l_chain->atoms_rwlock);
    dap_chain_cell_t * l_item, *l_item_tmp = NULL;
    HASH_ITER(hh,l_chain->cells,l_item,l_item_tmp){
        dap_chain_cell_file_update(l_item);
        if (ret <0 )
            ret++;
    }
    pthread_rwlock_unlock(&l_chain->atoms_rwlock);
    return ret;
}

/**
 * @brief dap_chain_load_all
 * @param l_chain
 * @return
 */
int dap_chain_load_all (dap_chain_t * l_chain)
{
    int l_ret = -2;
    if(!l_chain)
        return l_ret;
    pthread_rwlock_wrlock(&l_chain->atoms_rwlock);

    // create directory if not exist
    if(!dap_dir_test(DAP_CHAIN_PVT (l_chain)->file_storage_dir)) {
        dap_mkdir_with_parents(DAP_CHAIN_PVT (l_chain)->file_storage_dir);
    }
    DIR * l_dir = opendir(DAP_CHAIN_PVT(l_chain)->file_storage_dir);
    if( l_dir ) {
        struct dirent * l_dir_entry;
        l_ret = -1;
        while((l_dir_entry=readdir(l_dir))!=NULL){
            const char * l_filename = l_dir_entry->d_name;
            size_t l_filename_len = strlen (l_filename);
            // Check if its not special dir entries . or ..
            if( strcmp(l_filename,".") && strcmp(l_filename,"..") ){
                // If not check the file's suffix
                const char l_suffix[]=".dchaincell";
                size_t l_suffix_len = strlen(l_suffix);
                if (strncmp(l_filename+ l_filename_len-l_suffix_len,l_suffix,l_suffix_len) == 0 ){
                    if ( dap_chain_cell_load(l_chain,l_filename) == 0 )
                        l_ret = 0;
                }
            }
        }
        closedir(l_dir);
    }
    pthread_rwlock_unlock(&l_chain->atoms_rwlock);

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
    if(!a_chain)
        return;
    a_chain->callback_notify = a_callback;
    a_chain->callback_notify_arg = a_callback_arg;
}

/**
 * @brief dap_chain_get_last_atom_hash
 * @param a_chain
 * @param a_atom_hash
 * @return
 */
bool dap_chain_get_atom_last_hash(dap_chain_t * a_chain, dap_hash_fast_t * a_atom_hash)
{
    bool l_ret = false;
    pthread_rwlock_rdlock(&a_chain->atoms_rwlock);

    dap_chain_atom_iter_t *l_atom_iter = a_chain->callback_atom_iter_create(a_chain);
    dap_chain_atom_ptr_t * l_lasts_atom;
    size_t l_lasts_atom_count=0;
    size_t* l_lasts_atom_size =NULL;
    l_lasts_atom= a_chain->callback_atom_iter_get_lasts(l_atom_iter, &l_lasts_atom_count,&l_lasts_atom_size);
    if (l_lasts_atom&& l_lasts_atom_count){
        assert(l_lasts_atom_size[0]);
        assert(l_lasts_atom[0]);
        if(a_atom_hash){
            dap_hash_fast(l_lasts_atom[0], l_lasts_atom_size[0],a_atom_hash);
            if(dap_log_level_get() <= L_DEBUG){
                char l_hash_str[128]={[0]='\0'};
                dap_chain_hash_fast_to_str(a_atom_hash,l_hash_str,sizeof (l_hash_str)-1);
                log_it(L_DEBUG,"Send sync chain request from %s to infinity",l_hash_str);
            }
        }
        l_ret = true;
    }
    a_chain->callback_atom_iter_delete(l_atom_iter);
    pthread_rwlock_unlock(&a_chain->atoms_rwlock);
    return l_ret;
}
