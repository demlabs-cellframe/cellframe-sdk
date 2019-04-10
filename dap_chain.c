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

#include <unistd.h>

#include "dap_common.h"
#include "dap_config.h"
#include "dap_chain_pvt.h"
#include "dap_chain.h"
#include "dap_chain_cs.h"
#include <uthash.h>
#include <pthread.h>


#define LOG_TAG "chain"

typedef struct dap_chain_item_id {
    dap_chain_id_t id;
    dap_chain_net_id_t net_id;
} DAP_ALIGN_PACKED dap_chain_item_id_t;

typedef struct dap_chain_item {
    dap_chain_item_id_t item_id;
    dap_chain_t * chain;
   UT_hash_handle hh;
} dap_chain_item_t;

static pthread_mutex_t s_mutex = PTHREAD_MUTEX_INITIALIZER;
static dap_chain_item_t * s_chain_items = NULL;

int s_prepare_env();

/**
 * @brief dap_chain_init
 * @return
 */
int dap_chain_init()
{
    dap_chain_cs_init();
    //dap_chain_show_hash_blocks_file(g_gold_hash_blocks_file);
    //dap_chain_show_hash_blocks_file(g_silver_hash_blocks_file);
    return 0;
}

/**
 * @brief dap_chain_deinit
 */
void dap_chain_deinit()
{
    dap_chain_item_t * l_item = NULL, *l_tmp = NULL;
    HASH_ITER(hh, s_chain_items, l_item, l_tmp) {
          dap_chain_delete(s_chain_items->chain);
          DAP_DELETE(l_item);
        }
}

/**
 * @brief dap_chain_load_net_cfg_name
 * @param a_chan_net_cfg_name
 * @return
 */
dap_chain_t * dap_chain_load_net_cfg_name(const char * a_chan_net_cfg_name)
{

}

/**
 * @brief dap_chain_create
 * @param a_chain_net_name
 * @param a_chain_name
 * @param a_chain_net_id
 * @param a_chain_id
 * @return
 */
dap_chain_t * dap_chain_create(const char * a_chain_net_name, const char * a_chain_name, dap_chain_net_id_t a_chain_net_id, dap_chain_id_t a_chain_id )
{
    dap_chain_t * l_ret = DAP_NEW_Z(dap_chain_t);
    DAP_CHAIN_PVT_LOCAL_NEW(l_ret);
    memcpy(l_ret->id.raw,a_chain_id.raw,sizeof(a_chain_id));
    memcpy(l_ret->net_id.raw,a_chain_net_id.raw,sizeof(a_chain_net_id));
    l_ret->name = strdup (a_chain_name);
    l_ret->net_name = strdup (a_chain_net_name);

    dap_chain_item_t * l_ret_item = DAP_NEW_Z(dap_chain_item_t);
    l_ret_item->chain = l_ret;
    memcpy(l_ret_item->item_id.id.raw ,a_chain_id.raw,sizeof(a_chain_id));
    memcpy(l_ret_item->item_id.net_id.raw ,a_chain_net_id.raw,sizeof(a_chain_net_id));
    HASH_ADD(hh,s_chain_items,item_id,sizeof(dap_chain_item_id_t),l_ret_item);
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

    HASH_FIND(hh,s_chain_items,&l_chain_item_id,sizeof(dap_chain_item_id_t),l_ret_item);
    if ( l_ret_item ){
        return l_ret_item->chain;
    }else
        return NULL;
}

/**
 * @brief dap_chain_load_from_cfg
 * @param a_chain_net_name
 * @param a_chain_cfg_path
 * @return
 */
dap_chain_t * dap_chain_load_from_cfg(const char * a_chain_net_name, const char * a_chain_cfg_name)
{
    if ( a_chain_net_name){
        dap_chain_net_id_t l_chain_net_id = {0};
        if ( sscanf(a_chain_net_name,"0x%llX",&l_chain_net_id.uint64) !=1 )
            if ( sscanf(a_chain_net_name,"0x%llx",&l_chain_net_id.uint64) !=1 )
                if ( sscanf(a_chain_net_name,"%llu",&l_chain_net_id.uint64) !=1 ){
                    log_it (L_ERROR,"Can't recognize '%s' string as chain net id, hex or dec",a_chain_net_name);
                    return NULL;
                }

        dap_config_t * l_cfg = dap_config_open(a_chain_cfg_name);
        if (l_cfg) {
            dap_chain_t * l_chain = NULL;
            dap_chain_id_t l_chain_id = {0};
            const char * l_chain_id_str = NULL;
            const char * l_chain_name = NULL;
            // Recognize chains id
            if ( l_chain_id_str = dap_config_get_item_str(l_cfg,"chain","id") ){
                if ( sscanf(l_chain_id_str,"0x%llX",&l_chain_id.uint64) !=1 ){
                    if ( sscanf(l_chain_id_str,"0x%llx",&l_chain_id.uint64) !=1 ) {
                        if ( sscanf(l_chain_id_str,"%llu",&l_chain_id.uint64) !=1 ){
                            log_it (L_ERROR,"Can't recognize '%s' string as chain net id, hex or dec",l_chain_id_str);
                            dap_config_close(l_cfg);
                            return NULL;
                        }
                    }
                }
            }
            // Read chain name
            if ( l_chain_name = dap_config_get_item_str(l_cfg,"chain","name") ){
                log_it (L_ERROR,"Can't recognize '%s' string as chain net id, hex or dec",l_chain_id_str);
                dap_config_close(l_cfg);
                return NULL;
            }

            l_chain =  dap_chain_create(a_chain_net_name,l_chain_name, l_chain_net_id,l_chain_id);
            if ( dap_chain_cs_create(l_chain, l_cfg) == 0 ) {
                log_it (L_NOTICE,"Consensus initialized for chain id 0x%016llX",
                        l_chain_id.uint64 );
                DAP_CHAIN_PVT ( l_chain)->file_storage_dir = strdup ( dap_config_get_item_str (l_cfg , "files","storage_dir") );
                if ( dap_chain_pvt_cells_load ( l_chain ) != 0 ){
                    log_it (L_NOTICE, "Init chain file");
                    dap_chain_pvt_cells_save( l_chain );
                }
            }else{
                log_it (L_ERROR, "Can't init consensus \"%s\"",dap_config_get_item_str_default( l_cfg , "chain","consensus","NULL"));
                dap_chain_delete(l_chain);
                l_chain = NULL;
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
 * @brief dap_chain_init_net_cfg_name
 * @param a_chain_net_cfg_name
 * @return
 */
dap_chain_t * dap_chain_init_net_cfg_name(const char * a_chain_net_cfg_name)
{
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

}

