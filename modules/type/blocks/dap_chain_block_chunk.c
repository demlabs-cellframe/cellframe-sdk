/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd   https://demlabs.net
 * Copyright  (c) 2020
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_chain_net.h"
#include "dap_chain_global_db.h"
#include "dap_chain_block_chunk.h"

#define LOG_TAG "dap_chain_block_chunk"

/**
 * @brief dap_chain_block_chunks_create
 * @param a_blocks
 * @return
 */
dap_chain_block_chunks_t * dap_chain_block_chunks_create(dap_chain_cs_blocks_t * a_blocks)
{
    assert(a_blocks);
    assert(a_blocks->chain);
    dap_chain_block_chunks_t * l_ret = DAP_NEW_Z(dap_chain_block_chunks_t);
    l_ret->blocks = a_blocks;
    l_ret->gdb_group = dap_strdup_printf("local.%s.%s.block.chunks",a_blocks->chain->net_name, a_blocks->chain->name );

    size_t l_objs_count =0;
    dap_global_db_obj_t * l_objs= dap_chain_global_db_gr_load(l_ret->gdb_group, &l_objs_count);
    for(size_t n=0; n< l_objs_count; n++){
        dap_chain_block_chunks_add(l_ret,(dap_chain_block_t*) l_objs[n].value,l_objs[n].value_len );
    }
    dap_chain_global_db_objs_delete(l_objs,l_objs_count);
    return l_ret;
}

/**
 * @brief dap_chain_block_chunks_delete
 * @param a_chunks
 */
void dap_chain_block_chunks_delete(dap_chain_block_chunks_t * a_chunks)
{
    dap_chain_block_cache_t * l_block_cache = NULL, *l_tmp = NULL;
    HASH_ITER(hh, a_chunks->cache, l_block_cache, l_tmp){

        HASH_DEL(a_chunks->cache, l_block_cache);
        dap_chain_block_cache_delete(l_block_cache);
    }
    DAP_DELETE(a_chunks->gdb_group);
    DAP_DELETE(a_chunks);
}


/**
 * @brief dap_chain_block_chunks_add
 * @param a_chunks
 * @param a_block
 * @param a_block_size
 * @return
 */
dap_chain_block_cache_t * dap_chain_block_chunks_add(dap_chain_block_chunks_t * a_chunks, dap_chain_block_t *a_block ,size_t a_block_size)
{
    dap_chain_block_cache_t  * l_block_cache = dap_chain_block_cache_new(a_block,a_block_size);
    dap_chain_block_cache_t  * l_block_cache_check = NULL;
    HASH_FIND(hh, a_chunks->cache, &l_block_cache->block_hash, sizeof (l_block_cache->block_hash), l_block_cache_check);

    if (l_block_cache_check){
        log_it(L_WARNING, "Already present block %s in cache",l_block_cache_check->block_hash_str);
        dap_chain_block_cache_delete(l_block_cache);
        return l_block_cache_check;
    }
    dap_chain_global_db_gr_set(dap_strdup(l_block_cache->block_hash_str),a_block,a_block_size, a_chunks->gdb_group);
    HASH_ADD(hh,a_chunks->cache,block_hash,sizeof (l_block_cache->block_hash), l_block_cache);
    return l_block_cache;
}
