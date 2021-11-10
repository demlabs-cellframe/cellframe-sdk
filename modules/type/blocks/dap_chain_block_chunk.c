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
        dap_chain_block_cache_t * l_block_cache = dap_chain_block_cache_new((dap_chain_block_t*) l_objs[n].value,l_objs[n].value_len);
        dap_chain_block_chunks_add(l_ret, l_block_cache );
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
    dap_chain_block_chunk_t * l_chunk = a_chunks->chunks_last;

    while(l_chunk){
        dap_chain_block_cache_hash_t* l_block_cache_hash = NULL, *l_tmp = NULL;
        HASH_ITER(hh, l_chunk->block_cache_hash , l_block_cache_hash, l_tmp){
            HASH_DEL(l_chunk->block_cache_hash, l_block_cache_hash);
            DAP_DELETE(l_block_cache_hash);
        }
    }
    dap_chain_block_cache_t* l_block_cache = NULL, *l_tmp = NULL;
    HASH_ITER(hh, a_chunks->cache , l_block_cache, l_tmp){
        HASH_DEL(a_chunks->cache, l_block_cache);
        dap_chain_block_cache_delete(l_block_cache);
    }
    DAP_DELETE(a_chunks->gdb_group);
    DAP_DELETE(a_chunks);
}


/**
 * @brief dap_chain_block_chunks_add
 * @param a_chunks
 * @param a_block_cache
 * @return
 */
void dap_chain_block_chunks_add(dap_chain_block_chunks_t * a_chunks,dap_chain_block_cache_t  * a_block_cache)
{
    dap_chain_block_cache_hash_t  * l_chunk_cache_hash = NULL;
    // Parse block and produce cache object
    dap_chain_block_t *l_block = a_block_cache->block;
    size_t l_block_size = a_block_cache->block_size;

    // Check if already present
    HASH_FIND(hh, a_chunks->cache, &a_block_cache->block_hash, sizeof (l_chunk_cache_hash->block_hash), l_chunk_cache_hash);
    if (l_chunk_cache_hash){
        log_it(L_WARNING, "Already present block %s in cache",a_block_cache->block_hash_str);
        dap_chain_block_cache_delete(a_block_cache);
        return;
    }
    // Save to GDB
    dap_chain_global_db_gr_set(dap_strdup(a_block_cache->block_hash_str),l_block,l_block_size, a_chunks->gdb_group);


    // And here we select chunk for the new block cache
    bool l_is_chunk_found = false;
    for (dap_chain_block_chunk_t * l_chunk = a_chunks->chunks_last; l_chunk; l_chunk = l_chunk->prev ){
        if(dap_hash_fast_compare(&l_chunk->block_cache_top->block_hash, &a_block_cache->prev_hash ) ){
            // Init cache-hash object
            l_chunk_cache_hash = DAP_NEW_Z(dap_chain_block_cache_hash_t);
            l_chunk_cache_hash->block_cache=a_block_cache;
            l_chunk_cache_hash->ts_created = time(NULL);
            memcpy(&l_chunk_cache_hash->block_hash, &a_block_cache->block_hash,sizeof (a_block_cache->block_hash));
            l_chunk_cache_hash->chunk = l_chunk;

            // Update first block cache from the head
            l_chunk->block_cache_top = a_block_cache;
            // Add to selected chunk its hash object
            HASH_ADD(hh,l_chunk->block_cache_hash , block_hash, sizeof (l_chunk_cache_hash->block_hash), l_chunk_cache_hash);

            // Update chunk id to make it unique
            dap_chain_hash_fast_t l_hash_new_data[2]={a_block_cache->block_hash,l_chunk->chunk_id };
            dap_hash_fast(l_hash_new_data,sizeof (l_hash_new_data),&l_chunk->chunk_id);
            l_is_chunk_found = true;
        }
    }

    if ( ! l_is_chunk_found ) { // Don't found anything suitable - if so we create our own chunk
        dap_chain_block_chunk_t * l_chunk = dap_chain_block_chunk_create(a_chunks);

        // Init cache-hash object
        l_chunk_cache_hash = DAP_NEW_Z(dap_chain_block_cache_hash_t);
        l_chunk_cache_hash->block_cache=a_block_cache;
        l_chunk_cache_hash->ts_created = time(NULL);
        memcpy(&l_chunk_cache_hash->block_hash, &a_block_cache->block_hash,sizeof (a_block_cache->block_hash));
        l_chunk_cache_hash->chunk = l_chunk;

        // Update first block cache from the head
        l_chunk->block_cache_top = a_block_cache;
        // Add to selected chunk its hash object
        HASH_ADD(hh,l_chunk->block_cache_hash , block_hash, sizeof (l_chunk_cache_hash->block_hash), l_chunk_cache_hash);

        // Update chunk id to make it unique
        dap_chain_hash_fast_t l_hash_new_data[2]={a_block_cache->block_hash,l_chunk->chunk_id };
        dap_hash_fast(l_hash_new_data,sizeof (l_hash_new_data),&l_chunk->chunk_id);
    }


    // Add object itself to all-chunks cache
    HASH_ADD(hh,a_chunks->cache ,block_hash ,sizeof (a_block_cache->block_hash), a_block_cache);
}

/**
 * @brief dap_chain_block_chunk_create
 * @param a_chunks
 * @return
 */
dap_chain_block_chunk_t * dap_chain_block_chunk_create(dap_chain_block_chunks_t * a_chunks)
{
    dap_chain_block_chunk_t * l_chunk = DAP_NEW_Z(dap_chain_block_chunk_t);
    // Add in tail
    l_chunk->prev = a_chunks->chunks_first;
    if (a_chunks->chunks_first){
        l_chunk->next = a_chunks->chunks_first->next;
        if (! l_chunk->next)
            a_chunks->chunks_last = l_chunk;
        else
            l_chunk->next->prev = l_chunk;
    }else
        a_chunks->chunks_last = l_chunk;
    a_chunks->chunks_first = l_chunk;
    return l_chunk;
}

/**
 * @brief dap_chain_block_chunk_delete
 * @param a_chunk
 */
void dap_chain_block_chunk_delete( dap_chain_block_chunk_t * a_chunk)
{
    dap_chain_block_cache_hash_t  * l_cache_hash = NULL, *l_tmp = NULL;
    HASH_ITER(hh, a_chunk->block_cache_hash, l_cache_hash, l_tmp){
        HASH_DEL(a_chunk->block_cache_hash, l_cache_hash);
        DAP_DELETE(l_cache_hash);
    }
    DAP_DELETE(a_chunk);
}

/**
 * @brief dap_chain_block_chunks_sort
 * @param a_chunks
 */
void dap_chain_block_chunks_sort(dap_chain_block_chunks_t * a_chunks)
{
    // Sort chunk list beginning from the new one and bubble up the longest one on the top
    size_t l_chunk_length_max=0;
    //dap_chain_block_chunk_t * l_chunk_max = NULL;
    for (dap_chain_block_chunk_t * l_chunk = a_chunks->chunks_first ; l_chunk; l_chunk = l_chunk? l_chunk->next: NULL ){
        if(!l_chunk)
            break;
        size_t l_chunk_length = HASH_COUNT(l_chunk->block_cache_hash);
        if (! l_chunk_length){
            log_it(L_WARNING,"Chunk can't be empty, it must be deleted from chunks treshold");
        }
        if (l_chunk_length > l_chunk_length_max ){
            //l_chunk_max = l_chunk;
            l_chunk_length_max = l_chunk_length;
        }else if (l_chunk_length == l_chunk_length_max ){
            continue;
        }else{
            // Prev store
            dap_chain_block_chunk_t * l_chunk_prev = l_chunk->prev;

            // Link next with prev
            if (l_chunk->next )
                l_chunk->next->prev = l_chunk->prev;

            dap_chain_block_chunk_t * l_chunk_prev_prev = NULL;

            if (l_chunk_prev){
                // Link prev with next
                l_chunk_prev->next = l_chunk->next;
                l_chunk_prev_prev = l_chunk_prev->prev;
                // Link prev with current
                l_chunk_prev->prev = l_chunk;
                // Update first chunks
                if ( ! l_chunk_prev_prev)
                    a_chunks->chunks_first = l_chunk;
            }

            // Link current with prev
            l_chunk->next = l_chunk->prev ;
            l_chunk->prev = l_chunk_prev_prev;

            // Replace previous with current
            l_chunk = l_chunk_prev;

            // Its the last chunk
            if (l_chunk && ! l_chunk->next)
                a_chunks->chunks_last = l_chunk;
        }
    }
    log_it(L_INFO,"Chunks sorted: max tail %zd", l_chunk_length_max );

}
