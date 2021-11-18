/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd   https://demlabs.net
 * Copyright  (c) 2017-2020
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
#include <stdlib.h>
#include <time.h>
#include "dap_common.h"
#include "dap_chain_block_cache.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_in.h"
#include "dap_chain_datum_tx_out.h"

#define LOG_TAG "dap_chain_block_cache"

/**
 * @brief dap_chain_block_cache_init
 * @return
 */
int dap_chain_block_cache_init()
{
    return 0;
}

/**
 * @brief dap_chain_block_cache_deinit
 */
void dap_chain_block_cache_deinit()
{

}

/**
 * @brief dap_chain_block_cache_new
 * @param a_block
 * @param a_block_size
 * @return
 */
dap_chain_block_cache_t * dap_chain_block_cache_new(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t * a_block, size_t a_block_size)
{
    if (! a_block)
        return NULL;

    dap_chain_block_cache_t * l_block_cache = DAP_NEW_Z(dap_chain_block_cache_t);
    l_block_cache->block = a_block;
    l_block_cache->block_size= a_block_size;
    l_block_cache->_inheritor = a_blocks;
    if (dap_chain_block_cache_update(l_block_cache)) {
        log_it(L_WARNING, "Block cache can't be created, possible cause corrupted block inside");
        DAP_DELETE(l_block_cache);
        return NULL;
    }
    log_it(L_DEBUG,"Block cache created");
    return l_block_cache;
}

/**
 * @brief dap_chain_block_cache_dup
 * @param a_block
 * @return
 */
dap_chain_block_cache_t * dap_chain_block_cache_dup(dap_chain_block_cache_t * a_block)
{
    dap_chain_block_cache_t * l_ret = DAP_NEW_Z(dap_chain_block_cache_t);
    memcpy(l_ret,a_block, sizeof (*a_block));
    memset(&l_ret->hh,0, sizeof (l_ret->hh)); // Drop hash handle to prevent its usage
    return l_ret;
}

/**
 * @brief dap_chain_block_cache_update
 * @param a_block_cache
 */
int dap_chain_block_cache_update(dap_chain_block_cache_t * a_block_cache)
{
    assert(a_block_cache);
    assert(a_block_cache->block);
    dap_hash_fast(a_block_cache->block, a_block_cache->block_size, &a_block_cache->block_hash);
    if (a_block_cache->meta)
        DAP_DELETE(a_block_cache->meta);
    if (a_block_cache->datum)
        DAP_DELETE(a_block_cache->datum);
    a_block_cache->meta = dap_chain_block_get_meta(a_block_cache->block, a_block_cache->block_size, &a_block_cache->meta_count);
    if (a_block_cache->meta_count != a_block_cache->block->hdr.meta_count) {
        DAP_DELETE(a_block_cache->meta);
        return -1;
    }
    dap_chain_block_meta_extract( a_block_cache->meta,a_block_cache->meta_count,
                                        &a_block_cache->prev_hash,
                                        &a_block_cache->anchor_hash,
                                        &a_block_cache->merkle_root,
                                        &a_block_cache->links_hash,
                                        &a_block_cache->links_hash_count,
                                        &a_block_cache->is_genesis,
                                        &a_block_cache->nonce,
                                        &a_block_cache->nonce2
                                      );
    a_block_cache->datum = dap_chain_block_get_datums( a_block_cache->block, a_block_cache->block_size, &a_block_cache->datum_count );
    if (a_block_cache->datum_count != a_block_cache->block->hdr.datum_count) {
        DAP_DELETE(a_block_cache->datum);
        return -2;
    }
    for (size_t i = 0; i< a_block_cache->datum_count; i++){
        dap_chain_datum_t * l_datum = a_block_cache->datum[i];
        if ( l_datum && l_datum->header.data_size && l_datum->header.type_id == DAP_CHAIN_DATUM_TX){
            dap_chain_hash_fast_t l_tx_hash;
            dap_chain_block_cache_tx_index_t * l_tx_index = NULL;
            dap_hash_fast(l_datum->data,l_datum->header.data_size, &l_tx_hash);
            HASH_FIND(hh, a_block_cache->tx_index, &l_tx_hash, sizeof (l_tx_hash), l_tx_index);
            if ( ! l_tx_index ){
                l_tx_index = DAP_NEW_Z(dap_chain_block_cache_tx_index_t);
                memcpy(&l_tx_index->tx_hash,&l_tx_hash, sizeof (l_tx_hash) );
                l_tx_index->tx =(dap_chain_datum_tx_t*) l_datum->data;
                HASH_ADD(hh, a_block_cache->tx_index, tx_hash, sizeof (l_tx_hash), l_tx_index);
            }
        }
    }
    return 0;
}

/**
 * @brief dap_chain_block_cache_get_tx_by_hash
 * @param a_block_cache
 * @param a_tx_hash
 * @return
 */
dap_chain_datum_tx_t* dap_chain_block_cache_get_tx_by_hash (dap_chain_block_cache_t * a_block_cache, dap_chain_hash_fast_t * a_tx_hash)
{
    dap_chain_block_cache_tx_index_t * l_tx_index = NULL;
    HASH_FIND(hh, a_block_cache->tx_index, a_tx_hash,sizeof (*a_tx_hash), l_tx_index);
    return l_tx_index? l_tx_index->tx : NULL;
}

/**
 * @brief dap_chain_block_cache_delete
 * @param a_block
 */
void dap_chain_block_cache_delete(dap_chain_block_cache_t * a_block_cache)
{
    DAP_DELETE(a_block_cache);
    log_it(L_DEBUG,"Block cache deleted");
}
