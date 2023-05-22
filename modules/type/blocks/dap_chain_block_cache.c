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
 * @brief dap_chain_block_cache_create
 * @param a_block
 * @param a_block_size
 * @return
 */
dap_chain_block_cache_t *dap_chain_block_cache_create(dap_chain_cs_blocks_t *a_blocks, dap_hash_fast_t *a_block_hash, dap_chain_block_t *a_block, size_t a_block_size)
{
    if (!a_block)
        return NULL;

    size_t l_meta_count = 0;
    dap_chain_block_meta_t **l_meta = dap_chain_block_get_meta(a_block, a_block_size, &l_meta_count);
    if (l_meta_count != a_block->hdr.meta_count) {
        DAP_DELETE(l_meta);
        return NULL;
    }

    size_t l_datums_count = 0;
    dap_chain_datum_t **l_datums = dap_chain_block_get_datums(a_block, a_block_size, &l_datums_count);
    if (l_datums_count != a_block->hdr.datum_count) {
        DAP_DELETE(l_meta);
        DAP_DELETE(l_datums);
        return NULL;
    }

    dap_chain_block_cache_t *l_block_cache = DAP_NEW_Z(dap_chain_block_cache_t);
    l_block_cache->block        = a_block;
    l_block_cache->block_size   = a_block_size;
    l_block_cache->_inheritor   = a_blocks;
    l_block_cache->ts_created   = a_block->hdr.ts_created;
    l_block_cache->sign_count   = dap_chain_block_get_signs_count(a_block, a_block_size);
    l_block_cache->block_hash   = a_block_hash && !dap_hash_fast_is_blank(a_block_hash)
                                ? *a_block_hash
                                : ({dap_hash_fast_t l_h; dap_hash_fast(a_block, a_block_size, &l_h); l_h;});
    l_block_cache->block_hash_str = dap_hash_fast_to_str_new(&l_block_cache->block_hash);
    l_block_cache->datum        = l_datums;
    l_block_cache->datum_count  = l_datums_count;
    l_block_cache->meta         = l_meta;
    l_block_cache->meta_count   = l_meta_count;

    dap_chain_block_meta_extract(l_block_cache->meta,
                                 l_block_cache->meta_count,
                                 &l_block_cache->prev_hash,
                                 &l_block_cache->anchor_hash,
                                 &l_block_cache->merkle_root,
                                 &l_block_cache->links_hash,
                                 &l_block_cache->links_hash_count,
                                 &l_block_cache->is_genesis,
                                 &l_block_cache->nonce,
                                 &l_block_cache->nonce2);

    pthread_rwlock_init(&l_block_cache->tx_index_lock, NULL);

    dap_chain_datum_t *l_datum;
    size_t i;
    for (i = 0; i < l_block_cache->datum_count && (l_datum = l_block_cache->datum[i]); ++i) {
        if (!l_datum->header.data_size || l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
            break;

        dap_chain_hash_fast_t l_tx_hash;
        dap_hash_fast(l_datum->data, l_datum->header.data_size, &l_tx_hash);

        dap_chain_block_cache_tx_index_t *l_tx_index = NULL;
        pthread_rwlock_wrlock(&l_block_cache->tx_index_lock);
        HASH_FIND(hh, l_block_cache->tx_index, &l_tx_hash, sizeof (l_tx_hash), l_tx_index);
        if (!l_tx_index) {
            l_tx_index = DAP_NEW_Z(dap_chain_block_cache_tx_index_t);
            l_tx_index->tx_hash = l_tx_hash;
            l_tx_index->tx      = (dap_chain_datum_tx_t*)l_datum->data;
            HASH_ADD(hh, l_block_cache->tx_index, tx_hash, sizeof(l_tx_hash), l_tx_index);
        }
        pthread_rwlock_unlock(&l_block_cache->tx_index_lock);
    }

    debug_if(i != l_block_cache->datum_count, L_WARNING,
             "Only %llu of %llu datums could be read from block cache", i, l_block_cache->datum_count);

    return l_block_cache;
}

/**
 * @brief dap_chain_block_cache_dup
 * @param a_block
 * @return
 */
dap_chain_block_cache_t *dap_chain_block_cache_dup(dap_chain_block_cache_t * a_block)
{
    return ({ dap_chain_block_cache_t *l_ret = DAP_DUP(a_block); l_ret->hh = (UT_hash_handle){ }; l_ret; });
}

/**
 * @brief dap_chain_block_cache_get_tx_by_hash
 * @param a_block_cache
 * @param a_tx_hash
 * @return
 */
dap_chain_datum_tx_t* dap_chain_block_cache_get_tx_by_hash(dap_chain_block_cache_t * a_block_cache, dap_chain_hash_fast_t * a_tx_hash)
{
    dap_chain_block_cache_tx_index_t *l_tx_index = NULL;
    pthread_rwlock_rdlock(&a_block_cache->tx_index_lock);
    HASH_FIND(hh, a_block_cache->tx_index, a_tx_hash, sizeof(*a_tx_hash), l_tx_index);
    pthread_rwlock_unlock(&a_block_cache->tx_index_lock);
    return l_tx_index ? l_tx_index->tx : NULL;
}

/**
 * @brief dap_chain_block_cache_delete
 * @param a_block
 */
void dap_chain_block_cache_delete(dap_chain_block_cache_t **a_block_cache)
{
    DAP_DEL_Z((*a_block_cache)->block_hash_str);
    DAP_DEL_Z((*a_block_cache)->datum);
    DAP_DEL_Z((*a_block_cache)->meta);
    DAP_DEL_Z((*a_block_cache)->links_hash);
    dap_chain_block_cache_tx_index_t *l_tx_cur, *l_tmp;
    pthread_rwlock_wrlock(&(*a_block_cache)->tx_index_lock);
    HASH_ITER(hh, (*a_block_cache)->tx_index, l_tx_cur, l_tmp) {
        HASH_DEL((*a_block_cache)->tx_index, l_tx_cur);
        DAP_FREE(l_tx_cur);
    }
    pthread_rwlock_unlock(&(*a_block_cache)->tx_index_lock);
    pthread_rwlock_destroy(&(*a_block_cache)->tx_index_lock);
    DAP_DEL_Z(*a_block_cache);
}
