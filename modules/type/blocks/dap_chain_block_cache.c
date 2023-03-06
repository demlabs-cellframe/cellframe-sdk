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

dap_chain_block_cache_t *dap_chain_block_cache_new(dap_chain_cs_blocks_t *a_blocks, dap_hash_fast_t *a_block_hash,
                                                   dap_chain_block_t *a_block, size_t a_block_size)
{
    if (! a_block)
        return NULL;

    dap_chain_block_cache_t * l_block_cache = DAP_NEW_Z(dap_chain_block_cache_t);
    l_block_cache->block = a_block;
    l_block_cache->block_size= a_block_size;
    l_block_cache->_inheritor = a_blocks;
    l_block_cache->ts_created = a_block->hdr.ts_created;
    l_block_cache->sign_count = dap_chain_block_get_signs_count(a_block, a_block_size);
    if (dap_chain_block_cache_update(l_block_cache, a_block_hash)) {
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

int dap_chain_block_cache_update(dap_chain_block_cache_t *a_block_cache, dap_hash_fast_t *a_block_hash)
{
    assert(a_block_cache);
    assert(a_block_cache->block);
    if (a_block_hash)
        a_block_cache->block_hash = *a_block_hash;
    else
        dap_hash_fast(a_block_cache->block, a_block_cache->block_size, &a_block_cache->block_hash);
    a_block_cache->block_hash_str = dap_hash_fast_to_str_new(&a_block_cache->block_hash);
    DAP_DEL_Z(a_block_cache->meta);
    a_block_cache->meta = dap_chain_block_get_meta(a_block_cache->block, a_block_cache->block_size, &a_block_cache->meta_count);
    if (a_block_cache->meta_count != a_block_cache->block->hdr.meta_count) {
        DAP_DELETE(a_block_cache->meta);
        return -1;
    }
    dap_chain_block_meta_extract(a_block_cache->meta,a_block_cache->meta_count,
                                        &a_block_cache->prev_hash,
                                        &a_block_cache->anchor_hash,
                                        &a_block_cache->merkle_root,
                                        &a_block_cache->links_hash,
                                        &a_block_cache->links_hash_count,
                                        &a_block_cache->is_genesis,
                                        &a_block_cache->nonce,
                                        &a_block_cache->nonce2);
     DAP_DEL_Z(a_block_cache->datum);
     a_block_cache->datum = dap_chain_block_get_datums(a_block_cache->block, a_block_cache->block_size, &a_block_cache->datum_count);

    if (a_block_cache->datum_count != a_block_cache->block->hdr.datum_count) {
        DAP_DELETE(a_block_cache->datum);
        return -2;
    }
    dap_chain_datum_t *l_datum;
    for (size_t i = 0; i < a_block_cache->datum_count && (l_datum = a_block_cache->datum[i]); i++) {
        if (l_datum->header.data_size == 0 || l_datum->header.type_id != DAP_CHAIN_DATUM_TX)
            break;
        dap_chain_hash_fast_t l_tx_hash;
        dap_hash_fast(l_datum->data,l_datum->header.data_size, &l_tx_hash);

        dap_chain_block_cache_tx_index_t *l_tx_index = NULL;
        HASH_FIND(hh, a_block_cache->tx_index, &l_tx_hash, sizeof (l_tx_hash), l_tx_index);
        if (!l_tx_index) {
            l_tx_index = DAP_NEW_Z(dap_chain_block_cache_tx_index_t);
            l_tx_index->tx_hash = l_tx_hash;
            l_tx_index->tx = (dap_chain_datum_tx_t*)l_datum->data;
            HASH_ADD(hh, a_block_cache->tx_index, tx_hash, sizeof(l_tx_hash), l_tx_index);
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
    DAP_DEL_Z(a_block_cache->block_hash_str);
    DAP_DEL_Z(a_block_cache->datum);
    DAP_DEL_Z(a_block_cache->meta);
    DAP_DEL_Z(a_block_cache->links_hash);
    dap_chain_block_cache_tx_index_t *l_tx_cur, *l_tmp;
    HASH_ITER(hh, a_block_cache->tx_index, l_tx_cur, l_tmp) {
        HASH_DEL(a_block_cache->tx_index, l_tx_cur);
        DAP_FREE(l_tx_cur);
    }
    DAP_DELETE(a_block_cache);
}

/**
 * @brief dap_chain_datum_get_list_tx_outs_cond_with_val
 * @param a_ledger
 * @param a_block_cache
 * @param a_value_out
 * @return list of list_used_item_t
 */
dap_list_t * dap_chain_block_get_list_tx_cond_outs_with_val(dap_ledger_t *a_ledger,dap_chain_block_cache_t * a_block_cache,
                                                            uint256_t *a_value_out)
{
    dap_list_t *l_list_used_out = NULL; // list of transaction with 'out' items
    dap_chain_block_cache_tx_index_t *l_tx_cur, *l_tmp;
    dap_chain_tx_out_cond_t *l_tx_out_cond = NULL;
    uint256_t l_value_transfer = {};
    uint32_t l_out_idx_tmp = 0;
    HASH_ITER(hh, a_block_cache->tx_index, l_tx_cur, l_tmp) {
        if (NULL == (l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_tx_cur->tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE,
                                                                     &l_out_idx_tmp)))
        {
            dap_list_free_full(l_list_used_out, NULL);
            return NULL;
        }

        // Check whether used 'out' items
        if (!dap_chain_ledger_tx_hash_is_used_out_item (a_ledger, &(l_tx_cur->tx_hash), l_out_idx_tmp)) {
            list_used_item_t *l_item = DAP_NEW_Z(list_used_item_t);
            l_item->tx_hash_fast = l_tx_cur->tx_hash;
            l_item->num_idx_out = l_out_idx_tmp;
            l_item->value = l_tx_out_cond->header.value;
            l_list_used_out = dap_list_append(l_list_used_out, l_item);
            SUM_256_256(l_value_transfer, l_item->value, &l_value_transfer);
        }
    }
    if (IS_ZERO_256(l_value_transfer) || !l_list_used_out) {
        dap_list_free_full(l_list_used_out, NULL);
        return NULL;
    }
    else
        *a_value_out = l_value_transfer;
    return l_list_used_out;
}
