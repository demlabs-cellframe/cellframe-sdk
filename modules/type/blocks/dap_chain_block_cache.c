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
dap_chain_block_cache_t * dap_chain_block_cache_new(dap_chain_block_t * a_block, size_t a_block_size)
{
    if (! a_block)
        return NULL;

    dap_chain_block_cache_t * l_block_cache = DAP_NEW_Z(dap_chain_block_cache_t);
    l_block_cache->block = a_block;
    l_block_cache->block_size= a_block_size;
    dap_chain_block_cache_update(l_block_cache);

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
void dap_chain_block_cache_update(dap_chain_block_cache_t * a_block_cache)
{
    assert(a_block_cache);
    assert(a_block_cache->block);
    dap_hash_fast(a_block_cache->block, a_block_cache->block_size, &a_block_cache->block_hash);
    if (a_block_cache->datum)
        DAP_DELETE(a_block_cache->datum);
    a_block_cache->datum = dap_chain_block_get_datums( a_block_cache->block, a_block_cache->block_size, &a_block_cache->datum_count );
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
