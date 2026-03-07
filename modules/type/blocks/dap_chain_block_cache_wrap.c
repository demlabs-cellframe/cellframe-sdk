/*
 * Authors:
 * Cellframe Team <contact@cellframe.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2017-2025
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

/**
 * @file dap_chain_block_cache_wrap.c
 * @brief Wrapper functions for block cache operations
 * 
 * This file provides wrapper functions that enable mocking via --wrap linker flag.
 * The CLI code calls these wrappers instead of direct functions, allowing tests
 * to intercept the calls.
 */

#include "dap_chain_block_cache.h"
#include "dap_chain_type_blocks.h"

/**
 * @brief Wrapper for dap_chain_block_cache_get_by_hash
 * 
 * This function is called from CLI code and can be intercepted
 * by --wrap linker flag in unit tests.
 */
dap_chain_block_cache_t *dap_chain_block_cache_get_by_hash_w(
    dap_chain_type_blocks_t *a_blocks, 
    dap_chain_hash_fast_t *a_block_hash)
{
    return dap_chain_block_cache_get_by_hash(a_blocks, a_block_hash);
}

/**
 * @brief Wrapper for dap_chain_block_cache_get_by_number
 * 
 * This function is called from CLI code and can be intercepted
 * by --wrap linker flag in unit tests.
 */
dap_chain_block_cache_t *dap_chain_block_cache_get_by_number_w(
    dap_chain_type_blocks_t *a_blocks, 
    uint64_t a_block_number)
{
    return dap_chain_block_cache_get_by_number(a_blocks, a_block_number);
}

/**
 * @brief Wrapper for getting blocks count
 * 
 * This function is called from CLI code and can be intercepted
 * by --wrap linker flag in unit tests.
 */
uint64_t dap_chain_type_blocks_get_count_w(dap_chain_type_blocks_t *a_blocks)
{
    return dap_chain_type_blocks_get_count(a_blocks);
}

/**
 * @brief Wrapper for getting last block
 * 
 * This function is called from CLI code and can be intercepted
 * by --wrap linker flag in unit tests.
 */
dap_chain_block_cache_t *dap_chain_type_blocks_get_last_w(dap_chain_type_blocks_t *a_blocks)
{
    return dap_chain_type_blocks_get_last(a_blocks);
}
