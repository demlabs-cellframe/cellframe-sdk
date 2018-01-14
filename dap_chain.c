/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
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



#include "dap_chain_internal.h"
#include "dap_chain.h"

#define LOG_TAG "dap_chain"

/**
 * @brief dap_chain_init
 * @return
 */
int dap_chain_init()
{

}

/**
 * @brief dap_chain_deinit
 */
void dap_chain_deinit()
{

}


/**
 * @brief dap_chain_open
 * @param a_file_storage
 * @param a_file_cache
 * @return
 */
dap_chain_t * dap_chain_open(const char * a_file_storage,const char * a_file_cache)
{
    dap_chain_t * l_chain = DAP_NEW_Z(dap_chain_t);

    l_chain->difficulty = 4;

    DAP_CHAIN_INTERNAL_LOCAL_NEW(l_chain);

    l_chain_internal->file_storage_type = 0x0000; // TODO compressed format
    l_chain_internal->file_storage = fopen(a_file_storage,"a+");

    return l_chain;
}

/**
 * @brief dap_chain_remap
 * @param a_chain
 * @param a_offset
 */
void dap_chain_remap(dap_chain_t * a_chain, size_t a_offset)
{

}

/**
 * @brief dap_chain_save
 * @param a_chain
 */
void dap_chain_save(dap_chain_t * a_chain)
{

}

/**
 * @brief dap_chain_close
 * @param a_chain
 */
void dap_chain_close(dap_chain_t * a_chain)
{

}

/**
 * @brief dap_chain_info_dump_log
 * @param a_chain
 */
void dap_chain_info_dump_log(dap_chain_t * a_chain)
{

}

dap_chain_block_cache_t* dap_chain_allocate_next_block(dap_chain_t * a_chain)
{
    dap_chain_block_t* l_block = NULL;
    dap_chain_block_cache_t* l_block_cache = NULL;
    if ( a_chain->block_last )
        l_block = dap_chain_block_new( &a_chain->block_last->block_hash );
    else
        l_block = dap_chain_block_new( NULL );

    if( l_block ){
        l_block->header.difficulty = a_chain->difficulty;
        l_block_cache = dap_chain_block_cache_new(l_block);
        return l_block_cache;
    }else{
        log_it(L_ERROR, "Can't allocate next block!");
        return NULL;
    }
}
