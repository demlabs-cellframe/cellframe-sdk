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
#include <stdlib.h>
#include <time.h>
#include "dap_common.h"
#include "dap_chain_block_cache.h"
#include "dap_chain_datum_coin.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_in.h"
#include "dap_chain_datum_tx_out.h"

#define LOG_TAG "dap_chain_block_cache"

dap_chain_block_cache_t * dap_chain_block_cache_new(dap_chain_block_t * a_block)
{
    dap_chain_block_cache_t * l_block_cache = DAP_NEW_Z(dap_chain_block_cache_t);
    l_block_cache->block = a_block;
    log_it(L_DEBUG,"Block cache created");
    return l_block_cache;
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

/**
 * @brief dap_chain_block_cache_dump
 * @param a_block_cache
 */
void dap_chain_block_cache_dump(dap_chain_block_cache_t * a_block_cache)
{
    if ( a_block_cache ) {
        dap_chain_block_t * l_block = a_block_cache->block;
        if( l_block ){
            char * l_hash_str = dap_chain_hash_to_str_new(&a_block_cache->block_hash);
            char * l_prev_hash_str = dap_chain_hash_to_str_new(&l_block->header.prev_block);
            char * l_root_sections_str = dap_chain_hash_to_str_new(&l_block->header.root_sections);
            log_it(L_INFO, "  **  block_hash        %s",l_hash_str);
            log_it(L_INFO, "  **    version         %d",l_block->header.version);
            log_it(L_INFO, "  **    timestamp       %s",  ctime(  (time_t*) &l_block->header.timestamp) );
            log_it(L_INFO, "  **    difficulty      %llu",l_block->header.difficulty);
            log_it(L_INFO, "  **    nonce           %llu",l_block->header.nonce);
            log_it(L_INFO, "  **    prev_block      %s",l_prev_hash_str);
            log_it(L_INFO, "  **    root_sections   %s",l_root_sections_str  );
            log_it(L_INFO, "  **    size           %u",l_block->header.size);
            log_it(L_INFO, "  **    sections[]");
            DAP_DELETE(l_hash_str);
            DAP_DELETE(l_prev_hash_str);

            size_t i, l_sections_size = l_block->header.size - sizeof(l_block->header);
            for( i = 0; i< l_sections_size; i++ ){
                dap_chain_datum_t * l_datum = (dap_chain_datum_t *) (l_block->datums + i);
                switch ( l_datum->header.type_id  ) {
                    case DAP_CHAIN_DATUM_TX:{
                        dap_chain_datum_tx_t * l_tx = (dap_chain_datum_tx_t *) l_datum->data;
                        log_it(L_INFO, "  **      tx");
                        log_it(L_INFO, "  **          lock_time       %s", l_tx->header.lock_time?
                                   ctime( (time_t *) &l_tx->header.lock_time ) : "0x0000000000000000" );
                        log_it(L_INFO, "  **          tx_items_size   %u ",l_tx->header.tx_items_size);
                        /*uint32_t l_data_offset;
                        for ( l_data_offset = 0; l_data_offset < l_tx->header.tx_items_size; ++l_data_offset  ){

                        }*/
                        i += sizeof (l_tx->header);
                        i += l_tx->header.tx_items_size ;
                    }break;
                    default:
                        i = l_sections_size;
                }
            }
        }else{
            log_it(L_ERROR,"block in block cache for dump is NULL");
        }
    }else{
        log_it(L_ERROR,"block cache for dump is NULL");
    }

}

/**
 * @brief dap_chain_block_cache_sections_size_grow
 * @param a_block_cache
 * @param a_sections_size_grow
 */
dap_chain_block_t* dap_chain_block_cache_sections_size_grow(dap_chain_block_cache_t * a_block_cache,size_t a_sections_size_grow )
{
    log_it(L_DEBUG,"Block section size reallocation: grow up +%lu",a_sections_size_grow);
    a_block_cache->block->header.size += a_sections_size_grow;
    a_block_cache->block=(dap_chain_block_t *) realloc(a_block_cache->block,a_block_cache->block->header.size );
    if( a_block_cache->block ){
        a_block_cache->sections_size += a_sections_size_grow;
        return a_block_cache->block;
    }else{
        log_it(L_ERROR, "Can't reallocate block!");
        return NULL;
    }
}

