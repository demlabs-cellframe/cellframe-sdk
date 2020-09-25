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
#include <stddef.h>
#include "string.h"
#include "dap_common.h"
#include "dap_hash.h"

#include "dap_chain_block.h"
#include "dap_chain_block_cache.h"

#define LOG_TAG "dap_chain_block"

/**
 * @brief dap_chain_block_init
 * @return
 */
int dap_chain_block_init()
{
    return 0;
}

/**
 * @brief dap_chain_block_deinit
 */
void dap_chain_block_deinit()
{

}


/**
 * @brief dap_chain_block_new
 * @param a_prev_block
 * @return
 */
dap_chain_block_t * dap_chain_block_new(dap_chain_hash_fast_t * a_prev_block )
{
    dap_chain_block_t * l_block = DAP_NEW_Z_SIZE (dap_chain_block_t,sizeof(l_block->hdr));
    if( l_block == NULL){
        log_it(L_CRITICAL, "Can't allocate memory for the new block");
        return NULL;
    }else{
        l_block->hdr.signature = DAP_CHAIN_BLOCK_SIGNATURE;
        l_block->hdr.version = 1;
        l_block->hdr.ts_created = time(NULL);
        if( a_prev_block ){
            dap_chain_block_meta_add(l_block, DAP_CHAIN_BLOCK_META_PREV,a_prev_block,sizeof (*a_prev_block) );
        }else{
            log_it(L_INFO, "Genesis block produced");
        }
        return l_block;
    }


}

// Add metadata in block
size_t dap_chain_block_meta_add(dap_chain_block_t * a_block, size_t a_block_size, uint8_t a_meta_type, const void * a_data, size_t a_data_size)
{

}


size_t dap_chain_block_datum_add(dap_chain_block_t * a_block, size_t a_block_size, dap_chain_datum_t * a_datum, size_t a_datum_size)
{
    if ( a_block) {
        dap_chain_block_cache_t * l_block_cache = dap_chain_block_cache_get(a_block, )
        uint32_t l_sections_size = ( a_block->hdr.size - sizeof(a_block->hdr) );
        if(   l_sections_size > a_section_offset ){
            if( l_sections_size > (a_section_offset + a_section_data_size ) ) {
                dap_chain_datum_t * l_section = (dap_chain_datum_t *) ( a_block->datums +a_section_offset) ;
                l_section->header.type_id = a_section_type;
                return l_section;
            }else{
                log_it(L_ERROR, "Section data size %lu is bigger then left for sections in block (%lu)"
                       ,a_section_data_size,l_sections_size - a_section_offset );
                return NULL;
            }
        }else{
            log_it(L_ERROR, "Section offset %lu is bigger then section size %lu",a_section_offset,l_sections_size);
            return NULL;
        }
    }else{
        log_it(L_ERROR, "Block is NULL");
        return NULL;
    }
}

void dap_chain_block_datum_del_by_hash(dap_chain_block_t * a_block, size_t a_block_size, dap_chain_hash_fast_t* a_datum_hash);

