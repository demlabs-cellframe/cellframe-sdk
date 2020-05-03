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

#include "string.h"
#include "dap_common.h"

#include "dap_chain_block.h"

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
dap_chain_block_t * dap_chain_block_new(dap_chain_hash_t * a_prev_block )
{
    dap_chain_block_t * l_block = DAP_NEW_Z_SIZE (dap_chain_block_t,sizeof(l_block->header));
    if( l_block == NULL){
        log_it(L_CRITICAL, "Can't allocate memory for the new block");
        return NULL;
    }else{
        l_block->header.signature = DAP_CHAIN_BLOCK_SIGNATURE;
        l_block->header.version = 1;
        l_block->header.timestamp = time(NULL);
        if( a_prev_block ){
            memcpy(&l_block->header.prev_block,a_prev_block,sizeof(l_block->header.prev_block));
        }else{
            log_it(L_INFO, "Genesis block produced");
            memset(&l_block->header.prev_block,0xff,sizeof(l_block->header.prev_block));
        }

        l_block->header.size = sizeof(l_block->header);
        return l_block;
    }
}

/**
 * @brief dap_chain_block_create_section
 * @param a_block
 * @param a_section_type
 * @param a_section_data_size
 * @return
 */
dap_chain_datum_t * dap_chain_block_create_section(dap_chain_block_t * a_block, uint32_t a_section_offset,
                                                     uint16_t a_section_type, uint32_t a_section_data_size )
{
    if ( a_block) {
        uint32_t l_sections_size = ( a_block->header.size - sizeof(a_block->header) );
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

