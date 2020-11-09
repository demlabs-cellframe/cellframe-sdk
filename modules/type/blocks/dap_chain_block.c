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
#include "dap_config.h"
#include "dap_hash.h"

#include "dap_chain_block.h"
#include "dap_chain_block_cache.h"

#define LOG_TAG "dap_chain_block"

bool s_seed_mode = false;

/**
 * @brief dap_chain_block_init
 * @return
 */
int dap_chain_block_init()
{
    s_seed_mode = dap_config_get_item_bool_default(g_config,"general","seed_mode",false);

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
        size_t l_block_size = sizeof (l_block->hdr);
        if( a_prev_block ){
            l_block_size = dap_chain_block_meta_add(l_block, l_block_size, DAP_CHAIN_BLOCK_META_PREV,a_prev_block,sizeof (*a_prev_block) );
        }else{
            log_it(L_INFO, "Genesis block produced");
        }
        return l_block;
    }


}

// Add metadata in block
size_t dap_chain_block_meta_add(dap_chain_block_t * a_block, size_t a_block_size, uint8_t a_meta_type, const void * a_data, size_t a_data_size)
{
    return a_block_size;
}


size_t dap_chain_block_datum_add(dap_chain_block_t * a_block, size_t a_block_size, dap_chain_datum_t * a_datum, size_t a_datum_size)
{
    if ( a_block) {
        //
    }else{
        log_it(L_ERROR, "Block is NULL");
        return a_block_size;
    }
}

size_t dap_chain_block_datum_del_by_hash(dap_chain_block_t * a_block, size_t a_block_size, dap_chain_hash_fast_t* a_datum_hash)
{
    return a_block_size;
}

dap_chain_datum_t** dap_chain_block_get_datums(dap_chain_block_t * a_block, size_t a_block_size,size_t * a_datums_count )
{

}

dap_chain_block_meta_t** dap_chain_block_get_meta(dap_chain_block_t * a_block, size_t a_block_size,size_t * a_meta_count )
{

}

/**
 * @brief dap_chain_block_meta_extract_generals
 * @param a_meta
 * @param a_meta_count
 * @param a_block_prev_hash
 * @param a_block_anchor_hash
 * @param a_is_genesis
 * @param a_nonce
 * @param a_nonce2
 */
void dap_chain_block_meta_extract(dap_chain_block_meta_t ** a_meta, size_t a_meta_count,
                                    dap_chain_hash_fast_t * a_block_prev_hash,
                                    dap_chain_hash_fast_t * a_block_anchor_hash,
                                    dap_chain_hash_fast_t ** a_block_links,
                                    size_t *a_block_links_count,
                                    bool * a_is_genesis,
                                    uint64_t *a_nonce,
                                    uint64_t *a_nonce2
                                  )
{
    // Check for meta that could be faced only once
    bool l_was_prev = false;
    bool l_was_genesis = false;
    bool l_was_anchor = false;
    bool l_was_nonce = false;
    bool l_was_nonce2 = false;
    // Init links parsing
    size_t l_links_count_max = 5;
    if (a_block_links_count)
        *a_block_links_count = 0;


    for(size_t i = 0; i < a_meta_count; i++){
        dap_chain_block_meta_t * l_meta = a_meta[i];
        switch (l_meta->hdr.type) {
            case DAP_CHAIN_BLOCK_META_GENESIS:
                if(l_was_genesis){
                    log_it(L_WARNING, "Genesis meta could be only one in the block, meta #%u is ignored ", i);
                    break;
                }
                l_was_genesis = true;
                if (a_is_genesis)
                    *a_is_genesis = true;
            break;
            case DAP_CHAIN_BLOCK_META_PREV:
                if(l_was_prev){
                    log_it(L_WARNING, "Prev meta could be only one in the block, meta #%u is ignored ", i);
                    break;
                }
                l_was_prev = true;
                if (a_block_prev_hash){
                    if (l_meta->hdr.size == sizeof (*a_block_prev_hash) )
                        memcpy(a_block_prev_hash, l_meta->data, l_meta->hdr.size);
                    else
                        log_it(L_WARNING, "Meta  #%zd PREV has wrong size %zd when expecting %zd",i, l_meta->hdr.size, sizeof (*a_block_prev_hash));
                }
            break;
            case DAP_CHAIN_BLOCK_META_ANCHOR:
                if(l_was_anchor){
                    log_it(L_WARNING, "Anchor meta could be only one in the block, meta #%u is ignored ", i);
                    break;
                }
                l_was_anchor = true;
                if ( a_block_anchor_hash){
                    if (l_meta->hdr.size == sizeof (*a_block_anchor_hash) )
                        memcpy(a_block_anchor_hash, l_meta->data, l_meta->hdr.size);
                    else
                        log_it(L_WARNING, "Anchor meta #%zd has wrong size %zd when expecting %zd",i, l_meta->hdr.size, sizeof (*a_block_prev_hash));
                }
            break;
            case DAP_CHAIN_BLOCK_META_LINK:
                if ( a_block_links && a_block_links_count){
                    if ( *a_block_links_count == 0 ){
                        *a_block_links = DAP_NEW_Z_SIZE(dap_chain_hash_fast_t, sizeof (dap_chain_hash_fast_t *) *l_links_count_max);
                        *a_block_links_count = 0;
                    }else if ( *a_block_links_count == l_links_count_max ){
                        l_links_count_max *=2;
                        *a_block_links = DAP_REALLOC(*a_block_links, l_links_count_max);
                    }

                    if (l_meta->hdr.size == sizeof (**a_block_links) ){
                        memcpy(&a_block_links[*a_block_links_count], l_meta->data, l_meta->hdr.size);
                        (*a_block_links_count)++;
                    }else
                        log_it(L_WARNING, "Link meta #%zd has wrong size %zd when expecting %zd", i, l_meta->hdr.size, sizeof (*a_block_prev_hash));
                }
            break;
            case DAP_CHAIN_BLOCK_META_NONCE:
                if(l_was_nonce){
                    log_it(L_WARNING, "NONCE could be only one in the block, meta #%u is ignored ", i);
                    break;
                }
                l_was_nonce = true;

                if ( a_nonce){
                    if (l_meta->hdr.size == sizeof (*a_nonce ) )
                        memcpy(a_nonce, l_meta->data, l_meta->hdr.size);
                    else
                        log_it(L_WARNING, "NONCE meta #%zd has wrong size %zd when expecting %zd",i, l_meta->hdr.size, sizeof (*a_nonce));
                }
            break;
            case DAP_CHAIN_BLOCK_META_NONCE2:
                if(l_was_nonce2){
                    log_it(L_WARNING, "NONCE2 could be only one in the block, meta #%u is ignored ", i);
                    break;
                }
                l_was_nonce2 = true;
                if ( a_nonce2){
                    if (l_meta->hdr.size == sizeof (*a_nonce2 ) )
                        memcpy(a_nonce2, l_meta->data, l_meta->hdr.size);
                    else
                        log_it(L_WARNING, "NONCE2 meta #%zd has wrong size %zd when expecting %zd",i, l_meta->hdr.size, sizeof (*a_nonce2));
                }
            break;
            default: { log_it(L_WARNING, "Unknown meta #%zd type 0x%02x (size %zd), possible corrupted block or you need to upgrade your software",
                                 i, l_meta->hdr.type, l_meta->hdr.type); }
        }
    }
}
