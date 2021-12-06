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
#include "dap_chain_net.h"
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
dap_chain_block_t *dap_chain_block_new(dap_chain_hash_fast_t *a_prev_block, size_t *a_block_size)
{
    dap_chain_block_t * l_block = DAP_NEW_Z_SIZE (dap_chain_block_t,sizeof(l_block->hdr));
    if( l_block == NULL){
        log_it(L_CRITICAL, "Can't allocate memory for the new block");
        return NULL;
    }else{
        l_block->hdr.signature = DAP_CHAIN_BLOCK_SIGNATURE;
        l_block->hdr.version = 1;
        l_block->hdr.ts_created = time(NULL);
        size_t l_block_size = sizeof(l_block->hdr);
        if( a_prev_block ){
            l_block_size = dap_chain_block_meta_add(&l_block, l_block_size, DAP_CHAIN_BLOCK_META_PREV,
                                                    a_prev_block, sizeof(*a_prev_block));
        }else{
            l_block_size = dap_chain_block_meta_add(&l_block, l_block_size, DAP_CHAIN_BLOCK_META_GENESIS, NULL, 0);
            log_it(L_INFO, "Genesis block produced");
        }
        if (a_block_size)
            *a_block_size = l_block_size;
        return l_block;
    }
}

/**
 * @brief s_block_get_datum_offset
 * @param a_block
 * @param a_block_size
 * @return
 */
size_t s_block_get_datum_offset (dap_chain_block_t * a_block, size_t a_block_size)
{
    if( a_block_size < sizeof(a_block->hdr) ){
        log_it(L_ERROR, "Can't get datum offset: corrupted block size %zu / header size %zu", a_block_size, sizeof (a_block->hdr));
    }
    size_t l_offset = 0;
    dap_chain_block_meta_t * l_meta=NULL;
    for( size_t i = 0; i< a_block->hdr.meta_count &&
                       l_offset < (a_block_size-sizeof (a_block->hdr)) &&
                       sizeof (l_meta->hdr) <=  (a_block_size-sizeof (a_block->hdr)) - l_offset ; i++){
        l_meta =(dap_chain_block_meta_t *) (a_block->meta_n_datum_n_sign +l_offset);
        size_t l_meta_data_size = l_meta->hdr.data_size;
        if (l_meta_data_size + sizeof (l_meta->hdr) + l_offset <= (a_block_size-sizeof (a_block->hdr)) ){
            l_offset += sizeof (l_meta->hdr);
            l_offset += l_meta_data_size;
        }else
            l_offset = (a_block_size-sizeof (a_block->hdr));
    }
    return l_offset;
}

//
/**
 * @brief dap_chain_block_meta_add
 * @details Add metadata in block
 * @param a_block_ptr
 * @param a_block_size
 * @param a_meta_type
 * @param a_data
 * @param a_data_size
 * @return
 */
size_t dap_chain_block_meta_add(dap_chain_block_t ** a_block_ptr, size_t a_block_size, uint8_t a_meta_type, const void * a_data, size_t a_data_size)
{
    assert(a_block_ptr);
    dap_chain_block_t * l_block = *a_block_ptr;
    dap_chain_block_meta_t * l_meta = NULL;
    if( a_block_size < sizeof(l_block->hdr) ){
        log_it(L_ERROR,"Meta add: Corrupted block size %zd thats smaller then block header size %zd ", a_block_size, sizeof (l_block->hdr));
        return 0;
    }
    if(l_block->hdr.meta_count == UINT16_MAX){
        log_it(L_ERROR,"Meta add: Can't add more, maximum meta count %hu is achieved", UINT16_MAX);
        return 0;
    }
    if( UINT32_MAX - l_block->hdr.meta_n_datum_n_signs_size < a_data_size + sizeof (l_meta->hdr) ){
        log_it(L_ERROR,"Meta add: Can't add more, maximum block data section size %u achieved", UINT32_MAX);
        return 0;
    }

    size_t l_add_size = sizeof(l_meta->hdr) + a_data_size;
    *a_block_ptr = l_block = DAP_REALLOC(l_block, a_block_size + l_add_size);
    size_t l_offset = s_block_get_datum_offset(l_block, a_block_size);
    size_t l_datum_n_sign_copy_size = a_block_size - sizeof(l_block->hdr) - l_offset;
    if (l_datum_n_sign_copy_size) {
        byte_t *l_meta_end = l_block->meta_n_datum_n_sign + l_offset;
        memmove(l_meta_end + l_add_size, l_meta_end, l_datum_n_sign_copy_size);
    }
    l_meta = (dap_chain_block_meta_t *)(l_block->meta_n_datum_n_sign + l_offset); // Update data end in reallocated block
    l_meta->hdr.data_size = a_data_size;
    l_meta->hdr.type = a_meta_type;
    if (a_data_size)
        memcpy(l_meta->data, a_data, a_data_size);
    l_block->hdr.meta_n_datum_n_signs_size = l_offset + l_datum_n_sign_copy_size;
    l_block->hdr.meta_count++;
    return a_block_size + l_add_size;
}

/**
 * @brief dap_chain_block_datum_add
 * @param a_block_ptr
 * @param a_block_size
 * @param a_datum
 * @param a_datum_size
 * @return
 */
size_t dap_chain_block_datum_add(dap_chain_block_t ** a_block_ptr, size_t a_block_size, dap_chain_datum_t * a_datum, size_t a_datum_size)
{
    assert(a_block_ptr);
    dap_chain_block_t * l_block = *a_block_ptr;
    assert(l_block);
    assert(a_datum_size);
    size_t l_offset = s_block_get_datum_offset(l_block,a_block_size);
    dap_chain_datum_t * l_datum =(dap_chain_datum_t *) (l_block->meta_n_datum_n_sign + l_offset);
    // Pass all datums to the end
    for(size_t n=0; n<l_block->hdr.datum_count && l_offset<(a_block_size-sizeof (l_block->hdr)) ; n++){
        size_t l_datum_size = dap_chain_datum_size(l_datum);

        // Check if size 0
        if(! l_datum_size){
            log_it(L_ERROR,"Datum size is 0, smth is corrupted in block");
            return a_block_size;
        }
        // Check if size of of block size
        if (l_datum_size+l_offset >(a_block_size-sizeof (l_block->hdr))){
            log_it(L_ERROR,"Datum size is too big %zu thats with offset %zu is bigger than block size %zu (without header)", l_datum_size, l_offset,
                   (a_block_size-sizeof (l_block->hdr)));
            return a_block_size;
        }
        // update offset and current datum pointer
        l_offset += l_datum_size;
        l_datum =(dap_chain_datum_t *) (l_block->meta_n_datum_n_sign + l_offset);
    }
    if (l_offset> (a_block_size-sizeof (l_block->hdr))){
        log_it(L_ERROR,"Offset %zd is bigger than block size %zd (without header)", l_offset, (a_block_size-sizeof (l_block->hdr)));
        return a_block_size;
    }
    if (a_datum_size + l_block->hdr.meta_n_datum_n_signs_size < UINT32_MAX && l_block->hdr.datum_count < UINT16_MAX) {
        // If were signs - they would be deleted after because signed should be all the block filled
        *a_block_ptr = l_block = DAP_REALLOC(l_block, sizeof(l_block->hdr) + l_offset + a_datum_size);
        memcpy(l_block->meta_n_datum_n_sign + l_offset, a_datum, a_datum_size);
        l_offset += a_datum_size;
        l_block->hdr.datum_count++;
        l_block->hdr.meta_n_datum_n_signs_size = l_offset;
        return l_offset + sizeof(l_block->hdr);
    }else{
        //log_it(L_ERROR,"");
        return a_block_size;
    }
}

/**
 * @brief dap_chain_block_datum_del_by_hash
 * @param a_block_ptr
 * @param a_block_size
 * @param a_datum_hash
 * @return
 */
size_t dap_chain_block_datum_del_by_hash(dap_chain_block_t ** a_block_ptr, size_t a_block_size, dap_chain_hash_fast_t* a_datum_hash)
{
    assert(a_block_ptr);
    dap_chain_block_t * l_block = *a_block_ptr;
    assert(l_block);
    assert(a_datum_hash);
    if(a_block_size>=sizeof (l_block->hdr)){
        log_it(L_ERROR, "Corrupted block, block size %zd is lesser than block header size %zd", a_block_size,sizeof (l_block->hdr));
        return 0;
    }
    size_t l_offset = s_block_get_datum_offset(l_block,a_block_size);
    dap_chain_datum_t * l_datum =(dap_chain_datum_t *) (l_block->meta_n_datum_n_sign + l_offset);
    // Pass all datums to the end
    for(size_t n=0; n<l_block->hdr.datum_count && l_offset<(a_block_size-sizeof (l_block->hdr)) ; n++){
        size_t l_datum_size = dap_chain_datum_size(l_datum);

        // Check if size 0
        if(! l_datum_size){
            log_it(L_ERROR,"Datum size is 0, smth is corrupted in block");
            return a_block_size;
        }
        // Check if size of of block size
        if (l_datum_size+l_offset >(a_block_size-sizeof (l_block->hdr))){
            log_it(L_ERROR,"Datum size is too big %zu thats with offset %zu is bigger than block size %zu(without hdr)", l_datum_size, l_offset,
                   (a_block_size-sizeof (l_block->hdr)));
            return a_block_size;
        }
        // Calc current datum hash
        dap_chain_hash_fast_t l_datum_hash;
        dap_hash_fast(l_datum,l_datum_size,&l_datum_hash);
        // Check datum hash and delete if compares successfuly
        if (dap_hash_fast_compare(&l_datum_hash,a_datum_hash)){
            memmove(l_datum, (byte_t*)l_datum +l_datum_size,(a_block_size-sizeof (l_block->hdr))-l_offset-l_datum_size );
            *a_block_ptr = l_block = DAP_REALLOC(l_block, a_block_size - l_datum_size);
            l_block->hdr.datum_count--;
            l_block->hdr.meta_n_datum_n_signs_size -= l_datum_size;
            // here we don't update offset
        }else{
            // update offset
            l_offset += l_datum_size;
        }
        // Updae current datum pointer, if it was deleted - we also need to update it after realloc
        l_datum =(dap_chain_datum_t *) (l_block->meta_n_datum_n_sign + l_offset);

    }
    if (l_offset> (a_block_size-sizeof (l_block->hdr))){
        log_it(L_ERROR,"Offset %zd is bigger than block size %zd (without header)", l_offset, (a_block_size-sizeof (l_block->hdr)));
        return a_block_size;
    }

    return l_offset;
}

/**
 * @brief s_block_get_sign_offset
 * @param a_block
 * @param a_block_size
 * @return
 */
size_t dap_chain_block_get_sign_offset(dap_chain_block_t *a_block, size_t a_block_size)
{
    assert(a_block);
    assert(a_block_size);
    if (a_block_size <= sizeof(a_block->hdr)) {
        log_it(L_ERROR, "Get sign: corrupted block, block size %zd is lesser than block header size %zd", a_block_size,sizeof (a_block->hdr));
        return 0;
    }

    size_t l_offset = s_block_get_datum_offset(a_block,a_block_size);
    dap_chain_datum_t * l_datum =(dap_chain_datum_t *) (a_block->meta_n_datum_n_sign + l_offset);
    // Pass all datums to the end
    for(size_t n=0; n<a_block->hdr.datum_count && l_offset< (a_block_size-sizeof (a_block->hdr)) ; n++){
        size_t l_datum_size = dap_chain_datum_size(l_datum);

        // Check if size 0
        if(! l_datum_size){
            log_it(L_ERROR,"Datum size is 0, smth is corrupted in block");
            return a_block_size;
        }
        // Check if size of of block size
        if ( (l_datum_size+l_offset) > (a_block_size-sizeof (a_block->hdr)) ){
            log_it(L_ERROR,"Datum size is too big %zu thats with offset %zu is bigger than block size %zu", l_datum_size, l_offset, a_block_size);
            return a_block_size;
        }
        l_offset += l_datum_size;
        // Updae current datum pointer, if it was deleted - we also need to update it after realloc
        l_datum =(dap_chain_datum_t *) (a_block->meta_n_datum_n_sign + l_offset);
    }
    if (l_offset> (a_block_size-sizeof (a_block->hdr))){
        log_it(L_ERROR,"Offset %zd with block header %zu is bigger than block size %zu", l_offset,sizeof (a_block->hdr),a_block_size);
        return a_block_size;
    }

    return l_offset;
}

/**
 * @brief dap_chain_block_sign_add
 * @param a_block_ptr
 * @param a_block_size
 * @param a_cert
 * @return
 */
size_t dap_chain_block_sign_add(dap_chain_block_t **a_block_ptr, size_t a_block_size, dap_enc_key_t *a_key)
{
    assert(a_block_ptr);
    dap_chain_block_t *l_block = *a_block_ptr;
    size_t l_offset = dap_chain_block_get_sign_offset(l_block, a_block_size);
    dap_sign_t *l_block_sign = dap_sign_create(a_key, l_block, l_offset + sizeof(l_block->hdr), 0);
    size_t l_block_sign_size = dap_sign_get_size(l_block_sign);
    if (!l_block_sign_size)
        return 0;
    *a_block_ptr = l_block = DAP_REALLOC(l_block, l_block_sign_size + a_block_size);
    memcpy(((byte_t *)l_block) + a_block_size, l_block_sign, l_block_sign_size);
    DAP_DELETE(l_block_sign);
    return a_block_size + l_block_sign_size;
}

/**
 * @brief dap_chain_block_sign_get
 * @param a_block
 * @param a_block_size
 * @param a_sign_num
 * @return
 */
dap_sign_t *dap_chain_block_sign_get ( dap_chain_block_t * a_block, size_t a_block_size, uint16_t a_sign_num )
{
    assert(a_block);
    size_t l_offset = dap_chain_block_get_sign_offset(a_block, a_block_size);
    uint16_t l_sign_cur = 0;
    dap_sign_t *l_sign = (dap_sign_t *)(a_block->meta_n_datum_n_sign + l_offset);
    while (l_sign_cur < a_sign_num) {

        size_t l_sign_size = dap_sign_get_size(l_sign);
        if (!l_sign_size){
            log_it(L_ERROR, "Empty sign #%u",  l_sign_cur );
            return NULL;
        }
        if (l_sign_size >  a_block_size- l_offset - sizeof (a_block->hdr) ){
            log_it(L_ERROR, "Corrupted sign #%u size %zu",  l_sign_cur, l_sign_size );
            return NULL;
        }
        l_offset += l_sign_size;
        l_sign_cur++;
        l_sign = (dap_sign_t*) a_block->meta_n_datum_n_sign+l_offset;
    }
    return l_sign_cur == a_sign_num ? l_sign : NULL;
}

size_t dap_chain_block_get_signs_count(dap_chain_block_t * a_block, size_t a_block_size)
{
    assert(a_block);
    assert(a_block_size);
    uint16_t l_sign_count = 0;
    size_t l_offset = dap_chain_block_get_sign_offset(a_block,a_block_size);
    for ( ; l_offset < a_block_size; l_sign_count++) {
        dap_sign_t *l_sign = (dap_sign_t *)a_block->meta_n_datum_n_sign + l_offset;
        size_t l_sign_size = dap_sign_get_size(l_sign);
        if (!l_sign_size){
            log_it(L_WARNING, "Empty sign #%hu", l_sign_count);
            return l_sign_count;
        }
        if (l_sign_size > a_block_size - l_offset - sizeof(a_block->hdr)) {
            log_it(L_ERROR, "Corrupted sign #%hu size %zu", l_sign_count, l_sign_size);
            return l_sign_count;
        }
        l_offset += l_sign_size;
    }
    return l_sign_count;
}

/**
 * @brief dap_chain_block_get_datums
 * @param a_block
 * @param a_block_size
 * @param a_datums_count
 * @return
 */
dap_chain_datum_t** dap_chain_block_get_datums(dap_chain_block_t * a_block, size_t a_block_size,size_t * a_datums_count )
{
    assert(a_block);
    assert(a_block_size);
    if( a_block_size<sizeof (a_block->hdr)){
        log_it(L_ERROR, "Get datums: corrupted block size %zd lesser than block header size %zd", a_block_size, sizeof (a_block->hdr));
        return NULL;
    }
    if (a_datums_count)
        *a_datums_count = 0;
    if (a_block->hdr.datum_count == 0)
        return NULL;
    size_t l_offset = s_block_get_datum_offset(a_block,a_block_size);
    dap_chain_datum_t * l_datum =(dap_chain_datum_t *) (a_block->meta_n_datum_n_sign + l_offset);
    dap_chain_datum_t ** l_ret =DAP_NEW_Z_SIZE( dap_chain_datum_t *, sizeof (dap_chain_datum_t *)* a_block->hdr.datum_count);

    for(size_t n=0; n<a_block->hdr.datum_count && l_offset<(a_block_size-sizeof (a_block->hdr)) ; n++){
        size_t l_datum_size = dap_chain_datum_size(l_datum);

        // Check if size 0
        if(! l_datum_size){
            log_it(L_ERROR,"Datum size in block is 0");
            return l_ret;
        }
        // Check if size of of block size
        if (l_datum_size+l_offset >(a_block_size-sizeof (a_block->hdr))){
            log_it(L_ERROR,"Datum size is too big %zu thats with offset %zu is bigger than block size %zu (without header)", l_datum_size, l_offset,
                   (a_block_size-sizeof (a_block->hdr)));
            return l_ret;
        }
        l_ret[n] = l_datum;
        if (a_datums_count)
            (*a_datums_count)++;
        // Update current datum pointer and offset
        l_offset += l_datum_size;
        l_datum =(dap_chain_datum_t *) (a_block->meta_n_datum_n_sign + l_offset);
    }
    if (l_offset> (a_block_size-sizeof (a_block->hdr))){
        log_it(L_ERROR,"Offset %zd is bigger than block size %zd (without header)", l_offset, (a_block_size-sizeof (a_block->hdr)));
    }

    return l_ret;
}

/**
 * @brief dap_chain_block_get_meta
 * @param a_block
 * @param a_block_size
 * @param a_meta_count
 * @return
 */
dap_chain_block_meta_t** dap_chain_block_get_meta(dap_chain_block_t * a_block, size_t a_block_size,size_t * a_meta_count )
{
    if( a_block_size < sizeof(a_block->hdr) ){
        log_it(L_ERROR,"Get meta: corrupted block size %zu thats smaller then block header size %zu", a_block_size, sizeof (a_block->hdr));
    }
    if (a_meta_count)
        *a_meta_count = 0;
    if (a_block->hdr.meta_count == 0) // no meta - nothing to return
        return NULL;
    size_t l_offset = 0;
    dap_chain_block_meta_t * l_meta=NULL;
    dap_chain_block_meta_t ** l_ret = DAP_NEW_Z_SIZE(dap_chain_block_meta_t *,sizeof (dap_chain_block_meta_t *)* a_block->hdr.meta_count );
    for( size_t i = 0; i< a_block->hdr.meta_count &&
                       l_offset < (a_block_size-sizeof (a_block->hdr)) &&
                       sizeof (l_meta->hdr) <=  (a_block_size-sizeof (a_block->hdr)) - l_offset ; i++){
        l_meta =(dap_chain_block_meta_t *) (a_block->meta_n_datum_n_sign +l_offset);
        size_t l_meta_data_size = l_meta->hdr.data_size;
        if (l_meta_data_size + sizeof (l_meta->hdr) + l_offset <= (a_block_size-sizeof (a_block->hdr)) ){
            l_ret[i] = l_meta;
            if (a_meta_count)
                (*a_meta_count)++;
            l_offset += sizeof(l_meta->hdr) + l_meta_data_size;
        }else {
            log_it(L_WARNING, "Get meta: corrupted block, can read only %zu from %hu metas", i, a_block->hdr.meta_count);
            return l_ret;
        }
    }
    return l_ret;
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
                                    dap_chain_hash_fast_t *a_merkle,
                                    dap_chain_hash_fast_t ** a_block_links,
                                    size_t *a_block_links_count,
                                    bool * a_is_genesis,
                                    uint64_t *a_nonce,
                                    uint64_t *a_nonce2
                                  )
{
    if (!a_meta || !a_meta_count)
        return;
    // Check for meta that could be faced only once
    bool l_was_prev = false;
    bool l_was_genesis = false;
    bool l_was_anchor = false;
    bool l_was_nonce = false;
    bool l_was_nonce2 = false;
    bool l_was_merkle = false;
    // Init links parsing
    size_t l_links_count_max = 5;
    if (a_block_links_count)
        *a_block_links_count = 0;


    for(size_t i = 0; i < a_meta_count; i++){
        dap_chain_block_meta_t * l_meta = a_meta[i];
        switch (l_meta->hdr.type) {
            case DAP_CHAIN_BLOCK_META_GENESIS:
                if(l_was_genesis){
                    log_it(L_WARNING, "Genesis meta could be only one in the block, meta #%zu is ignored ", i);
                    break;
                }
                l_was_genesis = true;
                if (a_is_genesis)
                    *a_is_genesis = true;
            break;
            case DAP_CHAIN_BLOCK_META_PREV:
                if(l_was_prev){
                    log_it(L_WARNING, "Prev meta could be only one in the block, meta #%zu is ignored ", i);
                    break;
                }
                l_was_prev = true;
                if (a_block_prev_hash){
                    if (l_meta->hdr.data_size == sizeof (*a_block_prev_hash) )
                        memcpy(a_block_prev_hash, l_meta->data, l_meta->hdr.data_size);
                    else
                        log_it(L_WARNING, "Meta  #%zu PREV has wrong size %hu when expecting %zu",i, l_meta->hdr.data_size, sizeof (*a_block_prev_hash));
                }
            break;
            case DAP_CHAIN_BLOCK_META_ANCHOR:
                if(l_was_anchor){
                    log_it(L_WARNING, "Anchor meta could be only one in the block, meta #%zu is ignored ", i);
                    break;
                }
                l_was_anchor = true;
                if ( a_block_anchor_hash){
                    if (l_meta->hdr.data_size == sizeof (*a_block_anchor_hash) )
                        memcpy(a_block_anchor_hash, l_meta->data, l_meta->hdr.data_size);
                    else
                        log_it(L_WARNING, "Anchor meta #%zu has wrong size %hu when expecting %zu",i, l_meta->hdr.data_size, sizeof (*a_block_prev_hash));
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

                    if (l_meta->hdr.data_size == sizeof (**a_block_links) ){
                        memcpy(&a_block_links[*a_block_links_count], l_meta->data, l_meta->hdr.data_size);
                        (*a_block_links_count)++;
                    }else
                        log_it(L_WARNING, "Link meta #%zu has wrong size %hu when expecting %zu", i, l_meta->hdr.data_size, sizeof (*a_block_prev_hash));
                }
            break;
            case DAP_CHAIN_BLOCK_META_NONCE:
                if(l_was_nonce){
                    log_it(L_WARNING, "NONCE could be only one in the block, meta #%zu is ignored ", i);
                    break;
                }
                l_was_nonce = true;

                if ( a_nonce){
                    if (l_meta->hdr.data_size == sizeof (*a_nonce ) )
                        memcpy(a_nonce, l_meta->data, l_meta->hdr.data_size);
                    else
                        log_it(L_WARNING, "NONCE meta #%zu has wrong size %hu when expecting %zu",i, l_meta->hdr.data_size, sizeof (*a_nonce));
                }
            break;
            case DAP_CHAIN_BLOCK_META_NONCE2:
                if(l_was_nonce2){
                    log_it(L_WARNING, "NONCE2 could be only one in the block, meta #%zu is ignored ", i);
                    break;
                }
                l_was_nonce2 = true;
                if ( a_nonce2){
                    if (l_meta->hdr.data_size == sizeof (*a_nonce2 ) )
                        memcpy(a_nonce2, l_meta->data, l_meta->hdr.data_size);
                    else
                        log_it(L_WARNING, "NONCE2 meta #%zu has wrong size %hu when expecting %zu",i, l_meta->hdr.data_size, sizeof (*a_nonce2));
                }
            break;
            case DAP_CHAIN_BLOCK_META_MERKLE:
                if(l_was_merkle){
                    log_it(L_WARNING, "Merckle root could be only one in the block, meta #%zu is ignored ", i);
                    break;
                }
                l_was_merkle = true;
                if (a_merkle) {
                    if (l_meta->hdr.data_size == sizeof(*a_merkle))
                        memcpy(a_merkle, l_meta->data, l_meta->hdr.data_size);
                    else
                        log_it(L_WARNING, "Merkle root meta #%zu has wrong size %hu when expecting %zu", i, l_meta->hdr.data_size, sizeof (*a_nonce2));
                }
            break;
            default: { log_it(L_WARNING, "Unknown meta #%zu type 0x%02hx (size %hu), possible corrupted block or you need to upgrade your software",
                                 i, l_meta->hdr.type, l_meta->hdr.type); }
        }
    }
}
