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
#include "dap_common.h"
#include "dap_config.h"
#include "dap_hash.h"
#include "dap_uuid.h"
#include "dap_chain_block.h"

#define LOG_TAG "dap_chain_block"

bool s_seed_mode = false;
bool s_dap_block_debug_more = false;

/**
 * @brief dap_chain_block_init
 * @return
 */
int dap_chain_block_init()
{
    s_seed_mode = dap_config_get_item_bool_default(g_config,"general","seed_mode",false);
    s_dap_block_debug_more = dap_config_get_item_bool_default(g_config, "blocks", "debug_more", false);
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
 * @param a_blockreward
 * @param a_block_size
 * @return
 */
dap_chain_block_t *dap_chain_block_new(dap_chain_hash_fast_t *a_prev_block, size_t *a_block_size)
{
    dap_chain_block_t *l_block = DAP_NEW_Z(dap_chain_block_t);
    if (!l_block) {
        log_it(L_CRITICAL, "Can't allocate memory for the new block");
        return NULL;
    }
    l_block->hdr.signature = DAP_CHAIN_BLOCK_SIGNATURE;
    l_block->hdr.version = 2;
    l_block->hdr.ts_created = time(NULL);

    size_t l_block_size = sizeof(l_block->hdr);
    if (a_prev_block) {
        l_block_size = dap_chain_block_meta_add(&l_block, l_block_size, DAP_CHAIN_BLOCK_META_PREV,
                                                a_prev_block, sizeof(*a_prev_block));
    } else {
        l_block_size = dap_chain_block_meta_add(&l_block, l_block_size, DAP_CHAIN_BLOCK_META_GENESIS, NULL, 0);
        log_it(L_INFO, "Genesis block produced");
    }
    if (l_block_size) {
        uint64_t l_nonce = dap_uuid_generate_uint64();
        l_block_size = dap_chain_block_meta_add(&l_block, l_block_size, DAP_CHAIN_BLOCK_META_NONCE,
                                                &l_nonce, sizeof(uint64_t));
    }
    /*if (l_block_size && a_block_reward)
        l_block_size = dap_chain_block_meta_add(&l_block, l_block_size, DAP_CHAIN_BLOCK_META_REWARD,
                                               a_block_reward, sizeof(uint256_t));*/
    if (!l_block_size) {
        log_it(L_ERROR, "Can't add meta to block");
        DAP_DEL_Z(l_block);
    }
    if (a_block_size)
        *a_block_size = l_block_size;
    return l_block;
}

/**
 * @brief s_block_get_datum_offset
 * @param a_block
 * @param a_block_size
 * @return
 */
size_t s_block_get_datum_offset(const dap_chain_block_t *a_block, size_t a_block_size)
{
    if( a_block_size < sizeof(a_block->hdr) ){
        log_it(L_ERROR, "Can't get datum offset: corrupted block size %zu / header size %zu", a_block_size, sizeof (a_block->hdr));
        return 0;
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
        if (!l_block) {
            log_it(L_CRITICAL, "Memory reallocation error");
            return 0;
        }
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
size_t dap_chain_block_get_sign_offset(const dap_chain_block_t *a_block, size_t a_block_size)
{
    assert(a_block);
    assert(a_block_size);
    if (a_block_size <= sizeof(a_block->hdr)) {
        log_it(L_ERROR, "Get sign: corrupted block, block size %zd is lesser than block header size %zd", a_block_size,sizeof (a_block->hdr));
        return 0;
    }

    size_t l_offset = s_block_get_datum_offset(a_block, a_block_size);
    dap_chain_datum_t * l_datum =(dap_chain_datum_t *) (a_block->meta_n_datum_n_sign + l_offset);
    // Pass all datums to the end
    for(size_t n=0; n<a_block->hdr.datum_count && l_offset< (a_block_size-sizeof (a_block->hdr)) ; n++){
        size_t l_datum_size = dap_chain_datum_size(l_datum);

        // Check if size 0
        if(! l_datum_size){
            log_it(L_ERROR,"Datum size is 0, smth is corrupted in block");
            return 0;
        }
        // Check if size of of block size
        if ( (l_datum_size+l_offset) > (a_block_size-sizeof (a_block->hdr)) ){
            log_it(L_ERROR,"Datum size is too big %zu thats with offset %zu is bigger than block size %zu", l_datum_size, l_offset, a_block_size);
            return 0;
        }
        l_offset += l_datum_size;
        // Updae current datum pointer, if it was deleted - we also need to update it after realloc
        l_datum =(dap_chain_datum_t *) (a_block->meta_n_datum_n_sign + l_offset);
    }
    if (l_offset> (a_block_size-sizeof (a_block->hdr))){
        log_it(L_ERROR,"Offset %zd with block header %zu is bigger than block size %zu", l_offset,sizeof (a_block->hdr),a_block_size);
        return 0;
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
    if (!l_block) {
        log_it(L_CRITICAL, "Memory reallocation error");
        return 0;
    }
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
dap_sign_t *dap_chain_block_sign_get(const dap_chain_block_t *a_block, size_t a_block_size, uint16_t a_sign_num)
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
        l_sign = (dap_sign_t*)(a_block->meta_n_datum_n_sign+l_offset);
    }
    return l_sign_cur == a_sign_num ? l_sign : NULL;
}

size_t dap_chain_block_get_signs_count(const dap_chain_block_t * a_block, size_t a_block_size)
{
    assert(a_block);
    assert(a_block_size);
    uint16_t l_sign_count = 0;
    size_t l_offset = dap_chain_block_get_sign_offset(a_block,a_block_size);
    for ( ; l_offset+sizeof(a_block->hdr) < a_block_size; l_sign_count++) {
        dap_sign_t *l_sign = (dap_sign_t *)(a_block->meta_n_datum_n_sign + l_offset);
        size_t l_sign_size = dap_sign_get_size(l_sign);
        if (!l_sign_size){
            debug_if(s_dap_block_debug_more, L_WARNING, "Empty sign #%hu", l_sign_count);
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

bool dap_chain_block_sign_match_pkey(const dap_chain_block_t *a_block, size_t a_block_size, dap_pkey_t *a_sign_pkey)
{
    dap_return_val_if_fail(a_block && a_block_size, false);
    size_t l_offset = dap_chain_block_get_sign_offset(a_block, a_block_size);
    while (l_offset + sizeof(a_block->hdr) < a_block_size) {
        dap_sign_t *l_sign = (dap_sign_t *)(a_block->meta_n_datum_n_sign + l_offset);
        size_t l_sign_size = dap_sign_get_size(l_sign);
        if (!l_sign_size) {
            log_it(L_WARNING, "Empty or corrupted sign");
            return false;
        }
        if (dap_pkey_compare_with_sign(a_sign_pkey, l_sign))
            return true;
        l_offset += l_sign_size;
    }
    return false;
}

/**
 * @brief dap_chain_block_get_datums
 * @param a_block
 * @param a_block_size
 * @param a_datums_count
 * @return
 */
dap_chain_datum_t** dap_chain_block_get_datums(const dap_chain_block_t *a_block, size_t a_block_size, size_t * a_datums_count )
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
    dap_chain_datum_t **l_ret = DAP_NEW_Z_SIZE(dap_chain_datum_t *, sizeof(dap_chain_datum_t *) * a_block->hdr.datum_count);
    if (!l_ret) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
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
    if (!l_block) {
        log_it(L_CRITICAL, "Memory reallocation error");
        return 0;
    }
    size_t l_offset = s_block_get_datum_offset(l_block, a_block_size);
    l_meta = (dap_chain_block_meta_t *)(l_block->meta_n_datum_n_sign + l_offset); // Update data end in reallocated block
    size_t l_datum_n_sign_copy_size = a_block_size - sizeof(l_block->hdr) - l_offset;
    if (l_datum_n_sign_copy_size)
        memmove((byte_t *)l_meta + l_add_size, l_meta, l_datum_n_sign_copy_size);
    l_meta->hdr.data_size = a_data_size;
    l_meta->hdr.type = a_meta_type;
    if (a_data_size)
        memcpy(l_meta->data, a_data, a_data_size);
    l_block->hdr.meta_n_datum_n_signs_size += l_add_size;
    l_block->hdr.meta_count++;
    return a_block_size + l_add_size;
}

static const char *s_meta_type_to_string(uint8_t a_meta_type)
{
    switch (a_meta_type) {
    case DAP_CHAIN_BLOCK_META_GENESIS: return "GENESIS";
    case DAP_CHAIN_BLOCK_META_PREV: return "PREV";
    case DAP_CHAIN_BLOCK_META_ANCHOR: return "ANCHOR";
    case DAP_CHAIN_BLOCK_META_LINK: return "LINK";
    case DAP_CHAIN_BLOCK_META_NONCE: return "NONCE";
    case DAP_CHAIN_BLOCK_META_NONCE2: return "NONCE2";
    case DAP_CHAIN_BLOCK_META_MERKLE: return "MERKLE_ROOT";
    case DAP_CHAIN_BLOCK_META_EMERGENCY: return "EMERGENCY";
    case DAP_CHAIN_BLOCK_META_SYNC_ATTEMPT: return "SYNC_ATTEMPT";
    case DAP_CHAIN_BLOCK_META_ROUND_ATTEMPT: return "ROUND_ATTEMPT";
    case DAP_CHAIN_BLOCK_META_EXCLUDED_KEYS: return "EXCLUDED_KEYS";
    default: return "UNNOWN";
    }
}

static uint8_t *s_meta_extract(dap_chain_block_meta_t *a_meta)
{
    switch (a_meta->hdr.type) {
    case DAP_CHAIN_BLOCK_META_GENESIS:
    case DAP_CHAIN_BLOCK_META_EMERGENCY:
        if (a_meta->hdr.data_size == 0)
            return DAP_INT_TO_POINTER(1);
        log_it(L_WARNING, "Meta %s has wrong size %hu when expecting zero size",
               s_meta_type_to_string(a_meta->hdr.type), a_meta->hdr.data_size);
    break;
    case DAP_CHAIN_BLOCK_META_PREV:
    case DAP_CHAIN_BLOCK_META_ANCHOR:
    case DAP_CHAIN_BLOCK_META_LINK:
    case DAP_CHAIN_BLOCK_META_MERKLE:
        if (a_meta->hdr.data_size == sizeof(dap_hash_t))
            return a_meta->data;
        log_it(L_WARNING, "Meta %s has wrong size %hu when expecting %zu",
               s_meta_type_to_string(a_meta->hdr.type), a_meta->hdr.data_size, sizeof(dap_hash_t));
    break;
    case DAP_CHAIN_BLOCK_META_NONCE:
    case DAP_CHAIN_BLOCK_META_NONCE2:
    case DAP_CHAIN_BLOCK_META_SYNC_ATTEMPT:
        if (a_meta->hdr.data_size == sizeof(uint64_t))
            return a_meta->data;
        log_it(L_WARNING, "Meta %s has wrong size %hu when expecting %zu",
               s_meta_type_to_string(a_meta->hdr.type), a_meta->hdr.data_size, sizeof(uint64_t));
    break;
    case DAP_CHAIN_BLOCK_META_ROUND_ATTEMPT:
        if (a_meta->hdr.data_size == sizeof(uint8_t))
            return a_meta->data;
        log_it(L_WARNING, "Meta %s has wrong size %hu when expecting %zu",
               s_meta_type_to_string(a_meta->hdr.type), a_meta->hdr.data_size, sizeof(uint8_t));
    break;
    case DAP_CHAIN_BLOCK_META_EXCLUDED_KEYS:
        if (a_meta->hdr.data_size >= sizeof(uint16_t)) {
            uint16_t l_expected_size = *(uint16_t *)a_meta->data + sizeof(uint16_t);
            if (!(l_expected_size % sizeof(uint16_t)) &&
                    l_expected_size == a_meta->hdr.data_size)
                return a_meta->data;
        }
        log_it(L_WARNING, "Meta %s has wrong size %hu", s_meta_type_to_string(a_meta->hdr.type), a_meta->hdr.data_size);
    default:
        log_it(L_WARNING, "Unknown meta type 0x%02x (size %u), possible corrupted block or you need to upgrade your software",
                          a_meta->hdr.type, a_meta->hdr.type);
    }
    return NULL;
}

uint8_t *dap_chain_block_meta_get(const dap_chain_block_t *a_block, size_t a_block_size, uint8_t a_meta_type)
{
    if( a_block_size < sizeof(a_block->hdr) ){
        log_it(L_ERROR, "Get meta: corrupted block size %zu thats smaller then block header size %zu", a_block_size, sizeof (a_block->hdr));
        return NULL;
    }
    if (a_block->hdr.meta_count == 0) // no meta - nothing to return
        return NULL;

    dap_chain_block_meta_t *l_meta = NULL;
    for (size_t l_offset = 0, i = 0;
         i < a_block->hdr.meta_count && l_offset + sizeof(a_block->hdr) + sizeof(dap_chain_block_meta_t) < a_block_size;
         i++) {
        l_meta = (dap_chain_block_meta_t *)(a_block->meta_n_datum_n_sign + l_offset);
        l_offset += sizeof(l_meta->hdr) + l_meta->hdr.data_size;
        if (l_offset + sizeof(a_block->hdr) > a_block_size) {
            log_it(L_WARNING, "Get meta: corrupted block, can read only %zu from %hu metas", i, a_block->hdr.meta_count);
            return NULL;
        }
        if (l_meta->hdr.type == a_meta_type)
            return s_meta_extract(l_meta);
    }
    return NULL;
}

/**
 * @brief dap_chain_block_meta_extract_generals
 * @param a_block
 * @param a_block_size
 * @param a_block_prev_hash
 * @param a_block_anchor_hash
 * @param a_merkle
 * @param a_block_links
 * @param a_block_links_count
 * @param a_is_genesis
 * @param a_nonce
 * @param a_nonce2
 * @param a_reward
 */
int dap_chain_block_meta_extract(dap_chain_block_t *a_block, size_t a_block_size,
                                    dap_chain_hash_fast_t *a_block_prev_hash,
                                    dap_chain_hash_fast_t *a_block_anchor_hash,
                                    dap_chain_hash_fast_t *a_merkle,
                                    dap_chain_hash_fast_t **a_block_links,
                                    size_t *a_block_links_count,
                                    bool *a_is_genesis,
                                    uint64_t *a_nonce,
                                    uint64_t *a_nonce2)
{
    dap_return_val_if_fail(a_block && a_block_size, -1);
    // Check for meta that could be faced only once
    bool l_was_prev = false, l_was_genesis = false, l_was_anchor = false, l_was_nonce = false,
         l_was_nonce2 = false, l_was_merkle = false, l_was_reward = false;
    // Init links parsing
    size_t l_links_count = 0, l_links_count_max = 5;
    if (a_block_size < sizeof(a_block->hdr)) {
        log_it(L_ERROR, "Get meta: corrupted block size %zu thats smaller then block header size %zu", a_block_size, sizeof(a_block->hdr));
        return -2;
    }
    if (a_block->hdr.meta_count == 0) // no meta - nothing to return
        return 0;

    dap_chain_block_meta_t *l_meta = NULL;
    uint8_t *l_meta_data = NULL;
    for (size_t l_offset = 0, i = 0;
         i < a_block->hdr.meta_count && l_offset + sizeof(a_block->hdr) + sizeof(dap_chain_block_meta_t) < a_block_size;
         i++) {
        l_meta = (dap_chain_block_meta_t *)(a_block->meta_n_datum_n_sign + l_offset);
        l_offset += sizeof(l_meta->hdr) + l_meta->hdr.data_size;
        if (l_offset + sizeof(a_block->hdr) > a_block_size) {
            log_it(L_WARNING, "Get meta: corrupted block, can read only %zu from %hu metas", i, a_block->hdr.meta_count);
            return -3;
        }
        switch (l_meta->hdr.type) {
        case DAP_CHAIN_BLOCK_META_GENESIS:
            if(l_was_genesis) {
                log_it(L_WARNING, "Genesis meta could be only one in the block, meta #%zu is ignored ", i);
                break;
            }
            l_was_genesis = true;
            if (a_is_genesis)
                *a_is_genesis = s_meta_extract(l_meta);
        break;
        case DAP_CHAIN_BLOCK_META_PREV:
            if (l_was_prev) {
                log_it(L_WARNING, "Prev meta could be only one in the block, meta #%zu is ignored ", i);
                break;
            }
            l_was_prev = true;
            if (a_block_prev_hash) {
                l_meta_data = s_meta_extract(l_meta);
                if (l_meta_data)
                    *a_block_prev_hash = *(dap_hash_t *)l_meta_data;
                else
                    return -4;
            }
        break;
        case DAP_CHAIN_BLOCK_META_ANCHOR:
            if (l_was_anchor) {
                log_it(L_WARNING, "Anchor meta could be only one in the block, meta #%zu is ignored ", i);
                break;
            }
            l_was_anchor = true;
            if (a_block_anchor_hash) {
                l_meta_data = s_meta_extract(l_meta);
                if (l_meta_data)
                    *a_block_anchor_hash = *(dap_hash_t *)l_meta_data;
                else
                    return -4;
            }
        break;
        case DAP_CHAIN_BLOCK_META_LINK:
            if (a_block_links) {
                if (l_links_count == 0)
                    *a_block_links = DAP_NEW_Z_SIZE(dap_hash_t, sizeof(dap_hash_t) * l_links_count_max);
                else if (l_links_count == l_links_count_max) {
                    l_links_count_max *= 2;
                    *a_block_links = DAP_REALLOC(*a_block_links, l_links_count_max);
                }
                if (!*a_block_links) {
                    log_it(L_CRITICAL, "Not enough memory");
                    return -5;
                }
                l_meta_data = s_meta_extract(l_meta);
                if (l_meta_data)
                    *a_block_links[l_links_count++] = *(dap_hash_t *)l_meta_data;
                else
                    return -4;
                if (a_block_links_count)
                    *a_block_links_count = l_links_count;
            }
        break;
        case DAP_CHAIN_BLOCK_META_NONCE:
            if (l_was_nonce) {
                log_it(L_WARNING, "NONCE could be only one in the block, meta #%zu is ignored ", i);
                break;
            }
            l_was_nonce = true;
            if (a_nonce) {
                l_meta_data = s_meta_extract(l_meta);
                if (l_meta_data)
                    *a_nonce = *(uint64_t *)l_meta_data;
                else
                    return -4;
            }
        break;
        case DAP_CHAIN_BLOCK_META_NONCE2:
            if (l_was_nonce2) {
                log_it(L_WARNING, "NONCE2 could be only one in the block, meta #%zu is ignored ", i);
                break;
            }
            l_was_nonce2 = true;
            if (a_nonce2) {
                l_meta_data = s_meta_extract(l_meta);
                if (l_meta_data)
                    *a_nonce2 = *(uint64_t *)l_meta_data;
                else
                    return -4;
            }
        break;
        case DAP_CHAIN_BLOCK_META_MERKLE:
            if (l_was_merkle) {
                log_it(L_WARNING, "Merckle root could be only one in the block, meta #%zu is ignored ", i);
                break;
            }
            l_was_merkle = true;
            if (a_merkle) {
                l_meta_data = s_meta_extract(l_meta);
                if (l_meta_data)
                    *a_merkle = *(dap_hash_t *)l_meta_data;
                else
                    return -4;
            }
        break;
        case DAP_CHAIN_BLOCK_META_EMERGENCY:
        case DAP_CHAIN_BLOCK_META_EXCLUDED_KEYS:
        case DAP_CHAIN_BLOCK_META_SYNC_ATTEMPT:
        case DAP_CHAIN_BLOCK_META_ROUND_ATTEMPT:
            // No warning here
        break;
        default: log_it(L_WARNING, "Unknown meta #%zu type 0x%02x (size %u), possible corrupted block or you need to upgrade your software",
                                    i, l_meta->hdr.type, l_meta->hdr.type);
        break;
        }
    }
    return 0;
}
