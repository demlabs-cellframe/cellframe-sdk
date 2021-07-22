/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net    https:/gitlab.com/demlabs
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
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "dap_common.h"
#include "dap_enc.h"
#include "dap_enc_key.h"
#include "dap_file_utils.h"
#include "dap_cert_file.h"

#define LOG_TAG "dap_cert_file"

static const char s_key_inheritor[] = "Inheritor";

/**
 * @brief dap_cert_file_save
 * @param a_cert
 * @param a_cert_file_path
 * @return
 */
int dap_cert_file_save(dap_cert_t * a_cert, const char * a_cert_file_path)
{
    char * l_file_dir = dap_path_get_dirname(a_cert_file_path);
    dap_mkdir_with_parents(l_file_dir);
    DAP_DELETE(l_file_dir);

    FILE * l_file = fopen(a_cert_file_path,"wb");
    if( l_file ){
        uint32_t l_data_size = 0;
        void * l_data = dap_cert_mem_save(a_cert, &l_data_size);
        if ( l_data ){
            size_t l_retbytes;
            if ( (l_retbytes = fwrite(l_data,1,l_data_size,l_file)) != l_data_size ){
                log_it(L_ERROR, "Can't write %u bytes on disk (processed only %u)!", l_data_size,l_retbytes);
                return -3;
            }
            fclose(l_file);
            DAP_DELETE(l_data);
            return 0;
        }else{
            log_it(L_ERROR,"Can't serialize certificate in memory");
            fclose(l_file);
            return -4;
        }
    }else{
        log_it(L_ERROR, "Can't open file '%s' for write: %s", a_cert_file_path, strerror(errno));
        return -2;
    }
}

// balance the binary tree
void s_balance_the_tree(dap_cert_file_aux_t *a_reorder, size_t a_left_idx, size_t a_right_idx)
{
    if (a_left_idx == a_right_idx) {
        a_reorder->buf[a_reorder->idx++] = a_left_idx;
        return;
    }
    size_t i = (a_left_idx + a_right_idx) / 2 + 1;
    a_reorder->buf[a_reorder->idx++] = i;
    s_balance_the_tree(a_reorder, a_left_idx, i - 1);
    if (i < a_right_idx) {
        s_balance_the_tree(a_reorder, i + 1, a_right_idx);
    }
}

void dap_cert_deserialize_meta(dap_cert_t *a_cert, const uint8_t *a_data, size_t a_size)
{
    dap_cert_metadata_t **l_meta_arr = NULL;
    size_t l_mem_shift = 0;
    size_t l_meta_items_count = 0;
    while (l_mem_shift < a_size) {
        const char *l_key_str = (const char *)&a_data[l_mem_shift];
        if (!l_key_str) {
            break;
        }
        l_mem_shift += strlen(l_key_str) + 1;
        uint32_t l_value_size = dap_lendian_get32(&a_data[l_mem_shift]);
        l_mem_shift += sizeof(uint32_t);
        dap_cert_metadata_type_t l_meta_type = (dap_cert_metadata_type_t)a_data[l_mem_shift++];
        const uint8_t *l_value = &a_data[l_mem_shift];
        l_mem_shift += l_value_size;
        uint16_t l_tmp16;
        uint32_t l_tmp32;
        uint64_t l_tmp64;
        switch (l_meta_type) {
        case DAP_CERT_META_STRING:
        case DAP_CERT_META_SIGN:
        case DAP_CERT_META_CUSTOM:
            break;
        default:
            switch (l_value_size) {
            case 1:
                break;
            case 2:
                l_tmp16 = dap_lendian_get16(l_value);
                l_value = (const uint8_t *)&l_tmp16;
                break;
            case 4:
                l_tmp32 = dap_lendian_get32(l_value);
                l_value = (const uint8_t *)&l_tmp32;
                break;
            case 8:
            default:
                l_tmp64 = dap_lendian_get64(l_value);
                l_value = (const uint8_t *)&l_tmp64;
                break;
            }
            break;
        }
        dap_cert_metadata_t *l_new_meta = dap_cert_new_meta(l_key_str, l_meta_type, (void *)l_value, l_value_size);
        if (l_meta_arr == NULL) {
            l_meta_arr = DAP_NEW(dap_cert_metadata_t *);
        } else {
            l_meta_arr = DAP_REALLOC(l_meta_arr, (l_meta_items_count + 1) * sizeof(dap_cert_metadata_t *));
        }
        l_meta_arr[l_meta_items_count++] = l_new_meta;
    }
    if(l_meta_items_count){
        size_t l_reorder_arr[l_meta_items_count];
        dap_cert_file_aux_t l_reorder = {l_reorder_arr, 0};
        s_balance_the_tree(&l_reorder, 0, l_meta_items_count - 1);
        size_t n = l_reorder_arr[0];
        a_cert->metadata = dap_binary_tree_insert(NULL, l_meta_arr[n]->key, (void *)l_meta_arr[n]);
        for (size_t i = 1; i < l_meta_items_count; i++) {
            n = l_reorder_arr[i];
            dap_binary_tree_insert(a_cert->metadata, l_meta_arr[n]->key, (void *)l_meta_arr[n]);
        }
    }
    DAP_DELETE(l_meta_arr);
}

uint8_t *dap_cert_serialize_meta(dap_cert_t *a_cert, size_t *a_buflen_out)
{
    if (!a_cert) {
        return NULL;
    }
    if ( a_cert->enc_key->_inheritor_size) {
        dap_cert_add_meta_custom(a_cert, s_key_inheritor, a_cert->enc_key->_inheritor, a_cert->enc_key->_inheritor_size);
    }
    dap_list_t *l_meta_list = dap_binary_tree_inorder_list(a_cert->metadata);
    if (!l_meta_list) {
        return NULL;
    }
    dap_list_t *l_meta_list_item = dap_list_first(l_meta_list);
    uint8_t *l_buf = NULL;
    size_t l_mem_shift = 0;
    while (l_meta_list_item) {
        dap_cert_metadata_t *l_meta_item = l_meta_list_item->data;
        size_t l_meta_item_size = sizeof(dap_cert_metadata_t) - sizeof(const char *) + l_meta_item->length + strlen(l_meta_item->key) + 1;
        if (l_buf) {
            l_buf = DAP_REALLOC(l_buf, l_mem_shift + l_meta_item_size);
        } else {
            l_buf = DAP_NEW_SIZE(uint8_t, l_meta_item_size);
        }
        strcpy((char *)&l_buf[l_mem_shift], l_meta_item->key);
        l_mem_shift += strlen(l_meta_item->key) + 1;
        dap_lendian_put32(&l_buf[l_mem_shift], l_meta_item->length);
        l_mem_shift += sizeof(uint32_t);
        l_buf[l_mem_shift++] = l_meta_item->type;
        switch (l_meta_item->type) {
        case DAP_CERT_META_STRING:
        case DAP_CERT_META_SIGN:
        case DAP_CERT_META_CUSTOM:
            memcpy(&l_buf[l_mem_shift], l_meta_item->value, l_meta_item->length);
            l_mem_shift += l_meta_item->length;
            break;
        default:
            switch (l_meta_item->length) {
            case 1:
                l_buf[l_mem_shift++] = l_meta_item->value[0];
                break;
            case 2:
                dap_lendian_put16(&l_buf[l_mem_shift], *(uint16_t *)&l_meta_item->value[0]);
                l_mem_shift += 2;
                break;
            case 4:
                dap_lendian_put32(&l_buf[l_mem_shift], *(uint32_t *)&l_meta_item->value[0]);
                l_mem_shift += 4;
                break;
            case 8:
            default:
                dap_lendian_put64(&l_buf[l_mem_shift], *(uint64_t *)&l_meta_item->value[0]);
                l_mem_shift += 8;
                break;
            }
            break;
        }
        l_meta_list_item = l_meta_list_item->next;
    }
    dap_list_free(l_meta_list);
    if (a_buflen_out) {
        *a_buflen_out = l_mem_shift;
    }
    return l_buf;
}

/**
 * @brief dap_cert_file_save_to_mem
 * @param a_cert
 * @param a_cert_size_out
 * @return
 */
uint8_t* dap_cert_mem_save(dap_cert_t * a_cert, uint32_t *a_cert_size_out)
{
    dap_cert_file_hdr_t l_hdr={0};
    uint32_t l_data_offset = 0;
    dap_enc_key_t * l_key = a_cert->enc_key;
    uint8_t *l_data = NULL;

    size_t l_priv_key_data_size = a_cert->enc_key->priv_key_data_size;
    size_t l_pub_key_data_size = a_cert->enc_key->pub_key_data_size;
    size_t l_metadata_size = l_key->_inheritor_size;
    uint8_t *l_pub_key_data = a_cert->enc_key->pub_key_data_size ?
                dap_enc_key_serealize_pub_key(l_key, &l_pub_key_data_size) :
                NULL;
    uint8_t *l_priv_key_data = a_cert->enc_key->priv_key_data ?
                dap_enc_key_serealize_priv_key(l_key, &l_priv_key_data_size) :
                NULL;
    uint8_t *l_metadata = dap_cert_serialize_meta(a_cert, &l_metadata_size);

    l_hdr.sign = dap_cert_FILE_HDR_SIGN;
    l_hdr.type = dap_cert_FILE_TYPE_PUBLIC;
    if ( l_priv_key_data ){
        l_hdr.type =  dap_cert_FILE_TYPE_PRIVATE;
        //log_it(L_DEBUG,"Private key size %u",l_priv_key_data_size);
    }
    if (l_pub_key_data){
        //log_it(L_DEBUG,"Public key size %u",l_pub_key_data_size);
    }else{
        log_it(L_ERROR,"No public or private key in certificate, nothing to save");
        goto lb_exit;
    }
    //log_it(L_DEBUG,"Key private data size %u",l_key->_inheritor_size);

    l_hdr.version = dap_cert_FILE_VERSION;
    l_hdr.data_size = l_pub_key_data_size;
    l_hdr.data_pvt_size = l_priv_key_data_size;
    l_hdr.metadata_size = l_metadata_size;

    l_hdr.ts_last_used = l_key->last_used_timestamp;
    l_hdr.sign_type = dap_sign_type_from_key_type ( l_key->type );


    l_data = DAP_NEW_SIZE(void, sizeof(l_hdr) + DAP_CERT_ITEM_NAME_MAX + l_priv_key_data_size + l_pub_key_data_size + l_metadata_size);
    if (!l_data) {
        log_it(L_ERROR,"Certificate \"%s\" was not serialized",a_cert->name);
        goto lb_exit;
    }

    memcpy(l_data +l_data_offset, &l_hdr ,sizeof(l_hdr) );
    l_data_offset += sizeof(l_hdr);

    memcpy(l_data +l_data_offset, a_cert->name, DAP_CERT_ITEM_NAME_MAX );//save cert name
    l_data_offset += DAP_CERT_ITEM_NAME_MAX;

    memcpy(l_data +l_data_offset, l_pub_key_data ,l_pub_key_data_size );
    l_data_offset += l_pub_key_data_size;

    if ( l_priv_key_data_size && l_priv_key_data ) {
        memcpy(l_data +l_data_offset, l_priv_key_data ,l_priv_key_data_size );
        l_data_offset += l_priv_key_data_size;
    }

    if (l_metadata_size) {
        memcpy(l_data + l_data_offset, l_metadata, l_metadata_size);
        l_data_offset += l_metadata_size;
    }
lb_exit:
    DAP_DELETE(l_pub_key_data);
    if ( l_priv_key_data_size ) {
        DAP_DELETE(l_priv_key_data);
    }
    if ( l_metadata_size ) {
        DAP_DELETE(l_metadata);
    }

    //log_it(L_NOTICE,"Certificate \"%s\" successfully serialized",a_cert->name);

    if(a_cert_size_out)
        *a_cert_size_out = l_data_offset;
    return l_data;
}

/**
 * @brief dap_cert_file_load
 * @param a_cert_file_path
 * @return
 */

dap_cert_t* dap_cert_file_load(const char * a_cert_file_path)
{
    dap_cert_t * l_ret = NULL;
    FILE * l_file = fopen(a_cert_file_path,"rb");

    if( l_file ){
        fseek(l_file, 0L, SEEK_END);
        uint64_t l_file_size = ftell(l_file);
        rewind(l_file);
        uint8_t * l_data = DAP_NEW_SIZE(uint8_t,l_file_size);
        if ( fread(l_data,1,l_file_size,l_file ) != l_file_size ){
            log_it(L_ERROR, "Can't read %u bytes from the disk!", l_file_size);
            DAP_DELETE (l_data);
            goto lb_exit;
        }else{
            l_ret = dap_cert_mem_load(l_data,l_file_size);
        }
        DAP_DELETE(l_data);
    }
lb_exit:
    if( l_file )
        fclose(l_file);
    return l_ret;
}


/**
 * @brief dap_cert_mem_load
 * @param a_data
 * @param a_data_size
 * @return
 */
dap_cert_t* dap_cert_mem_load(const void * a_data, size_t a_data_size)
{
    dap_cert_t * l_ret = NULL;
    dap_cert_file_hdr_t l_hdr={0};
    const uint8_t * l_data = (const uint8_t *) a_data;
    uint32_t l_data_offset = 0;
    memcpy(&l_hdr,l_data, sizeof(l_hdr));
    l_data_offset += sizeof(l_hdr);
    if (l_hdr.sign != dap_cert_FILE_HDR_SIGN ){
        log_it(L_ERROR, "Wrong cert signature, corrupted header!");
        goto l_exit;
    }
    if (l_hdr.version >= 1 ){
        if ( (sizeof(l_hdr) + l_hdr.data_size+l_hdr.data_pvt_size +l_hdr.metadata_size) > a_data_size ){
            log_it(L_ERROR,"Corrupted cert data, data sections size is smaller than exists on the disk! (%llu expected, %llu on disk)",
                    sizeof(l_hdr)+l_hdr.data_pvt_size+l_hdr.data_size+l_hdr.metadata_size, a_data_size);
            goto l_exit;
        }

        char l_name[DAP_CERT_ITEM_NAME_MAX];
        memcpy(l_name, l_data +l_data_offset, DAP_CERT_ITEM_NAME_MAX );//save cert name
        l_data_offset += DAP_CERT_ITEM_NAME_MAX;

        //l_ret = DAP_NEW_Z(dap_cert_t);
        l_ret = dap_cert_new(l_name);
        l_ret->enc_key = dap_enc_key_new( dap_sign_type_to_key_type( l_hdr.sign_type ));
        l_ret->enc_key->last_used_timestamp = l_hdr.ts_last_used;

        if ( l_hdr.data_size > 0 ){

            dap_enc_key_deserealize_pub_key(l_ret->enc_key, l_data + l_data_offset, l_hdr.data_size);
            l_data_offset += l_hdr.data_size;
        }
        if ( l_hdr.data_pvt_size > 0 ){

            dap_enc_key_deserealize_priv_key(l_ret->enc_key, l_data + l_data_offset, l_hdr.data_pvt_size);
            l_data_offset += l_hdr.data_pvt_size;
        }
        if ( l_hdr.metadata_size > 0 ){
            dap_cert_deserialize_meta(l_ret, l_data + l_data_offset, l_hdr.metadata_size);
            l_data_offset += l_hdr.metadata_size;
        }
        dap_enc_key_update(l_ret->enc_key);
        //log_it(L_NOTICE,"Successfully loaded certificate %s", l_ret->name);
    }else
        log_it(L_ERROR,"Unrecognizable certificate version, corrupted file or you have too old software");

l_exit:
    return l_ret;
}
