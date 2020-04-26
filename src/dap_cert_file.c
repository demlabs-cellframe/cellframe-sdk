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
#include "dap_cert_file.h"

#define LOG_TAG "dap_cert_file"

/**
 * @brief dap_cert_file_save
 * @param a_cert
 * @param a_cert_file_path
 * @return
 */
int dap_cert_file_save(dap_cert_t * a_cert, const char * a_cert_file_path)
{
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
    uint8_t *l_pub_key_data = a_cert->enc_key->pub_key_data_size ?
                dap_enc_key_serealize_pub_key(l_key, &l_pub_key_data_size) :
                NULL;
    uint8_t *l_priv_key_data = a_cert->enc_key->priv_key_data ?
                dap_enc_key_serealize_priv_key(l_key, &l_priv_key_data_size) :
                NULL;

    l_hdr.sign = dap_cert_FILE_HDR_SIGN;
    l_hdr.type = dap_cert_FILE_TYPE_PUBLIC;
    if ( l_priv_key_data ){
        l_hdr.type =  dap_cert_FILE_TYPE_PRIVATE;
        log_it(L_DEBUG,"Private key size %u",l_priv_key_data_size);
    }
    if (l_pub_key_data){
        log_it(L_DEBUG,"Public key size %u",l_pub_key_data_size);
    }else{
        log_it(L_ERROR,"No public or private key in certificate, nothing to save");
        goto lb_exit;
    }
    log_it(L_DEBUG,"Key private data size %u",l_key->_inheritor_size);

    l_hdr.version = dap_cert_FILE_VERSION;
    l_hdr.data_size = l_pub_key_data_size;
    l_hdr.data_pvt_size = l_priv_key_data_size;
    l_hdr.metadata_size = l_key->_inheritor_size;

    l_hdr.ts_last_used = l_key->last_used_timestamp;
    l_hdr.sign_type = dap_sign_type_from_key_type ( l_key->type );


    l_data = DAP_NEW_SIZE(void, sizeof(l_hdr) + DAP_CERT_ITEM_NAME_MAX + l_priv_key_data_size + l_pub_key_data_size + l_hdr.metadata_size);

    memcpy(l_data +l_data_offset, &l_hdr ,sizeof(l_hdr) );
    l_data_offset += sizeof(l_hdr);

    memcpy(l_data +l_data_offset, a_cert->name, DAP_CERT_ITEM_NAME_MAX );//save cert name
    l_data_offset += DAP_CERT_ITEM_NAME_MAX;

    memcpy(l_data +l_data_offset, l_pub_key_data ,l_pub_key_data_size );
    l_data_offset += l_pub_key_data_size;

    if ( l_priv_key_data_size ) {
        memcpy(l_data +l_data_offset, l_priv_key_data ,l_priv_key_data_size );
        l_data_offset += l_priv_key_data_size;
    }

    if ( l_key->_inheritor_size ) {
        memcpy(l_data +l_data_offset, l_key->_inheritor ,l_key->_inheritor_size );
        l_data_offset += l_key->_inheritor_size;
    }
lb_exit:
    DAP_DELETE(l_pub_key_data);
    DAP_DELETE(l_priv_key_data);
    if (l_data)
        log_it(L_NOTICE,"Certificate \"%s\" successfully serialized",a_cert->name);
    else
        log_it(L_ERROR,"Certificate \"%s\" was not serialized",a_cert->name);
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
        if(l_hdr.metadata_size > 0 && l_ret->enc_key->_inheritor && l_ret->enc_key->_inheritor_size == l_hdr.metadata_size) {
            memcpy(l_ret->enc_key->_inheritor, l_data + l_data_offset, l_ret->enc_key->_inheritor_size);
        }
        dap_enc_key_update(l_ret->enc_key);
        log_it(L_NOTICE,"Successfully loaded certificate %s", l_ret->name);
    }else
        log_it(L_ERROR,"Unrecognizable certificate version, corrupted file or you have too old software");

l_exit:
    return l_ret;
}
