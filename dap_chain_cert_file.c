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
#include "dap_chain_cert_file.h"

#define LOG_TAG "dap_chain_cert_file"


/**
 * @brief dap_chain_cert_file_save_to_mem_size
 * @param a_cert
 * @return
 */
size_t dap_chain_cert_save_mem_size(dap_chain_cert_t * a_cert )
{
    return sizeof (dap_chain_cert_file_hdr_t)
            + a_cert->enc_key->pub_key_data_size
            + a_cert->enc_key->priv_key_data_size
            + (a_cert->metadata?strlen(a_cert->metadata):0);
}

/**
 * @brief dap_chain_cert_file_save
 * @param a_cert
 * @param a_cert_file_path
 * @return
 */
int dap_chain_cert_save_file(dap_chain_cert_t * a_cert, const char * a_cert_file_path)
{
    FILE * l_file = fopen(a_cert_file_path,"w");
    if( l_file ){
        size_t l_data_size = dap_chain_cert_save_mem_size(a_cert);
        void * l_data = DAP_NEW_SIZE(void,l_data_size);
        if ( dap_chain_cert_save_mem(a_cert,l_data) == 0 ){
            size_t l_retbytes;
            if ( (l_retbytes = fwrite(l_data,1,l_data_size,l_file)) != l_data_size ){
                log_it(L_ERROR, "Can't write %u bytes on disk (processed only %u)!", l_data_size,l_retbytes);
                return -3;
            }
            fclose(l_file);
            return 0;
        }else{
            log_it(L_ERROR,"Can't serialize certificate in memory");
            fclose(l_file);
            return -4;
        }
    }else{
        log_it(L_ERROR, "Can't open file for write: %s", strerror(errno));
        return -2;
    }
}

/**
 * @brief dap_chain_cert_file_save_to_mem
 * @param a_cert
 * @param a_data
 * @return
 */
int dap_chain_cert_save_mem(dap_chain_cert_t * a_cert, void * a_data )
{
    dap_chain_cert_file_hdr_t l_hdr={0};
    uint8_t * l_data = (uint8_t *) a_data;
    size_t l_data_offset = 0;
    dap_enc_key_t * l_key = a_cert->enc_key;
    int ret = 0;

    l_hdr.sign = DAP_CHAIN_CERT_FILE_HDR_SIGN;
    l_hdr.type = DAP_CHAIN_CERT_FILE_TYPE_PUBLIC;
    if ( l_key->priv_key_data ){
        l_hdr.type =  DAP_CHAIN_CERT_FILE_TYPE_PRIVATE;
        log_it(L_DEBUG,"Private key size %u",l_key->priv_key_data_size);
    }
    if (l_key->pub_key_data){
        log_it(L_DEBUG,"Public key size %u",l_key->pub_key_data_size);
    }else{
        log_it(L_ERROR,"No public or private key in certificate, nothing to save");
        ret = -1;
        goto lb_exit;
    }
    log_it(L_DEBUG,"Metadata size %u",l_key->_inheritor_size);

    l_hdr.version = DAP_CHAIN_CERT_FILE_VERSION;
    l_hdr.data_size = l_key->pub_key_data_size;
    l_hdr.data_pvt_size = l_key->priv_key_data_size;
    l_hdr.metadata_size = 0;

    l_hdr.ts_last_used = l_key->last_used_timestamp;
    l_hdr.sign_type = dap_chain_sign_type_from_key_type ( l_key->type );

    memcpy(l_data +l_data_offset, &l_hdr ,sizeof(l_hdr) );
    l_data_offset += sizeof(l_hdr);

    memcpy(l_data +l_data_offset, l_key->pub_key_data ,l_key->pub_key_data_size );
    l_data_offset += l_key->pub_key_data_size;

    memcpy(l_data +l_data_offset, l_key->priv_key_data ,l_key->priv_key_data_size );
    l_data_offset += l_key->priv_key_data_size;


lb_exit:

    if (ret == 0)
        log_it(L_NOTICE,"Certificate \"%s\"sucsessfully serialized",a_cert->name);

    return ret;
}

/**
 * @brief dap_chain_cert_file_load
 * @param a_cert_file_path
 * @return
 */

dap_chain_cert_t* dap_chain_cert_file_load(const char * a_cert_file_path)
{
    dap_chain_cert_t * l_ret = NULL;
    FILE * l_file = fopen(a_cert_file_path,"r");

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
            l_ret = dap_chain_cert_mem_load(l_data,l_file_size);
        }

    }
lb_exit:
    if( l_file )
        fclose(l_file);
    return l_ret;
}


/**
 * @brief dap_chain_cert_mem_load
 * @param a_data
 * @param a_data_size
 * @return
 */
dap_chain_cert_t* dap_chain_cert_mem_load(void * a_data, size_t a_data_size)
{
    dap_chain_cert_t * l_ret = NULL;
    dap_chain_cert_file_hdr_t l_hdr={0};
    uint8_t * l_data = (uint8_t *) a_data;
    memcpy(&l_hdr,l_data, sizeof(l_hdr));
    if (l_hdr.sign != DAP_CHAIN_CERT_FILE_HDR_SIGN ){
        log_it(L_ERROR, "Wrong cert signature, corrupted header!");
        goto l_exit;
    }
    if (l_hdr.version >= 1 ){
        if ( (l_hdr.data_size+l_hdr.data_pvt_size +l_hdr.metadata_size) > a_data_size ){
            log_it(L_ERROR,"Corrupted cert data, data sections size is smaller than exists on the disk! (%llu expected, %llu on disk)",
                   l_hdr.data_pvt_size+l_hdr.data_size+l_hdr.metadata_size, a_data_size);
            goto l_exit;
        }

        l_ret = DAP_NEW_Z(dap_chain_cert_t);
        l_ret->enc_key = dap_enc_key_new( dap_chain_sign_type_to_key_type( l_hdr.sign_type ));
        l_ret->enc_key->last_used_timestamp = l_hdr.ts_last_used;
        if ( l_hdr.data_size > 0 ){
            l_ret->enc_key->pub_key_data_size = l_hdr.data_size;
            l_ret->enc_key->pub_key_data = DAP_NEW_SIZE (void,l_hdr.data_size);
            memcpy(l_ret->enc_key->pub_key_data, l_data + sizeof(l_hdr),l_ret->enc_key->pub_key_data_size);
        }
        l_ret->enc_key->priv_key_data_size = l_hdr.data_size;
        if ( l_hdr.data_pvt_size > 0 ){
            l_ret->enc_key->priv_key_data = DAP_NEW_SIZE (void,l_ret->enc_key->priv_key_data_size);
            memcpy(l_ret->enc_key->priv_key_data, l_data + sizeof(l_hdr)
                                                        + l_ret->enc_key->pub_key_data_size
                   ,l_ret->enc_key->priv_key_data_size);
        }
        log_it(L_NOTICE,"Successfuly loaded certificate");

//        log_it(L_NOTICE,"Successfuly loaded certificate \"%s\" from the file %s",l_ret->name);
    }else
        log_it(L_ERROR,"Unrecognizable certificate version, corrupted file or you have too old software");

l_exit:
    return l_ret;
}
