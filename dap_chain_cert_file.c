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
 * @brief dap_chain_cert_file_save
 * @param a_cert
 * @param a_cert_file_path
 * @return
 */
int dap_chain_cert_file_save(dap_chain_cert_t * a_cert, const char * a_cert_file_path)
{
    dap_chain_cert_file_hdr_t l_hdr={0};
    dap_enc_key_t * l_key = a_cert->key_private;
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
    l_hdr.inheritor_size = l_key->_inheritor_size;

    l_hdr.ts_last_used = l_key->last_used_timestamp;
    l_hdr.sign_type = dap_chain_sign_type_from_key_type ( l_key->type );
    FILE * l_file = fopen(a_cert_file_path,"w");
    if( l_file ){
        size_t l_retbytes=0;
        if ( (l_retbytes = fwrite(&l_hdr,1,sizeof(l_hdr),l_file )) != sizeof(l_hdr) ){
            log_it(L_ERROR, "Can't write %u bytes on disk (processed only %u)!", sizeof(l_hdr),l_retbytes);
            ret = -3;
        }
        if ( ( l_retbytes = fwrite(l_key->pub_key_data,1,l_key->pub_key_data_size,l_file )) != l_key->pub_key_data_size ){
            log_it(L_ERROR, "Can't write %u bytes of public key to file (processed only %u)!", l_key->pub_key_data_size,l_retbytes);
            ret = -4;
        }
        if ( ( l_retbytes = fwrite(l_key->priv_key_data,1,l_key->priv_key_data_size,l_file )) != l_key->priv_key_data_size ){
            log_it(L_ERROR, "Can't write %u bytes of private key to file (processed only %u)!", l_key->priv_key_data_size,l_retbytes);
            ret = -4;
        }
        if ( ( l_retbytes = fwrite(l_key->_inheritor,1,l_key->_inheritor_size,l_file )) != l_key->_inheritor_size ){
            log_it(L_ERROR, "Can't write %u bytes if metadata to file (processed only %u)!", l_key->_inheritor_size,l_retbytes);
            ret = -1;
        }
    }else{
        log_it(L_ERROR, "Can't open file for write: %s", strerror(errno));
        return -2;
    }
lb_exit:
    if (l_file)
        fclose(l_file);

    if (ret == 0)
        log_it(L_NOTICE,"Certificate sucsessfully saved to %s",a_cert_file_path);

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
    dap_chain_cert_file_hdr_t l_hdr={0};
    if( l_file ){
        fseek(l_file, 0L, SEEK_END);
        uint64_t l_file_size = ftell(l_file);
        rewind(l_file);

        if ( fread(&l_hdr,1,sizeof(l_hdr),l_file ) != sizeof(l_hdr) ){
            log_it(L_ERROR, "Can't read %u bytes from the disk!", sizeof(l_hdr));
            goto l_exit;
        }
        if (l_hdr.sign != DAP_CHAIN_CERT_FILE_HDR_SIGN ){
            log_it(L_ERROR, "Wrong file signature, corrupted header!");
            goto l_exit;
        }
        if (l_hdr.version >= 1 ){
            if ( (l_hdr.data_size+l_hdr.data_pvt_size +l_hdr.inheritor_size) > l_file_size ){
                log_it(L_ERROR,"Corrupted file, data sections size is smaller than exists on the disk! (%llu expected, %llu on disk)",
                       l_hdr.data_pvt_size+l_hdr.data_size+l_hdr.inheritor_size, l_file_size);
                goto l_exit;
            }


            l_ret = DAP_NEW_Z(dap_chain_cert_t);
            l_ret->key_private = dap_enc_key_new( dap_chain_sign_type_to_key_type( l_hdr.sign_type ));
            l_ret->key_private->last_used_timestamp = l_hdr.ts_last_used;
            if ( l_hdr.data_size > 0 ){
                l_ret->key_private->pub_key_data_size = l_hdr.data_size;
                l_ret->key_private->pub_key_data = DAP_NEW_SIZE (void,l_hdr.data_size);
                if ( fread(l_ret->key_private->pub_key_data , 1, l_hdr.data_size, l_file ) != l_hdr.data_size ){
                    log_it(L_ERROR, "Can't read %u bytes of public key from the file!", l_hdr.data_size);
                    goto l_exit;
                }
            }
            l_ret->key_private->priv_key_data_size = l_hdr.data_size;
            if ( l_hdr.data_pvt_size > 0 ){
                l_ret->key_private->priv_key_data = DAP_NEW_SIZE (void,l_ret->key_private->priv_key_data_size);
                if ( fread(l_ret->key_private->priv_key_data  , 1, l_ret->key_private->priv_key_data_size,l_file )
                     != l_ret->key_private->priv_key_data_size ){
                    log_it(L_ERROR, "Can't read %u bytes of private key from the file!", l_ret->key_private->priv_key_data_size);
                    goto l_exit;
                }
            }

            l_ret->key_private->_inheritor_size = l_hdr.inheritor_size;
            if ( l_hdr.inheritor_size > 0 ){
                l_ret->key_private->_inheritor = DAP_NEW_SIZE (void,l_hdr.inheritor_size);
                if ( fread(l_ret->key_private->_inheritor , 1, l_hdr.inheritor_size, l_file ) != l_hdr.inheritor_size ){
                    log_it(L_ERROR, "Can't read %u bytes of inheritor part to the file!", l_hdr.inheritor_size);
                    goto l_exit;
                }

            }


            log_it(L_NOTICE,"Successfuly loaded certificate from the file %s",a_cert_file_path);
        }else
            log_it(L_ERROR,"Unrecognizable certificate version, corrupted file or you have too old software");

    }else{
        log_it(L_ERROR, "Can't open file for reading: %s", strerror(errno));
        goto l_exit;
    }
l_exit:
    if( l_file )
        fclose(l_file);
    return l_ret;
}
