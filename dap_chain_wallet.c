/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
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

#include <string.h>
#include <errno.h>
#include "dap_common.h"
#include "dap_chain_cert_file.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_internal.h"

#define LOG_TAG "dap_chain_wallet"

/**
 * @brief dap_chain_wallet_init
 * @return
 */
int dap_chain_wallet_init()
{
   return 0;
}

/**
 * @brief dap_chain_wallet_deinit
 */
void dap_chain_wallet_deinit()
{

}


/**
 * @brief dap_chain_wallet_create
 * @param a_wallet_name
 * @param a_wallets_path
 * @param a_net_id
 * @param a_sig_type
 * @details Creates new wallet
 * @return Wallet, new wallet or NULL if errors
 */
dap_chain_wallet_t * dap_chain_wallet_create(const char * a_wallet_name, const char * a_wallets_path, dap_chain_net_id_t a_net_id,
                                             dap_chain_sign_type_t a_sig_type)
{
    dap_chain_wallet_t * l_wallet = DAP_NEW_Z(dap_chain_wallet_t);
    DAP_CHAIN_WALLET_INTERNAL_LOCAL_NEW(l_wallet);
    l_wallet->name = strdup(a_wallet_name);
    l_wallet_internal->certs_count = 1;
    l_wallet_internal->certs = DAP_NEW_Z_SIZE(dap_chain_cert_t *,l_wallet_internal->certs_count);

    size_t l_file_name_size = strlen(a_wallet_name)+strlen(a_wallets_path)+13;
    l_wallet_internal->file_name = DAP_NEW_Z_SIZE (char, l_file_name_size);

    snprintf(l_wallet_internal->file_name,l_file_name_size,"%s/%s.dwallet");

    l_wallet_internal->certs[0] = dap_chain_cert_generate_mem(a_wallet_name,
                                                         dap_chain_sign_type_to_key_type(a_sig_type));

    if ( dap_chain_wallet_save(l_wallet) == 0 )
        return l_wallet;
    else {
        log_it(L_ERROR,"Can't save the new wallet in disk: \"%s\"",strerror(errno));
    }

}

/**
 * @brief dap_chain_wallet_close
 * @param a_wallet
 */
void dap_chain_wallet_close( dap_chain_wallet_t * a_wallet)
{
    DAP_CHAIN_WALLET_INTERNAL_LOCAL(a_wallet);
    if(a_wallet->name)
        DAP_DELETE (a_wallet->name);

    DAP_DELETE(l_wallet_internal);
    DAP_DELETE(a_wallet);
}

/**
 * @brief dap_chain_wallet_get_pkey
 * @param a_wallet
 * @param a_pkey_idx
 * @return serialized object if success, NULL if not
 */
dap_chain_pkey_t* dap_chain_wallet_get_pkey( dap_chain_wallet_t * a_wallet,uint32_t a_pkey_idx )
{
    DAP_CHAIN_WALLET_INTERNAL_LOCAL(a_wallet);
    if( l_wallet_internal->certs_count > a_pkey_idx ){
        return dap_chain_cert_to_pkey(l_wallet_internal->certs[a_pkey_idx]);
    }else{
        log_it( L_WARNING, "No pkey with index %u in the wallet (total size %u)",a_pkey_idx,l_wallet_internal->certs_count);
        return 0;
    }
}

/**
 * @brief dap_chain_wallet_get_certs_number
 * @param a_wallet
 * @return
 */
size_t dap_chain_wallet_get_certs_number( dap_chain_wallet_t * a_wallet)
{
    DAP_CHAIN_WALLET_INTERNAL_LOCAL(a_wallet);
    return l_wallet_internal->certs_count;
}



/**
 * @brief dap_chain_wallet_get_key
 * @param a_wallet
 * @param a_pkey_idx
 * @return
 */
dap_enc_key_t* dap_chain_wallet_get_key( dap_chain_wallet_t * a_wallet,uint32_t a_pkey_idx )
{
    DAP_CHAIN_WALLET_INTERNAL_LOCAL(a_wallet);
    if( l_wallet_internal->certs_count > a_pkey_idx ){
        return l_wallet_internal->certs[a_pkey_idx] ?
                    l_wallet_internal->certs[a_pkey_idx]->key_private
                  : NULL;
    }else{
        log_it( L_WARNING, "No key with index %u in the wallet (total size %u)",a_pkey_idx,l_wallet_internal->certs_count);
        return 0;
    }
}


/**
 * @brief dap_chain_wallet_save
 * @param a_wallet
 * @return
 */
int dap_chain_wallet_save(dap_chain_wallet_t * a_wallet)
{
    if ( a_wallet ){
        DAP_CHAIN_WALLET_INTERNAL_LOCAL (a_wallet);
        FILE * l_file = fopen( l_wallet_internal->file_name ,"w");
        if ( l_file ){
            dap_chain_wallet_file_hdr_t l_file_hdr = {0};
            l_file_hdr.signature = DAP_CHAIN_WALLETS_FILE_SIGNATURE;
            l_file_hdr.type = 0;
            l_file_hdr.version = 1;
            l_file_hdr.net_id = l_wallet_internal->addr->net_id;
            size_t i;
            fwrite(&l_file_hdr,1,sizeof(l_file_hdr),l_file);
            for ( i = 0; i < l_wallet_internal->certs_count ; i ++) {
                dap_chain_wallet_cert_hdr_t l_wallet_cert_hdr = {0};
                l_wallet_cert_hdr.version = 1;
                l_wallet_cert_hdr.cert_raw_size = dap_chain_cert_save_mem_size(  l_wallet_internal->certs[i] );
                fwrite( &l_wallet_cert_hdr,1, sizeof (l_wallet_cert_hdr), l_file);
                uint8_t * l_buf = DAP_NEW_SIZE (uint8_t, l_wallet_cert_hdr.cert_raw_size);
                if ( dap_chain_cert_save_mem(l_wallet_internal->certs[i],l_buf) == 0 ){
                    fwrite( l_buf, 1, l_wallet_cert_hdr.cert_raw_size, l_file);
                }else{
                    log_it(L_WARNING,"Cant write cert to  file %s: error \"%s\"",l_wallet_internal->file_name,
                           strerror(errno));
                }
                DAP_DELETE (l_buf);
            }
            fclose (l_file);
            return 0;
        }else{
            log_it(L_ERROR,"Cant open file %s for writting",l_wallet_internal->file_name);
            return -2;
        }
    }else{
        log_it(L_ERROR,"Wallet is null, can't save it to file!");
        return -1;
    }
}

/**
 * @brief dap_chain_wallet_open_file
 * @param a_file_name
 * @return
 */
dap_chain_wallet_t * dap_chain_wallet_open_file(const char * a_file_name)
{
    FILE * l_file = fopen( a_file_name ,"w");
    fseek(l_file, 0L, SEEK_END);
    uint64_t l_file_size = ftell(l_file);
    rewind(l_file);

    if ( l_file ){
        dap_chain_wallet_file_hdr_t l_file_hdr={0};

        if ( fread(&l_file_hdr,1,sizeof(l_file_hdr),l_file) == sizeof (l_file_hdr) ) {
            if ( l_file_hdr.signature == DAP_CHAIN_WALLETS_FILE_SIGNATURE ) {
                dap_chain_wallet_t * l_wallet = DAP_NEW_Z(dap_chain_wallet_t);
                DAP_CHAIN_WALLET_INTERNAL_LOCAL_NEW(l_wallet);

                l_wallet_internal->file_name = strdup(a_file_name);

                size_t l_certs_count = 0,i;
                while (i <  (l_file_size - sizeof(l_file_hdr)) ){
                    dap_chain_wallet_cert_hdr_t l_cert_hdr={0};
                    fread(&l_cert_hdr,1,sizeof(l_cert_hdr),l_file);
                    i+=sizeof(l_cert_hdr);
                    if (l_cert_hdr.cert_raw_size > 0 ){
                        if (l_cert_hdr.cert_raw_size <=  (l_file_size - sizeof (l_file_hdr) - i  ) ){
                            i+=l_cert_hdr.cert_raw_size;
                            l_certs_count++;
                        }else{
                            log_it(L_WARNING,"Wrong raw cert size %u (too big)",l_cert_hdr.cert_raw_size);
                            break;
                        }
                    }else{
                        log_it(L_WARNING,"Wrong raw cert size 0");
                        break;
                    }
                }
                fseek(l_file,sizeof(l_file_hdr),SEEK_SET);
                l_wallet_internal->certs = DAP_NEW_Z_SIZE(dap_chain_cert_t *,l_wallet_internal->certs_count);
                for (i = 0; i < l_wallet_internal->certs_count; i++ ){
                    dap_chain_wallet_cert_hdr_t l_cert_hdr={0};
                    fread(&l_cert_hdr,1,sizeof(l_cert_hdr),l_file);
                    uint8_t * l_data = DAP_NEW_SIZE(uint8_t,l_cert_hdr.cert_raw_size);
                    l_wallet_internal->certs[i] = dap_chain_cert_mem_load(l_data,l_cert_hdr.cert_raw_size);
                    DAP_DELETE (l_data);
                }
                fclose(l_file);
                return l_wallet;
            } else {
                log_it(L_ERROR,"Wrong wallet file signature: corrupted file or wrong format");
                return NULL;
            }
        }else{
            log_it(L_ERROR,"Can't read wallet's header %s: \"%s\"",a_file_name,strerror(errno));
            return NULL;
        }
    }else{
        log_it(L_ERROR,"Can't open file %s: \"%s\"",a_file_name,strerror(errno));
        return NULL;
    }
}

/**
 * @brief dap_chain_wallet_open
 * @param a_wallet_name
 * @param a_wallets_path
 * @return
 */
dap_chain_wallet_t * dap_chain_wallet_open(const char * a_wallet_name, const char * a_wallets_path)
{
    size_t l_file_name_size = strlen(a_wallet_name)+strlen(a_wallets_path)+13;
    char *l_file_name = DAP_NEW_Z_SIZE (char, l_file_name_size);
    snprintf(l_file_name,l_file_name_size,"%s/%s.dwallet");
    dap_chain_wallet_t * l_wallet = dap_chain_wallet_open_file(l_file_name);
    DAP_DELETE(l_file_name);
    return l_wallet;
}
