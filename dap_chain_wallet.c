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

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>

#ifdef DAP_OS_UNIX
#include <sys/types.h>
#include <sys/stat.h>
#endif

#ifdef WIN32
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <wepoll.h>
#endif

#include <pthread.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
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
    // load certificates from existing wallets
    const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
    if(c_wallets_path) {
        DIR * l_dir = opendir(c_wallets_path);
        if (l_dir) {
            struct dirent * l_dir_entry;
            while((l_dir_entry = readdir(l_dir)) != NULL) {
                const char *l_file_name = l_dir_entry->d_name;
                size_t l_file_name_len = (l_file_name) ? strlen(l_file_name) : 0;
                if((l_file_name_len > 8) && (strcmp(l_file_name + l_file_name_len - 8, ".dwallet") == 0)) {
                    char *l_file_path_tmp = dap_strdup_printf("%s/%s", c_wallets_path, l_file_name);
                    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open_file(l_file_path_tmp);
                    if(l_wallet) {
                        dap_chain_wallet_close(l_wallet);
                    }
                    DAP_DELETE(l_file_path_tmp);
                }
            }
            closedir(l_dir);
        } else {
#ifdef _WIN32
            mkdir(c_wallets_path);
#else
            mkdir(c_wallets_path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
#endif
        }
    }
    return 0;
}

/**
 * @brief dap_chain_wallet_deinit
 */
void dap_chain_wallet_deinit()
{

}

/**
 * @brief dap_chain_wallet_get_path
 * @param[in] a_config Configuration
 * @return wallets path or NULL if error
 */
const char* dap_chain_wallet_get_path(dap_config_t * a_config)
{
    static char l_wallets_path[MAX_PATH];
    if (strlen(l_wallets_path) > 3)
        goto RET;

#ifdef _WIN32
    memcpy(l_wallets_path, s_sys_dir_path, l_sys_dir_path_len);
#endif
    dap_sprintf(l_wallets_path + l_sys_dir_path_len, "%s", dap_config_get_item_str(g_config, "resources", "wallets_path"));
RET:
    return l_wallets_path;
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

    dap_snprintf(l_wallet_internal->file_name,l_file_name_size,"%s/%s.dwallet",a_wallets_path,a_wallet_name);

    l_wallet_internal->certs[0] = dap_chain_cert_generate_mem(a_wallet_name,
                                                         dap_chain_sign_type_to_key_type(a_sig_type));
    l_wallet_internal->addr = dap_chain_cert_to_addr (l_wallet_internal->certs[0],a_net_id);

    if ( dap_chain_wallet_save(l_wallet) == 0 )
        return l_wallet;
    else {
        log_it(L_ERROR,"Can't save the new wallet in disk: \"%s\"",strerror(errno));
    }
    return NULL;
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
    // TODO Make clean struct dap_chain_wallet_internal_t (certs, addr)
    DAP_DELETE(l_wallet_internal->addr);
    DAP_DELETE(l_wallet_internal->file_name);
    DAP_DELETE(l_wallet_internal->certs);
    DAP_DELETE(l_wallet_internal);
    DAP_DELETE(a_wallet);
}

/**
 * @brief dap_chain_wallet_get_addr
 * @param a_wallet
 * @return
 */
dap_chain_addr_t* dap_chain_wallet_get_addr(dap_chain_wallet_t * a_wallet)
{
    if(!a_wallet)
        return NULL;
    DAP_CHAIN_WALLET_INTERNAL_LOCAL(a_wallet);
    return l_wallet_internal->addr;
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
                    l_wallet_internal->certs[a_pkey_idx]->enc_key
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
        FILE * l_file = fopen( l_wallet_internal->file_name ,"wb");
        if ( l_file ){
            dap_chain_wallet_file_hdr_t l_file_hdr = {0};
            l_file_hdr.signature = DAP_CHAIN_WALLETS_FILE_SIGNATURE;
            l_file_hdr.type = 0;
            l_file_hdr.version = 1;
            l_file_hdr.net_id = l_wallet_internal->addr->net_id;
            size_t i;
            // write header
            fwrite(&l_file_hdr,1,sizeof(l_file_hdr),l_file);
            // write name
            uint16_t name_len = (a_wallet->name) ? (uint16_t)strlen(a_wallet->name) : 0;
            fwrite(&name_len,1,sizeof(uint16_t),l_file);
            fwrite(a_wallet->name,1,name_len,l_file);
            // write certs
            for ( i = 0; i < l_wallet_internal->certs_count ; i ++) {
                dap_chain_wallet_cert_hdr_t l_wallet_cert_hdr = {0};
                l_wallet_cert_hdr.version = 1;
                uint8_t * l_buf = dap_chain_cert_mem_save(l_wallet_internal->certs[i], &l_wallet_cert_hdr.cert_raw_size);
                //l_wallet_cert_hdr.cert_raw_size = dap_chain_cert_save_mem_size(  l_wallet_internal->certs[i] );
                //uint8_t * l_buf = DAP_NEW_SIZE (uint8_t, l_wallet_cert_hdr.cert_raw_size);
                fwrite( &l_wallet_cert_hdr,1, sizeof (l_wallet_cert_hdr), l_file);
                if ( l_buf ){
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
    FILE * l_file = fopen( a_file_name ,"rb");
    if(!l_file){
        log_it(L_WARNING,"Can't open wallet file %s",a_file_name);
        return NULL;
    }
    fseek(l_file, 0L, SEEK_END);
    uint64_t l_file_size = ftell(l_file);
    rewind(l_file);

    if ( l_file ){
        dap_chain_wallet_file_hdr_t l_file_hdr={0};
        // read header
        if ( fread(&l_file_hdr,1,sizeof(l_file_hdr),l_file) == sizeof (l_file_hdr) ) {
            if ( l_file_hdr.signature == DAP_CHAIN_WALLETS_FILE_SIGNATURE ) {
                dap_chain_wallet_t * l_wallet = DAP_NEW_Z(dap_chain_wallet_t);
                DAP_CHAIN_WALLET_INTERNAL_LOCAL_NEW(l_wallet);
                // read name
                uint16_t name_len = 0;
                fread(&name_len, 1, sizeof(uint16_t), l_file);
                l_wallet->name = DAP_NEW_Z_SIZE(char, name_len + 1);
                fread(l_wallet->name, 1, name_len, l_file);

                l_wallet_internal->file_name = strdup(a_file_name);
                size_t i = sizeof (l_file_hdr) + sizeof(uint16_t) + name_len;
                // calculate certs count
                while (i <  l_file_size ){
                    dap_chain_wallet_cert_hdr_t l_cert_hdr={0};
                    fread(&l_cert_hdr,1,sizeof(l_cert_hdr),l_file);
                    i+=sizeof(l_cert_hdr);
                    if (l_cert_hdr.cert_raw_size > 0 ){
                        if(l_cert_hdr.cert_raw_size <= (l_file_size - i)) {
                            i+=l_cert_hdr.cert_raw_size;
                            l_wallet_internal->certs_count++;
                        }else{
                            log_it(L_WARNING,"Wrong raw cert size %u (too big)",l_cert_hdr.cert_raw_size);
                            break;
                        }
                    }else{
                        log_it(L_WARNING,"Wrong raw cert size 0");
                        break;
                    }
                }
                // read certs
                fseek(l_file,sizeof (l_file_hdr) + sizeof(uint16_t) + name_len,SEEK_SET);
                l_wallet_internal->certs = DAP_NEW_Z_SIZE(dap_chain_cert_t *,l_wallet_internal->certs_count * sizeof(dap_chain_cert_t *));
                for (i = 0; i < l_wallet_internal->certs_count; i++ ){
                    dap_chain_wallet_cert_hdr_t l_cert_hdr={0};
                    fread(&l_cert_hdr,1,sizeof(l_cert_hdr),l_file);
                    uint8_t * l_data = DAP_NEW_SIZE(uint8_t,l_cert_hdr.cert_raw_size);
                    fread(l_data,1,l_cert_hdr.cert_raw_size,l_file);
                    l_wallet_internal->certs[i] = dap_chain_cert_mem_load(l_data,l_cert_hdr.cert_raw_size);
                    DAP_DELETE (l_data);
                }
                fclose(l_file);
                // make addr
                if(l_wallet_internal->certs_count>0)
                    l_wallet_internal->addr = dap_chain_cert_to_addr (l_wallet_internal->certs[0], l_file_hdr.net_id);
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
    if(!a_wallet_name || !a_wallets_path)
        return NULL;
    size_t l_file_name_size = strlen(a_wallet_name)+strlen(a_wallets_path)+13;
    char *l_file_name = DAP_NEW_Z_SIZE (char, l_file_name_size);
    dap_snprintf(l_file_name, l_file_name_size, "%s/%s.dwallet", a_wallets_path, a_wallet_name);
    dap_chain_wallet_t * l_wallet = dap_chain_wallet_open_file(l_file_name);
    DAP_DELETE(l_file_name);
    return l_wallet;
}
