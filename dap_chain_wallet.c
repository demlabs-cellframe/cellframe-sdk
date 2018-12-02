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

#include "dap_common.h"
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
 * @brief dap_chain_wallet_open
 * @param a_file_name
 * @param a_sig_type
 * @details Creates new one if not found
 * @return Wallet, new wallet or NULL if errors
 */
dap_chain_wallet_t * dap_chain_wallet_create(const char * a_file_name, dap_chain_sign_type_t a_sig_type)
{
    dap_chain_wallet_t * l_wallet = DAP_NEW_Z(dap_chain_wallet_t);
    DAP_CHAIN_WALLET_INTERNAL_LOCAL_NEW(l_wallet);
    return l_wallet;
}

/**
 * @brief dap_chain_wallet_close
 * @param a_wallet
 */
void dap_chain_wallet_close( dap_chain_wallet_t * a_wallet)
{
    DAP_CHAIN_WALLET_INTERNAL_LOCAL(a_wallet);
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
    if( l_wallet_internal->keys_count > a_pkey_idx ){
        //return dap_enc_key_new()  l_wallet_internal->keys[a_pkey_idx];
    }else{
        log_it( L_WARNING, "No key with index %u in the wallet (total size %u)",a_pkey_idx,l_wallet_internal->keys_count);
        return 0;
    }
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
    if( l_wallet_internal->keys_count > a_pkey_idx ){
        return l_wallet_internal->keys[a_pkey_idx];
    }else{
        log_it( L_WARNING, "No key with index %u in the wallet (total size %u)",a_pkey_idx,l_wallet_internal->keys_count);
        return 0;
    }
}

/**
 * @brief dap_chain_wallet_sign
 * @param a_wallet
 * @param a_pkey_idx
 * @param a_data
 * @param a_data_size
 * @param a_sign
 * @param a_sign_size_max
 * @return 0 if everything is ok, negative value if error
 */
int dap_chain_wallet_sign( dap_chain_wallet_t * a_wallet,uint32_t a_pkey_idx, const void * a_data, size_t a_data_size,
                           void * a_sign, size_t a_sign_size_max)
{
    DAP_CHAIN_WALLET_INTERNAL_LOCAL(a_wallet);

    return 0;
}
