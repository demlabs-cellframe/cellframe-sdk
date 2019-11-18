/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Aleksandr Lysikov <alexander.lysikov@demlabs.net>
 * CellFrame       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2017-2019
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
#include <stddef.h>

#include <dap_common.h>
#include "dap_config.h"
#include "dap_enc_key.h"
#include "dap_strfuncs.h"
#include "dap_hash.h"

#include "dap_chain_common.h"
#include "dap_chain_sign.h"
#include "dap_chain_wallet.h"

#include "dap_chain_net_srv_key.h"

#define LOG_TAG "dap_chain_net_srv_key"

/**
 * Parse a_service_key from service client
 * a_addr_base58[out] - address
 * a_sign_hash[out] - hash of sign
 */
bool dap_chain_net_srv_key_parse(const char *a_service_key, char **a_addr_base58, char **a_sign_hash)
{
    bool l_ret = false;
    // format a_service_key = "a_addr_base58;a_sign_hash"
    if(!a_service_key)
        return false;
    char **l_str = dap_strsplit(a_service_key, ";", -1);
    if(dap_str_countv(l_str) == 2) {
        if(a_addr_base58)
            *a_addr_base58 = strdup(l_str[0]);
        if(a_sign_hash)
            *a_sign_hash = strdup(l_str[1]);
        l_ret = true;
    }
    dap_strfreev(l_str);
    return l_ret;
}

/**
 * Create new service_key
 */
char* dap_chain_net_srv_key_create(const char *a_wallet_name)
{
    char *l_addr_base58 = NULL;
    char *l_sign_hash_str = dap_chain_net_srv_key_create_hash(a_wallet_name, &l_addr_base58);
    char *l_ret_str = NULL;

    if(l_sign_hash_str && l_addr_base58) {
        l_ret_str = dap_strdup_printf("%s;%s", l_addr_base58, l_sign_hash_str);
    }
    DAP_DELETE(l_addr_base58);
    DAP_DELETE(l_sign_hash_str);
    return l_ret_str;
}

/**
 * Create new key hash
 */
char* dap_chain_net_srv_key_create_hash(const char *a_wallet_name, char **a_addr_base58)
{
    const char *c_wallets_path = dap_config_get_item_str(g_config, "general", "wallets_path");
    dap_chain_wallet_t * l_wallet = dap_chain_wallet_open(a_wallet_name, c_wallets_path);
    if(!l_wallet)
        return NULL;
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(l_wallet, 0);
    const dap_chain_addr_t *l_addr = NULL;// TODO: make work with chain network //  dap_chain_wallet_get_addr(l_wallet);
    char *l_addr_base58 = dap_chain_addr_to_str(l_addr);
    if(!l_addr_base58)
        return NULL;

    // make signature
    const void *l_data = l_addr_base58;
    const size_t l_data_size = strlen(l_data);
    dap_chain_sign_t *l_chain_sign = dap_chain_sign_create(l_key, l_data, l_data_size, 0);
    size_t l_chain_sign_size = dap_chain_sign_get_size(l_chain_sign);

    dap_chain_wallet_close(l_wallet);
    if(a_addr_base58)
        *a_addr_base58 = l_addr_base58;
    else
        DAP_DELETE(l_addr_base58);

    // make dap_chain_sign_t hash
    dap_chain_hash_fast_t l_sign_hash;
    if(!dap_hash_fast(l_chain_sign, l_chain_sign_size, &l_sign_hash) ) {
        return NULL;
    }

    // hash to str
    const size_t cl_str_ret_size = sizeof(dap_chain_hash_fast_t) * 2 + 1;
    char *l_str_ret = DAP_NEW_Z_SIZE(char, sizeof(dap_chain_hash_fast_t) * 2 + 1);
    dap_chain_hash_fast_to_str(&l_sign_hash, l_str_ret, cl_str_ret_size);
    return l_str_ret;
}

/**
 * Checking service_key from service client
 */
bool dap_chain_net_srv_key_check(char *a_addr_base58, const char *a_sign_hash_str)
{
    //exist_user_in_db("da");
    if(!a_addr_base58 || !a_sign_hash_str)
        return false;

    /*    // create l_chain_sign for check a_sign
     dap_chain_sign_t *l_chain_sign = DAP_NEW_Z_SIZE(dap_chain_sign_t,
     sizeof(dap_chain_sign_t) + a_sign_size + l_pkey_size);
     l_chain_sign->header.type = l_sig_type;
     l_chain_sign->header.sign_size = l_pkey_size;
     l_chain_sign->header.sign_pkey_size = l_pkey_size;
     // write serialized public key to dap_chain_sign_t
     memcpy(l_chain_sign->pkey_n_sign, l_pkey, l_pkey_size);
     // write serialized signature to dap_chain_sign_t
     memcpy(l_chain_sign->pkey_n_sign + l_pkey_size, a_sign, a_sign_size);

     // check signature
     if(dap_chain_sign_verify(l_chain_sign, a_sign, a_sign_size) != 1) {
     // invalid signature
     return 0;
     }*/

    // TODO add find l_wallet_name by a_addr_base58
    const char *l_wallet_name = "w_picnic";
    // Create new hash
    char *l_sign_hash_str = dap_chain_net_srv_key_create_hash(l_wallet_name, NULL);
    size_t l_sign_hash_str_len = (l_sign_hash_str) ? strlen(l_sign_hash_str) : 0;

    // compare l_sign_hash_str and a_sign_hash_str
    if(!l_sign_hash_str_len || l_sign_hash_str_len != strlen(a_sign_hash_str)) {
        return false;
    }
    if(memcmp(l_sign_hash_str, a_sign_hash_str, l_sign_hash_str_len)) {
        return false;
    }

    return true;
}
