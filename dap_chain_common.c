/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
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

#include <string.h>
#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_enc_base58.h"

#define LOG_TAG "chain_common"

/**
 * @brief dap_chain_hash_to_str
 * @param a_hash
 * @param a_str
 * @param a_str_max
 * @return
 */
size_t dap_chain_hash_to_str(dap_chain_hash_t * a_hash, char * a_str, size_t a_str_max)
{
    const size_t c_hash_str_size = sizeof(*a_hash)*2 +1 /*trailing zero*/ +2 /* heading 0x */  ;
    if (a_str_max < c_hash_str_size ){
        log_it(L_ERROR,"String for hash too small, need %u but have only %u",c_hash_str_size,a_str_max);
    }
    size_t i;
    snprintf(a_str,3,"0x");
    for (i = 0; i< sizeof(a_hash->raw); ++i)
        snprintf(a_str+i*2+2,3,"%02x",a_hash->raw[i]);
    a_str[c_hash_str_size]='\0';
    return  strlen(a_str);
}

/**
 * @brief dap_chain_addr_to_str
 * @param a_addr
 * @return
 */
char* dap_chain_addr_to_str(dap_chain_addr_t *a_addr)
{
    size_t l_ret_size = DAP_ENC_BASE58_ENCODE_SIZE (sizeof (dap_chain_addr_t) );
    char * l_ret = DAP_NEW_SIZE(char,l_ret_size);
    if ( dap_enc_base58_encode(a_addr,sizeof(dap_chain_addr_t),l_ret) > 0 )
        return l_ret;
    else{
        DAP_DELETE(l_ret);
        return NULL;
    }
}

/**
 * @brief dap_chain_str_to_addr
 * @param a_addr
 * @return
 */
dap_chain_addr_t* dap_chain_str_to_addr(const char *str)
{
    size_t str_len = (str) ? strlen(str) : 0;
    if(str_len<=0)
        return NULL;
    size_t l_ret_size = DAP_ENC_BASE58_DECODE_SIZE (str_len);
    dap_chain_addr_t * a_addr = DAP_NEW_Z_SIZE(dap_chain_addr_t,l_ret_size);
    if ( dap_enc_base58_decode(str, a_addr) == sizeof(dap_chain_addr_t) )
        return a_addr;
    else
        DAP_DELETE(a_addr);
    return NULL;
}
