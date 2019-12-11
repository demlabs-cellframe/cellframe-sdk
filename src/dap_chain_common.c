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
#include "dap_sign.h"
#include "dap_chain_common.h"
#include "dap_enc_base58.h"
#include "dap_hash.h"

#define LOG_TAG "dap_chain_common"

/**
 * @brief dap_chain_hash_to_str
 * @param a_hash
 * @param a_str
 * @param a_str_max
 * @return
 */
size_t dap_chain_hash_slow_to_str( dap_chain_hash_slow_t *a_hash, char *a_str, size_t a_str_max )
{
    const size_t c_hash_str_size = sizeof(*a_hash) * 2 + 1 /*trailing zero*/+ 2 /* heading 0x */;

    if(a_str_max < c_hash_str_size) {
        log_it(L_ERROR, "String for hash too small, need %u but have only %u", c_hash_str_size, a_str_max);
    }
    size_t i;
    dap_snprintf(a_str, 3, "0x");

    for(i = 0; i < sizeof(a_hash->raw); ++i)
        dap_snprintf( a_str + i * 2 + 2, 3, "%02x", a_hash->raw[i] );

    a_str[c_hash_str_size] = '\0';

//#define dap_htoa64( out, in, len ) \


    return strlen(a_str);
}

/**
 * @brief dap_chain_hash_fast_to_str
 * @param a_hash
 * @param a_str
 * @param a_str_max
 * @return
 */
#if 0
size_t dap_chain_hash_fast_to_str( dap_chain_hash_fast_t *a_hash, char *a_str, size_t a_str_max )
{
    const size_t c_hash_str_size = sizeof(*a_hash) * 2 + 1 /*trailing zero*/+ 2 /* heading 0x */;

    if ( a_str_max < c_hash_str_size ) {
      log_it( L_ERROR, "String for hash too small, need %u but have only %u", c_hash_str_size, a_str_max );
    }

//    size_t i;
    // faster conversion to string

    dap_snprintf( a_str, 3, "0x" );

    size_t l_ret = dap_bin2hex(a_str + 2, a_hash->raw, sizeof(a_hash->raw));

    //for(i = 0; i < sizeof(a_hash->raw); ++i)
    //    dap_snprintf(a_str + i * 2 + 2, 3, "%02x", (a_hash->raw[i]));

    a_str[c_hash_str_size - 1] = '\0';

    if(!l_ret)
        return 0;

    return c_hash_str_size - 1; //strlen(a_str);
}
#endif



/**
 * @brief dap_chain_addr_to_str
 * @param a_addr
 * @return
 */
char* dap_chain_addr_to_str(const dap_chain_addr_t *a_addr)
{
    if ( a_addr ==NULL)
        return  NULL;

    size_t l_ret_size = DAP_ENC_BASE58_ENCODE_SIZE(sizeof(dap_chain_addr_t));
    char * l_ret = DAP_NEW_SIZE(char, l_ret_size);
    if(dap_enc_base58_encode(a_addr, sizeof(dap_chain_addr_t), l_ret) > 0)
        return l_ret;
    else {
        DAP_DELETE(l_ret);
        return NULL;
    }
}

/**
 * @brief dap_chain_str_to_addr
 * @param a_addr
 * @return
 */
dap_chain_addr_t* dap_chain_addr_from_str(const char *a_str)
{
    size_t l_str_len = (a_str) ? strlen(a_str) : 0;
    if(l_str_len <= 0)
        return NULL;
    size_t l_ret_size = DAP_ENC_BASE58_DECODE_SIZE(l_str_len);
    dap_chain_addr_t * l_addr = DAP_NEW_Z_SIZE(dap_chain_addr_t, l_ret_size);
    if(dap_enc_base58_decode(a_str, l_addr) == sizeof(dap_chain_addr_t) &&
            dap_chain_addr_check_sum(l_addr)==1)
        return l_addr;
    else
        DAP_DELETE(l_addr);
    return NULL;
}

/**
 * @brief dap_chain_net_id_from_str
 * @param a_net_str
 * @return
 */
dap_chain_net_id_t dap_chain_net_id_from_str( const char * a_net_str)
{
    dap_chain_net_id_t l_ret={0};
    size_t l_net_str_len = strlen( a_net_str);
    if (l_net_str_len >2){
        a_net_str+=2;
        l_net_str_len-=2;
        if (l_net_str_len == sizeof (l_ret)/2 ){
            size_t l_pos =0;
            char l_byte[3];
            while(l_net_str_len){
                // Copy two characters for bytes
                memcpy(l_byte,a_net_str,2);
                l_byte[2]='\0';
                // Read byte chars
                if ( sscanf(l_byte,"%02hhx",&l_ret.raw[l_pos] ) != 1)
                    if( sscanf(l_byte,"%02hhX",&l_ret.raw[l_pos] ) ==1 )
                        break;

                // Update pos
                l_pos++;
                // Reduce in two steps to not to break if input will have bad input
                l_net_str_len-=1;
                if(l_net_str_len)
                    l_net_str_len-=1;
            }
        }else
            log_it(L_WARNING,"Wrong input string \"%s\" not recognized as network id", a_net_str);
    }
    return  l_ret;
}

/**
 * @brief dap_chain_net_srv_uid_from_str
 * @param a_net_str
 * @return
 */
dap_chain_net_srv_uid_t dap_chain_net_srv_uid_from_str( const char * a_net_srv_uid_str)
{
    dap_chain_net_srv_uid_t l_ret={{0}};
    size_t l_net_srv_uid_str_len = strlen( a_net_srv_uid_str);
    if (l_net_srv_uid_str_len >2){
        a_net_srv_uid_str+=2;
        l_net_srv_uid_str_len-=2;
        if (l_net_srv_uid_str_len == sizeof (l_ret)/2 ){
            size_t l_pos =0;
            char l_byte[3];
            while(l_net_srv_uid_str_len){

                // Copy two characters for bytes
                memcpy(l_byte,a_net_srv_uid_str,2);
                l_byte[2]='\0';

                // Read byte chars
                if ( sscanf(l_byte,"%02hhx",&l_ret.raw[l_pos] ) != 1)
                    if( sscanf(l_byte,"%02hhX",&l_ret.raw[l_pos] ) ==1 )
                        break;

                // Update pos
                l_pos++;
                // Reduce in two steps to not to break if input will have bad input
                l_net_srv_uid_str_len-=1;
                if(l_net_srv_uid_str_len)
                    l_net_srv_uid_str_len-=1;
            }
        }else
            log_it(L_WARNING,"Wrong input string \"%s\" not recognized as network id", a_net_srv_uid_str);
    }
    return  l_ret;
}



/**
 * @brief dap_chain_addr_fill
 * @param a_addr
 * @param a_key
 * @param a_net_id
 * @return
 */
void dap_chain_addr_fill(dap_chain_addr_t *a_addr, dap_enc_key_t *a_key, dap_chain_net_id_t *a_net_id)
{
    if(!a_addr || !a_key || !a_net_id)
        return;
    a_addr->addr_ver = DAP_CHAIN_ADDR_VERSION_CURRENT;
    a_addr->net_id.uint64 = a_net_id->uint64;
    a_addr->sig_type.raw = dap_sign_type_from_key_type(a_key->type).raw;
    // key -> serialized key
    dap_chain_hash_fast_t l_hash_public_key;
    size_t l_pub_key_data_size;
    uint8_t *l_pub_key_data = dap_enc_key_serealize_pub_key(a_key, &l_pub_key_data_size);
    // serialized key -> key hash

    if(dap_hash_fast(l_pub_key_data, l_pub_key_data_size, &l_hash_public_key))
        memcpy(a_addr->data.hash, l_hash_public_key.raw, sizeof(l_hash_public_key.raw));
    DAP_DELETE(l_pub_key_data);
    // calc checksum
    dap_hash_fast(a_addr, sizeof(dap_chain_addr_t) - sizeof(dap_chain_hash_fast_t), &a_addr->checksum);
}

/**
 * @brief dap_chain_addr_check_sum
 * @param a_addr
 * @return 1 Ok, -1 Invalid a_addr or checksum
 */
int dap_chain_addr_check_sum(const dap_chain_addr_t *a_addr)
{
    if(!a_addr)
        return -1;
    dap_chain_hash_fast_t l_checksum;
    // calc checksum
    dap_hash_fast(a_addr, sizeof(dap_chain_addr_t) - sizeof(dap_chain_hash_fast_t), &l_checksum);
    if(!memcmp(a_addr->checksum.raw, l_checksum.raw, sizeof(l_checksum.raw)))
        return 1;
    return -1;
}
