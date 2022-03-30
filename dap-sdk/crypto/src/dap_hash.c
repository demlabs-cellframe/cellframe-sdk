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
#include <stdio.h>
#include <stdlib.h>
#include "dap_strfuncs.h"
#include "dap_common.h"
#include "dap_hash.h"
#include "dap_enc_base58.h"

#include "KeccakHash.h"
#include "SimpleFIPS202.h"

#define LOG_TAG "dap_hash"

/**
 * @brief dap_chain_str_to_hash_fast_to_str
 * @param a_hash_str
 * @param a_hash
 * @return
 */
int dap_chain_hash_fast_from_hex_str( const char *a_hex_str, dap_chain_hash_fast_t *a_hash)
{
    const size_t c_hash_str_size = sizeof(*a_hash) * 2 + 1 /*trailing zero*/+ 2 /* heading 0x */;
    size_t l_hash_str_len = strlen(a_hex_str);
    if ( l_hash_str_len + 1 == c_hash_str_size ){
        for(size_t l_offset = 2; l_offset < l_hash_str_len; l_offset += 2) {
            char l_byte;
            if(dap_sscanf(a_hex_str + l_offset, "%02hhx", &l_byte) != 1) {
                if(dap_sscanf(a_hex_str + l_offset, "%02hhx", &l_byte) != 1) {
                    log_it(L_ERROR, "dap_chain_str_to_hash_fast parse error: offset=%zu, hash_str_len=%zu, str=\"%2s\"",
                            l_offset, l_hash_str_len, a_hex_str + l_offset);
                    return -10 * ((int) l_offset); // Wrong char
                }
            }
            *(a_hash->raw + l_offset / 2 - 1) = l_byte;
        }
        return  0;
    }else  // Wrong string len
        return -1;
}


/**
 * @brief dap_chain_hash_fast_from_base58_str
 * @param a_base58_str
 * @param a_datum_hash
 * @return
 */
int dap_chain_hash_fast_from_base58_str(const char *a_base58_str,  dap_chain_hash_fast_t *a_hash)
{
    if (!a_hash)
        return -1;
    if (!a_base58_str)
        return -2;
    size_t l_hash_len = dap_strlen(a_base58_str);
    if (l_hash_len > DAP_ENC_BASE58_ENCODE_SIZE(sizeof(dap_hash_fast_t)))
        return -3;
    // from base58 to binary
    byte_t l_out[DAP_ENC_BASE58_DECODE_SIZE(DAP_ENC_BASE58_ENCODE_SIZE(sizeof(dap_hash_fast_t)))];
    size_t l_out_size = dap_enc_base58_decode(a_base58_str, l_out);
    if (l_out_size != sizeof(dap_hash_fast_t))
        return -4;
    memcpy(a_hash, l_out, sizeof(dap_hash_fast_t));
    return 0;
}

int dap_chain_hash_fast_from_str( const char *a_hash_str, dap_chain_hash_fast_t *a_hash)
{
    return dap_chain_hash_fast_from_hex_str(a_hash_str, a_hash) && dap_chain_hash_fast_from_base58_str(a_hash_str, a_hash);
}
