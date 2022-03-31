/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Blockchain community https://github.com/kelvinblockchain
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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_enc_base58.h"

#define LOG_TAG "dap_enc_base58"

const char c_b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const int8_t c_b58digits_map[] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,
};

/**
 * @brief dap_enc_base58_decode decode string using base58 alghoritm
 * @param a_in - encoded string
 * @param a_out - output buffer
 * @return size_t output buffer size
 */
size_t dap_enc_base58_decode(const char * a_in, void * a_out)
{
    size_t l_out_size_max = DAP_ENC_BASE58_DECODE_SIZE(strlen(a_in ));
    size_t l_out_size = l_out_size_max;

    const unsigned char *l_in_u8 = (const unsigned char*)a_in;
    size_t l_outi_size = (l_out_size_max + 3) / 4;

    uint32_t l_outi[l_outi_size];
    memset(l_outi, 0, l_outi_size*sizeof(uint32_t));
    uint64_t t;
    uint32_t c;
    size_t i, j;
    uint8_t bytesleft = l_out_size_max % 4;
    uint32_t zeromask = bytesleft ? (0xffffffff << (bytesleft * 8)) : 0;
    unsigned zerocount = 0;
    size_t l_in_len = strlen(a_in);


    // Leading zeros, just count
    for (i = 0; i < l_in_len && l_in_u8[i] == '1'; ++i)
        ++zerocount;

    for ( ; i < l_in_len; ++i)
    {
        if (l_in_u8[i] & 0x80)
            // High-bit set on invalid digit
            return 0;
        if (c_b58digits_map[l_in_u8[i]] == -1)
            // Invalid base58 digit
            return 0;
        c = (unsigned)c_b58digits_map[l_in_u8[i]];
        for (j = l_outi_size; j--; )
        {
            t = ((uint64_t)l_outi[j]) * 58 + c;
            c = (t & 0x3f00000000) >> 32;
            l_outi[j] = t & 0xffffffff;
        }
        if (c)
            // Output number too big (carry to the next int32)
            return 0;
        if (l_outi[0] & zeromask)
            // Output number too big (last int32 filled too far)
            return 0;
    }

    unsigned char l_out_u80[l_out_size_max];
    memset(l_out_u80,0,l_out_size_max);
    unsigned char *l_out_u8 = l_out_u80;
    j = 0;
    switch (bytesleft) {
        case 3:
            *(l_out_u8++) = (l_outi[0] &   0xff0000) >> 16;
            //-fallthrough
        case 2:
            *(l_out_u8++) = (l_outi[0] &     0xff00) >>  8;
            //-fallthrough
        case 1:
            *(l_out_u8++) = (l_outi[0] &       0xff);
            ++j;
            //-fallthrough
        default:
            break;
    }

    for (; j < l_outi_size; ++j)
    {
        *(l_out_u8++) = (l_outi[j] >> 0x18) & 0xff;
        *(l_out_u8++) = (l_outi[j] >> 0x10) & 0xff;
        *(l_out_u8++) = (l_outi[j] >>    8) & 0xff;
        *(l_out_u8++) = (l_outi[j] >>    0) & 0xff;
    }

    // Count canonical base58 byte count
    l_out_u8 = l_out_u80;
    for (i = 0; i < l_out_size_max; ++i)
    {
        if (l_out_u8[i]) {
            if (zerocount > i) {
                /* result too large */
                return 0;
            }
            break;
        }
        --l_out_size;
    }


    unsigned char *l_out = a_out;
    memset(l_out, 0, zerocount);
    // shift result to beginning of the string
    for (j = 0; j < l_out_size; j++){
        l_out[j+zerocount] = l_out_u8[j+i];
    }
    l_out[j+zerocount] = 0;
    l_out_size += zerocount;

    return l_out_size;
}


/**
 * @brief dap_enc_base58_encode encode string in Base58 alghorithm
 * 
 * @param a_in - input buffer
 * @param a_in_size - buffer size
 * @param a_out - string with results
 * @return size_t - returned string size (in bytes)
 */
size_t dap_enc_base58_encode(const void * a_in, size_t a_in_size, char * a_out)
{
    const uint8_t *l_in_u8 = a_in;
    int carry;
    ssize_t i, j, high, zcount = 0;
    size_t size;
    size_t l_out_size = DAP_ENC_BASE58_ENCODE_SIZE (a_in_size);
    while (zcount < (ssize_t)a_in_size && !l_in_u8[zcount])
        ++zcount;

    size = (a_in_size - zcount) * 138 / 100 + 1;
    uint8_t buf[size];
    memset(buf, 0, size);

    for (i = zcount, high = size - 1; i < (ssize_t)a_in_size; ++i, high = j)
    {
        for (carry = l_in_u8[i], j = size - 1; (j > high) || carry; --j)
        {
            carry += 256 * buf[j];
            buf[j] = carry % 58;
            carry /= 58;
        }
    }

    for (j = 0; j < (ssize_t)size && !buf[j]; ++j);

    if (l_out_size <= ( zcount + size - j) ){
        l_out_size = ( zcount + size - j + 1 );
        return l_out_size;
    }

    if (zcount)
        memset(a_out, '1', zcount);
    for (i = zcount; j < (ssize_t)size; ++i, ++j)
        a_out[i] = c_b58digits_ordered[buf[j]];
    a_out[i] = '\0';
    l_out_size = i;

    return l_out_size;
}

/**
 * @brief dap_enc_base58_encode_to_str Encode to base58 and convert to string like '0xXXXXXXXXXXXXXXX'
 * @param a_in buffer for encode
 * @param a_in_size size of string
 * @return allocated string or NULL if error
 */
char* dap_enc_base58_encode_to_str(const void * a_in, size_t a_in_size)
{
    size_t l_out_size = DAP_ENC_BASE58_ENCODE_SIZE (a_in_size);
    char * l_out = DAP_NEW_Z_SIZE(char, l_out_size + 1);//+ 3); no prefix needed
    size_t l_size = dap_enc_base58_encode(a_in, a_in_size, l_out);//l_out+2); no prefix needed
    if(!l_size || !l_out){
        DAP_DELETE(l_out);
        return NULL;
    }
    // no prefix needed
    // memcpy(l_out, "0x", 2);
    return l_out;
}

char* dap_enc_base58_encode_hash_to_str(dap_chain_hash_fast_t *a_in_hash)
{
    return dap_enc_base58_encode_to_str(a_in_hash->raw, sizeof(dap_chain_hash_fast_t));
}

// convert from "0xA21F1E865B6740A28E8708798ECF25D2C0AA596DF5EB1FD724186B6AD7FF2199" to "Bura1HFrKsqbdytEXQVrxpbovtvLhR1VbrJs65JBx3gc"
char* dap_enc_base58_from_hex_str_to_str(const char *a_in_str)
{
    size_t a_in_hash_len = dap_strlen(a_in_str);
    if(a_in_hash_len<3 || dap_strncmp(a_in_str,"0x",2))
        return NULL;
    // from "0x..." to binary
    char *l_out_str = DAP_NEW_Z_SIZE(char, a_in_hash_len / 2 + 1);
    size_t len = dap_hex2bin((uint8_t*)l_out_str, a_in_str+2, a_in_hash_len-2);
    // from binary to base58
    char *l_base58_out = dap_enc_base58_encode_to_str(l_out_str, len/2);
    DAP_DELETE(l_out_str);
    return l_base58_out;
}

// convert from "Bura1HFrKsqbdytEXQVrxpbovtvLhR1VbrJs65JBx3gc" to "0xA21F1E865B6740A28E8708798ECF25D2C0AA596DF5EB1FD724186B6AD7FF2199"
char* dap_enc_base58_to_hex_str_from_str(const char *a_in_str)
{
    size_t a_in_hash_len = dap_strlen(a_in_str);
    if(a_in_hash_len < 8)
        return NULL;
    // from base58 to binary
    size_t l_out_size_max = DAP_ENC_BASE58_DECODE_SIZE(a_in_hash_len);
    void * l_out = DAP_NEW_Z_SIZE(char, l_out_size_max + 1);
    size_t l_out_size = dap_enc_base58_decode( a_in_str, l_out);
    // dap_htoa64() requires a multiple of 8 bytes
    if(l_out_size < 8 || l_out_size%8){
        DAP_DELETE(l_out);
        return NULL;
    }
    // from binary to "0x..."
    size_t l_out_str_size = l_out_size * 2 + 3;
    char* l_out_str = DAP_NEW_Z_SIZE(char, l_out_str_size);
    l_out_str[0] = '0';
    l_out_str[1] = 'x';
    dap_htoa64((l_out_str + 2), l_out, l_out_size);
    DAP_DELETE(l_out);
    return l_out_str;
}
