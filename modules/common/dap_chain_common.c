/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Demlabs Application Protocol) the open source project

    DAP (Demlabs Application Protocol) is free software: you can redistribute it and/or modify
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
#include <ctype.h>
#include <errno.h>
#ifdef DAP_OS_WINDOWS
#include <time.h>
#endif
#include "dap_common.h"
#include "dap_sign.h"
#include "dap_chain_common.h"
#include "dap_enc_base58.h"
#include "dap_hash.h"
#include "dap_strfuncs.h"

#define LOG_TAG "dap_chain_common"

const dap_chain_net_srv_uid_t c_dap_chain_net_srv_uid_null = {0};
const dap_chain_cell_id_t c_dap_chain_cell_id_null = {0};
const dap_chain_addr_t c_dap_chain_addr_blank = {0};

int dap_id_uint64_parse(const char *a_id_str, uint64_t *a_id)
{
    if (!a_id_str || !a_id || (sscanf(a_id_str, "0x%16"DAP_UINT64_FORMAT_X, a_id) != 1 &&
            sscanf(a_id_str, "0x%16"DAP_UINT64_FORMAT_x, a_id) != 1 &&
            sscanf(a_id_str, "%"DAP_UINT64_FORMAT_U, a_id) != 1)) {
        log_it (L_ERROR, "Can't recognize '%s' string as 64-bit id, hex or dec", a_id_str);
        return -1;
    }
    return 0;
}

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
        log_it(L_ERROR, "String for hash too small, need %zu but have only %zu", c_hash_str_size, a_str_max);
    }
    size_t i;
    snprintf(a_str, 3, "0x");

    for(i = 0; i < sizeof(a_hash->raw); ++i)
        snprintf( a_str + i * 2 + 2, 3, "%02x", a_hash->raw[i] );

    a_str[c_hash_str_size] = '\0';

    return strlen(a_str);
}

/**
 * @brief dap_chain_addr_to_str
 * @param a_addr
 * @return
 */
char *dap_chain_addr_to_str(const dap_chain_addr_t *a_addr)
{
// sanity check
    dap_return_val_if_pass(!a_addr, NULL);
// func work
    if (dap_chain_addr_is_blank(a_addr)) return dap_strdup("null");

    return dap_enc_base58_encode_to_str((const void *)a_addr, sizeof(dap_chain_addr_t));
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
    if (!dap_strcmp(a_str, "null") || !dap_strcmp(a_str, "0")) {
        return DAP_NEW_Z(dap_chain_addr_t);
    }
    size_t l_ret_size = DAP_ENC_BASE58_DECODE_SIZE(l_str_len);
    dap_chain_addr_t *l_addr = DAP_NEW_Z_SIZE(dap_chain_addr_t, l_ret_size);
    return (dap_enc_base58_decode(a_str, l_addr) == sizeof(dap_chain_addr_t)) && !dap_chain_addr_check_sum(l_addr)
            ? l_addr
            : ({ DAP_DELETE(l_addr); NULL; });
}

bool dap_chain_addr_is_blank(const dap_chain_addr_t *a_addr)
{
    return dap_chain_addr_compare(a_addr, &c_dap_chain_addr_blank);
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
                unsigned int l_bytechar;
                if ( sscanf(l_byte,"%02x", &l_bytechar) != 1)
                    if( sscanf(l_byte,"%02X", &l_bytechar) != 1 )
                        break;
                l_ret.raw[l_pos] = l_bytechar;
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
 * @brief dap_chain_addr_fill_from_key
 * @param a_addr
 * @param a_key
 * @param a_net_id
 * @return
 */
int dap_chain_addr_fill_from_key(dap_chain_addr_t *a_addr, dap_enc_key_t *a_key, dap_chain_net_id_t a_net_id)
{
    dap_sign_type_t l_type = dap_sign_type_from_key_type(a_key->type);
    size_t l_pub_key_data_size;
    uint8_t *l_pub_key_data = dap_enc_key_serialize_pub_key(a_key, &l_pub_key_data_size);
    if (!l_pub_key_data) {
        log_it(L_ERROR,"Can't fill address from key, its empty");
        return -1;
    }
    dap_chain_hash_fast_t l_hash_public_key;
    // serialized key -> key hash
    dap_hash_fast(l_pub_key_data, l_pub_key_data_size, &l_hash_public_key);
    dap_chain_addr_fill(a_addr, l_type, &l_hash_public_key, a_net_id);
    DAP_DELETE(l_pub_key_data);
    return 0;
}

int dap_chain_addr_fill_from_sign(dap_chain_addr_t *a_addr, dap_sign_t *a_sign, dap_chain_net_id_t a_net_id)
{
    dap_hash_fast_t l_sign_pkey_hash;
    if (!dap_sign_get_pkey_hash(a_sign, &l_sign_pkey_hash))
        return -1;
    dap_chain_addr_fill(a_addr, a_sign->header.type, &l_sign_pkey_hash, a_net_id);
    return 0;
}

/**
 * @brief dap_chain_addr_fill
 * @param a_addr
 * @param a_type
 * @param a_pkey_hash
 * @param a_net_id
 * @return
 */
void dap_chain_addr_fill(dap_chain_addr_t *a_addr, dap_sign_type_t a_type, dap_chain_hash_fast_t *a_pkey_hash, dap_chain_net_id_t a_net_id)
{
    if(!a_addr || !a_pkey_hash)
        return;
    a_addr->addr_ver = DAP_CHAIN_ADDR_VERSION_CURRENT;
    a_addr->net_id.uint64 = a_net_id.uint64;
    a_addr->sig_type.raw = a_type.raw;
    memcpy(a_addr->data.hash, a_pkey_hash, sizeof(dap_chain_hash_fast_t));
    // calc checksum
    dap_hash_fast(a_addr, sizeof(dap_chain_addr_t) - sizeof(dap_chain_hash_fast_t), &a_addr->checksum);
}

/**
 * @brief dap_chain_addr_check_sum
 * @param a_addr
 * @return 0 - Ok, otherwise - Invalid a_addr or checksum
 */
int dap_chain_addr_check_sum(const dap_chain_addr_t *a_addr)
{
    if(!a_addr)
        return -1;
    if (dap_chain_addr_is_blank(a_addr))
        return 0;
    dap_chain_hash_fast_t l_checksum;
    // calc checksum
    dap_hash_fast(a_addr, sizeof(dap_chain_addr_t) - sizeof(dap_chain_hash_fast_t), &l_checksum);
    return memcmp(a_addr->checksum.raw, l_checksum.raw, sizeof(l_checksum.raw));
}



uint64_t dap_chain_uint128_to(uint128_t a_from)
{
#ifdef DAP_GLOBAL_IS_INT128
    if (a_from > UINT64_MAX) {
        log_it(L_ERROR, "Can't convert balance to uint64_t. It's too big.");
    }
    return (uint64_t)a_from;
#else
    if (a_from.hi) {
        log_it(L_ERROR, "Can't convert balance to uint64_t. It's too big.");
    }
    return a_from.lo;
#endif
}

uint64_t dap_chain_uint256_to(uint256_t a_from)
{
#ifdef DAP_GLOBAL_IS_INT128
    if (a_from.hi || a_from.lo > UINT64_MAX) {
        log_it(L_ERROR, "Can't convert balance to uint64_t. It's too big.");
    }
    return (uint64_t)a_from.lo;
#else
    if (!IS_ZERO_128(a_from.hi) || a_from.lo.hi) {
        log_it(L_ERROR, "Can't convert balance to uint64_t. It's too big.");
    }
    return a_from.lo.lo;
#endif
}

// 256
uint128_t dap_chain_uint128_from_uint256(uint256_t a_from)
{
    if ( !( EQUAL_128(a_from.hi, uint128_0) ) ) {
        log_it(L_ERROR, "Can't convert to uint128_t. It's too big.");
    }
    return a_from.lo;
}


char *dap_chain_balance_print128(uint128_t a_balance)
{
    char *l_buf = DAP_NEW_Z_SIZE(char, DATOSHI_POW + 2);
    if (!l_buf) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    int l_pos = 0;
    uint128_t l_value = a_balance;
#ifdef DAP_GLOBAL_IS_INT128
    do {
        l_buf[l_pos++] = (l_value % 10) + '0';
        l_value /= 10;
    } while (l_value);
#else
    uint32_t l_tmp[4] = {l_value.u32.a, l_value.u32.b, l_value.u32.c, l_value.u32.d};
    uint64_t t, q;
    do {
        q = 0;
        // Byte order is 1, 0, 3, 2 for little endian
        for (int i = 1; i <= 3; ) {
            t = q << 32 | l_tmp[i];
            q = t % 10;
            l_tmp[i] = t / 10;
            if (i == 2) i = 4; // end of cycle
            if (i == 3) i = 2;
            if (i == 0) i = 3;
            if (i == 1) i = 0;
        }
        l_buf[l_pos++] = q + '0';
    } while (l_tmp[2]);
#endif
    int l_strlen = strlen(l_buf) - 1;
    for (int i = 0; i < (l_strlen + 1) / 2; i++) {
        char c = l_buf[i];
        l_buf[i] = l_buf[l_strlen - i];
        l_buf[l_strlen - i] = c;
    }
    return l_buf;
}

char *dap_chain_balance_to_coins128(uint128_t a_balance)
{
    char *l_buf = dap_chain_balance_print128(a_balance);
    int l_strlen = strlen(l_buf);
    int l_pos;
    if (l_strlen > DATOSHI_DEGREE) {
        for (l_pos = l_strlen; l_pos > l_strlen - DATOSHI_DEGREE; l_pos--) {
            l_buf[l_pos] = l_buf[l_pos - 1];
        }
        l_buf[l_pos] = '.';
    } else {
        int l_sub = DATOSHI_DEGREE - l_strlen + 2;
        for (l_pos = DATOSHI_DEGREE + 1; l_pos >= 0; l_pos--) {
            l_buf[l_pos] = (l_pos >= l_sub) ? l_buf[l_pos - l_sub] : '0';
        }
        l_buf[1] = '.';
    }
    return l_buf;
}

const union __c_pow10__ {
    uint64_t u64[2];
    uint32_t u32[4];
} DAP_ALIGN_PACKED c_pow10[DATOSHI_POW] = {
        { .u64 = {0,                         1ULL} },                          // 0
        { .u64 = {0,                         10ULL} },                         // 1
        { .u64 = {0,                         100ULL} },                        // 2
        { .u64 = {0,                         1000ULL} },                       // 3
        { .u64 = {0,                         10000ULL} },                      // 4
        { .u64 = {0,                         100000ULL} },                     // 5
        { .u64 = {0,                         1000000ULL} },                    // 6
        { .u64 = {0,                         10000000ULL} },                   // 7
        { .u64 = {0,                         100000000ULL} },                  // 8
        { .u64 = {0,                         1000000000ULL} },                 // 9
        { .u64 = {0,                         10000000000ULL} },                // 10
        { .u64 = {0,                         100000000000ULL} },               // 11
        { .u64 = {0,                         1000000000000ULL} },              // 12
        { .u64 = {0,                         10000000000000ULL} },             // 13
        { .u64 = {0,                         100000000000000ULL} },            // 14
        { .u64 = {0,                         1000000000000000ULL} },           // 15
        { .u64 = {0,                         10000000000000000ULL} },          // 16
        { .u64 = {0,                         100000000000000000ULL} },         // 17
        { .u64 = {0,                         1000000000000000000ULL} },        // 18
        { .u64 = {0,                         10000000000000000000ULL} },       // 19
        { .u64 = {5ULL,                      7766279631452241920ULL} },        // 20
        { .u64 = {54ULL,                     3875820019684212736ULL} },        // 21
        { .u64 = {542ULL,                    1864712049423024128ULL} },        // 22
        { .u64 = {5421ULL,                   200376420520689664ULL} },         // 23
        { .u64 = {54210ULL,                  2003764205206896640ULL} },        // 24
        { .u64 = {542101ULL,                 1590897978359414784ULL} },        // 25
        { .u64 = {5421010ULL,                15908979783594147840ULL} },       // 26
        { .u64 = {54210108ULL,               11515845246265065472ULL} },       // 27
        { .u64 = {542101086ULL,              4477988020393345024ULL} },        // 28
        { .u64 = {5421010862ULL,             7886392056514347008ULL} },        // 29
        { .u64 = {54210108624ULL,            5076944270305263616ULL} },        // 30
        { .u64 = {542101086242ULL,           13875954555633532928ULL} },       // 31
        { .u64 = {5421010862427ULL,          9632337040368467968ULL} },        // 32
        { .u64 = {54210108624275ULL,         4089650035136921600ULL} },        // 33
        { .u64 = {542101086242752ULL,        4003012203950112768ULL} },        // 34
        { .u64 = {5421010862427522ULL,       3136633892082024448ULL} },        // 35
        { .u64 = {54210108624275221ULL,      12919594847110692864ULL} },       // 36
        { .u64 = {542101086242752217ULL,     68739955140067328ULL} },          // 37
        { .u64 = {5421010862427522170ULL,    687399551400673280ULL} }          // 38
};

uint128_t dap_chain_balance_scan128(const char *a_balance)
{
    int l_strlen = strlen(a_balance);
    uint128_t l_ret = uint128_0, l_nul = uint128_0;
    if (l_strlen > DATOSHI_POW)
        return l_nul;
    for (int i = 0; i < l_strlen ; i++) {
        char c = a_balance[l_strlen - i - 1];
        if (!isdigit(c)) {
            log_it(L_WARNING, "Incorrect input number");
            return l_nul;
        }
        uint8_t l_digit = c - '0';
        if (!l_digit)
            continue;
#ifdef DAP_GLOBAL_IS_INT128
        uint128_t l_tmp = (uint128_t)c_pow10[i].u64[0] * l_digit;
        if (l_tmp >> 64) {
            log_it(L_WARNING, "Input number is too big");
            return l_nul;
        }
        l_tmp = (l_tmp << 64) + (uint128_t)c_pow10[i].u64[1] * l_digit;
        SUM_128_128(l_ret, l_tmp, &l_ret);
        if (l_ret == l_nul)
            return l_nul;
#else
        uint128_t l_tmp;
        l_tmp.hi = 0;
        l_tmp.lo = (uint64_t)c_pow10[i].u32[2] * (uint64_t)l_digit;
        SUM_128_128(l_ret, l_tmp, &l_ret);
        if (l_ret.hi == 0 && l_ret.lo == 0)
            return l_nul;
        uint64_t l_mul = (uint64_t)c_pow10[i].u32[3] * (uint64_t)l_digit;
        l_tmp.lo = l_mul << 32;
        l_tmp.hi = l_mul >> 32;
        SUM_128_128(l_ret, l_tmp, &l_ret);
        if (l_ret.hi == 0 && l_ret.lo == 0)
            return l_nul;
        l_tmp.lo = 0;
        l_tmp.hi = (uint64_t)c_pow10[i].u32[0] * (uint64_t)l_digit;
        SUM_128_128(l_ret, l_tmp, &l_ret);
        if (l_ret.hi == 0 && l_ret.lo == 0)
            return l_nul;
        l_mul = (uint64_t)c_pow10[i].u32[1] * (uint64_t)l_digit;
        if (l_mul >> 32) {
            log_it(L_WARNING, "Input number is too big");
            return l_nul;
        }
        l_tmp.hi = l_mul << 32;
        SUM_128_128(l_ret, l_tmp, &l_ret);
        if (l_ret.hi == 0 && l_ret.lo == 0)
            return l_nul;
#endif
    }
    return l_ret;
}

uint128_t dap_chain_coins_to_balance128(const char *a_coins)
{
    char l_buf [DATOSHI_POW + 2] = {0};
    uint128_t l_ret = uint128_0, l_nul = uint128_0;

    if (strlen(a_coins) > DATOSHI_POW + 1) {
        log_it(L_WARNING, "Incorrect balance format - too long");
        return l_nul;
    }

    strcpy(l_buf, a_coins);
    char *l_point = strchr(l_buf, '.');
    int l_tail = 0;
    int l_pos = strlen(l_buf);
    if (l_point) {
        l_tail = l_pos - 1 - (l_point - l_buf);
        l_pos = l_point - l_buf;
        if (l_tail > DATOSHI_DEGREE) {
            log_it(L_WARNING, "Incorrect balance format - too much precision");
            return l_nul;
        }
        while (l_buf[l_pos]) {
            l_buf[l_pos] = l_buf[l_pos + 1];
            l_pos++;
        }
        l_pos--;
    }
    if (l_pos + DATOSHI_DEGREE - l_tail > DATOSHI_POW) {
        log_it(L_WARNING, "Incorrect balance format - too long with point");
        return l_nul;
    }
    int i;
    for (i = 0; i < DATOSHI_DEGREE - l_tail; i++) {
        l_buf[l_pos + i] = '0';
    }
    l_buf[l_pos + i] = '\0';
    l_ret = dap_chain_balance_scan128(l_buf);

    return l_ret;
}

//#define __NEW_STARLET__ "BMF"
#ifdef  __NEW_STARLET__


char *dap_chain_balance_print333(uint256_t a_balance)
{
    int     l_pos, l_len, l_len_hi, l_len_lo;
    char    *l_buf, *l_cp, *l_cp2,  *l_cps, *l_cpe, l_chr;
    static const   char l_zero[sizeof(uint256_t)] = {0};
    uint64_t t, q;
    uint32_t l_tmp[4];

    l_len = (DAP_CHAIN$SZ_MAX256DEC + 8) & (~7);                            /* Align size of the buffer to 8 bytes */

    if ( !(l_buf = DAP_NEW_Z_SIZE(char, l_len)) )
        return  log_it(L_ERROR, "Cannot allocate %d octets, errno=%d", l_len, errno), NULL;

    l_cp = l_buf;

    if ( memcmp(&a_balance.hi, &l_zero, sizeof(uint128_t)) )
    {
        l_tmp [0] = a_balance.__hi.a;
        l_tmp [1] = a_balance.__hi.b;
        l_tmp [2] = a_balance.__hi.c;
        l_tmp [3] = a_balance.__hi.d;

        l_len_hi = 0;
        l_cps = l_cp;

        do {
            q = 0;
            // Byte order is 1, 0, 3, 2 for little endian
            for (int i = 1; i <= 3; )
            {
                t = q << 32 | l_tmp[i];
                q = t % 10;
                l_tmp[i] = t / 10;

                if (i == 2) i = 4; // end of cycle
                if (i == 3) i = 2;
                if (i == 0) i = 3;
                if (i == 1) i = 0;
            }

            *(l_cp++) = q + '0';
            l_len_hi++;

        } while (l_tmp[2]);

        l_pos = l_len_hi / 2;                                                   /* A number of swaps */
        l_cpe = l_cp - 1;                                                       /* -- // -- to tail of the string */

        for (int i = l_pos; i--; l_cps++, l_cpe--)                              /* Do swaps ... */
        {
            l_chr = *l_cps;
            *l_cps = *l_cpe;
            *l_cpe = l_chr;
        }
    }

    l_tmp [0] = a_balance.__lo.a;
    l_tmp [1] = a_balance.__lo.b;
    l_tmp [2] = a_balance.__lo.c;
    l_tmp [3] = a_balance.__lo.d;

    l_len_lo = 0;
    l_cps = l_cp2 = l_cp;

    do {
        q = 0;
        // Byte order is 1, 0, 3, 2 for little endian
        for (int i = 1; i <= 3; )
        {
            t = q << 32 | l_tmp[i];
            q = t % 10;
            l_tmp[i] = t / 10;

            if (i == 2) i = 4; // end of cycle
            if (i == 3) i = 2;
            if (i == 0) i = 3;
            if (i == 1) i = 0;
        }

        *(l_cp2++) = q + '0';
        l_len_lo++;

    } while (l_tmp[2]);


    l_pos = l_len_lo / 2;                                                   /* A number of swaps */
    l_cpe = l_cp2 - 1;                                                      /* -- // -- to tail of the string */

    for (int i = l_pos; i--; l_cps++, l_cpe--)                              /* Do swaps ... */
    {
        l_chr = *l_cps;
        *l_cps = *l_cpe;
        *l_cpe = l_chr;
    }

    if (  l_len_hi && (DAP_CHAIN$SZ_MAX128DEC > l_len_lo) )                    /* Do we need to add leading zeroes ? */
    {
        /* "123456" -> 123000...000456" */
        memmove(l_cp2 + ( DAP_CHAIN$SZ_MAX128DEC - l_len), l_cp2, l_len_lo);
        memset(l_cp2, '0', ( DAP_CHAIN$SZ_MAX128DEC - l_len_lo));
    }

    return  l_buf;
}





void    uint256_cvt_test (void)
{
    extern char *dap_cvt_uint256_to_str(uint256_t a_uint256);
    extern uint256_t dap_cvt_str_to_uint256(const char *a_256bit_num);
    extern char *dap_chain_balance_to_coins256(uint256_t a_balance);
    extern  char *dap_chain_balance_print333(uint256_t a_balance);

    char *cp;
    uint128_t uint128 = dap_chain_uint128_from(-1);
    uint256_t uint256;
    uint256.hi = dap_chain_uint128_from(123);
    uint256.lo = dap_chain_uint128_from(374607431768211455);
    const   uint256_t uint256_zero = {0};

    uint256 = uint256_zero;
    uint256.__lo.c = 1;

    cp = dap_chain_balance_print(uint256);
    DAP_DELETE(cp);

    uint256 = uint256_zero;
    uint256.__lo.c = 1;
    cp = dap_chain_balance_to_coins(uint256);
    uint256 = dap_chain_coins_to_balance(cp);
    DAP_DELETE(cp);

    uint256 = uint256_zero;
    uint256.__lo.c = 100000000;
    cp = dap_chain_balance_to_coins(uint256);
    uint256 = dap_chain_coins_to_balance(cp);
    DAP_DELETE(cp);




    cp = dap_chain_balance_print333(uint256);
    DAP_DELETE(cp);



    uint256.hi = dap_chain_uint128_from(-1);
    uint256.lo = dap_chain_uint128_from(-1);
    cp = dap_chain_balance_print333(uint256);
    DAP_DELETE(cp);

    cp = dap_chain_balance_print(uint256);
    DAP_DELETE(cp);

    cp = dap_cvt_uint256_to_str(uint256 );
    uint256 = dap_cvt_str_to_uint256(cp);
    DAP_DELETE(cp);

    uint256.hi = dap_chain_uint128_from(-1);
    uint256.lo = dap_chain_uint128_from(-1);
    cp = dap_cvt_uint256_to_str(uint256 );
    DAP_DELETE(cp);

    uint256.hi = dap_chain_uint128_from(123);
    uint256.lo = dap_chain_uint128_from(374607431768211455);

    cp = dap_chain_balance_to_coins256(uint256);
    uint256 = dap_chain_coins_to_balance(cp);
    DAP_DELETE(cp);
}
#endif
