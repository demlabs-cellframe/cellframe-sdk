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

/*
 * Forward declarations
 */
#define DAP_CHAIN$SZ_MAX128DEC DATOSHI_POW                                           /* "340282366920938463463374607431768211455" */
#define DAP_CHAIN$SZ_MAX256DEC DATOSHI_POW256                                       /* 2 ^ 256 = 1.15792089237316195423570985008687907853269984665640564039457584007913129639935e77*/
#define DAP_SZ_MAX256SCINOT (DATOSHI_POW256 + 5)

char        *dap_cvt_uint256_to_str (uint256_t a_uint256);
uint256_t   dap_cvt_str_to_uint256 (const char *a_256bit_num);

json_object* dap_chain_receipt_info_to_json(dap_chain_receipt_info_t *a_info){
    json_object *l_obj = json_object_new_object();
    json_object *l_obj_srv_uid = json_object_new_uint64(a_info->srv_uid.uint64);
    json_object_object_add(l_obj, "srvUID", l_obj_srv_uid);
#if DAP_CHAIN_NET_SRV_UID_SIZE == 8
    json_object *l_obj_addition = json_object_new_uint64(a_info->addition);
    json_object_object_add(l_obj, "addition", l_obj_addition);
#endif
    json_object *l_obj_units_type = json_object_new_string(serv_unit_enum_to_str(&a_info->units_type.enm));
    json_object_object_add(l_obj, "unitsType", l_obj_units_type);
    char *l_datoshi_value = dap_chain_balance_print(a_info->value_datoshi);
    json_object *l_obj_datoshi = json_object_new_string(l_datoshi_value);
    DAP_DELETE(l_datoshi_value);
    json_object_object_add(l_obj, "value", l_obj_datoshi);
    return l_obj;
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
    dap_snprintf(a_str, 3, "0x");

    for(i = 0; i < sizeof(a_hash->raw); ++i)
        dap_snprintf( a_str + i * 2 + 2, 3, "%02x", a_hash->raw[i] );

    a_str[c_hash_str_size] = '\0';

    return strlen(a_str);
}

/**
 * @brief dap_chain_addr_to_str
 * @param a_addr
 * @return
 */
char* dap_chain_addr_to_str(const dap_chain_addr_t *a_addr)
{
    if ( a_addr ==NULL)
        return  NULL;

    if (dap_chain_addr_is_blank(a_addr)) return dap_strdup("null");

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
 * @brief dap_chain_addr_to_json
 * @param a_addr
 * @return
 */
json_object *dap_chain_addr_to_json(const dap_chain_addr_t *a_addr){
    char *l_addr_str = dap_chain_addr_to_str(a_addr);
    json_object *l_obj = json_object_new_string(l_addr_str);
    DAP_DELETE(l_addr_str);
    return l_obj;
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
    if (dap_strcmp(a_str, "null") == 0) {
        return DAP_NEW_Z(dap_chain_addr_t);
    }
    size_t l_ret_size = DAP_ENC_BASE58_DECODE_SIZE(l_str_len);
    dap_chain_addr_t * l_addr = DAP_NEW_Z_SIZE(dap_chain_addr_t, l_ret_size);
    if(dap_enc_base58_decode(a_str, l_addr) == sizeof(dap_chain_addr_t) &&
       dap_chain_addr_check_sum(l_addr)==1)
        return l_addr;
    else
        DAP_DELETE(l_addr);
    return NULL;
}

bool dap_chain_addr_is_blank(const dap_chain_addr_t *a_addr){
    dap_chain_addr_t l_addr_blank = {0};
    return !memcmp(a_addr, &l_addr_blank, sizeof(dap_chain_addr_t));
}

#if 0
/**
 * @brief dap_chain_net_id_from_str
 * @param a_net_str
 * @return
 */
dap_chain_net_id_t dap_chain_net_id_from_str(const char * a_net_str)
{
    dap_chain_net_id_t l_ret={ 0 };
    log_it(L_DEBUG, "net id: %s", a_net_str);

    if (!(l_ret.uint64 = strtoll(a_net_str, NULL, 0))) {
        log_it(L_ERROR, "Wrong input string \"%s\" not recognized as network id", a_net_str);
        return l_ret;
    }
    return l_ret;
}
#endif

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
void dap_chain_addr_fill_from_key(dap_chain_addr_t *a_addr, dap_enc_key_t *a_key, dap_chain_net_id_t a_net_id) {
    dap_sign_type_t l_type = dap_sign_type_from_key_type(a_key->type);
    size_t l_pub_key_data_size;
    uint8_t *l_pub_key_data = dap_enc_key_serialize_pub_key(a_key, &l_pub_key_data_size);
    if (!l_pub_key_data) {
        log_it(L_ERROR,"Can't fill address from key, its empty");
        return;
    }
    dap_chain_hash_fast_t l_hash_public_key;
    // serialized key -> key hash
    dap_hash_fast(l_pub_key_data, l_pub_key_data_size, &l_hash_public_key);
    dap_chain_addr_fill(a_addr, l_type, &l_hash_public_key, a_net_id);
    DAP_DELETE(l_pub_key_data);
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
 * @return 1 Ok, -1 Invalid a_addr or checksum
 */
int dap_chain_addr_check_sum(const dap_chain_addr_t *a_addr)
{
    if(!a_addr)
        return -1;
    if (dap_chain_addr_is_blank(a_addr)) return 1;
    dap_chain_hash_fast_t l_checksum;
    // calc checksum
    dap_hash_fast(a_addr, sizeof(dap_chain_addr_t) - sizeof(dap_chain_hash_fast_t), &l_checksum);
    if(!memcmp(a_addr->checksum.raw, l_checksum.raw, sizeof(l_checksum.raw)))
        return 1;
    return -1;
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

char *dap_chain_balance_print(uint256_t a_balance)
{
    return  dap_cvt_uint256_to_str(a_balance);   /* @RRL */
    //return  dap_chain_balance_print128(a_balance.lo);
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



char *dap_chain_balance_to_coins256(uint256_t a_balance)
{
    char *l_buf, *l_cp;
    int l_strlen, l_len;

    /* 123000...456 -> "123000...456" */
    if ( !(l_buf = dap_cvt_uint256_to_str(a_balance)) )
        return NULL;

    l_strlen = strlen(l_buf);

    if ( 0 < (l_len = (l_strlen - DATOSHI_DEGREE)) )
    {
        l_cp = l_buf + l_len;                                               /* Move last 18 symbols to one position right */
        memmove(l_cp + 1, l_cp, DATOSHI_DEGREE);
        *l_cp = '.';                                                        /* Insert '.' separator */

        l_strlen++;                                                         /* Adjust string len in the buffer */
    } else {
        l_len = DATOSHI_DEGREE - l_strlen;                           /* Add leading "0." */
        l_cp = l_buf;
        memmove(l_cp + l_len + 2, l_cp, DATOSHI_DEGREE - l_len);                                     /* Move last 18 symbols to 2 positions right */
        memset(l_cp, '0', l_len + 2);
        *(++l_cp) = '.';
        l_strlen += 2;                                                      /* Adjust string len in the buffer */
    }

    if ( *(l_cp = l_buf) == '0' )                                           /* Is there lead zeroes ? */
    {
        /* 000000000000000000000.000000000000000001 */
        /* 000000000000000000123.000000000000000001 */
        for ( l_cp += 1; *l_cp == '0'; l_cp++);                             /* Skip all '0' symbols */

        if ( *l_cp == '.' )                                                 /* l_cp point to separator - then step back */
            l_cp--;

        if ( (l_len = (l_cp - l_buf)) )
        {
            l_len = l_strlen - l_len;                                       /* A part of the buffer to be moved to begin */
            memmove(l_buf, l_cp, l_len);                                    /* Move and terminated by zero */
            l_buf[l_len] = '\0';
        }

        l_strlen = l_len;                                                   /* Adjust string len in the buffer */
    }

    for ( l_cp = l_buf + strlen(l_buf) - 1; *l_cp == '0' && l_cp >= l_buf; l_cp--)
        if (*(l_cp - 1) != '.')
            *l_cp = '\0';

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

uint256_t dap_chain_balance_scan(const char *a_balance)
{
    return dap_cvt_str_to_uint256 (a_balance);                              /* @RRL */
    //return GET_256_FROM_128(dap_chain_balance_scan128(a_balance));

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
    if (l_pos + DATOSHI_DEGREE - l_tail > DATOSHI_POW-1) {
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





/*
 *   DESCRIPTION: Convert a text representation of the coins amount in to
 *   the binary uint256 value .
 *      Coins string can be in form:
 *          - "123.00456"
 *          -
 *   INPUTS:
 *      a_coins:    A text string in format
 *
 *   OUTPUTS:
 *      NONE
 *
 *   RETURNS:
 *      A converted value
 */

uint256_t dap_chain_coins_to_balance256(const char *a_coins)
{
    int l_len, l_pos;
    char    l_buf  [DAP_CHAIN$SZ_MAX256DEC + 8] = {0}, *l_point;
    uint256_t l_nul = {0};

    /* "12300000000.0000456" */
    if ( (l_len = strnlen(a_coins, DATOSHI_POW256 + 2)) > DATOSHI_POW256 + 1)/* Check for legal length */ /* 1 symbol for \0, one for '.', if more, there is an error */
        return  log_it(L_WARNING, "Incorrect balance format of '%s' - too long (%d > %d)", a_coins,
                       l_len, DATOSHI_POW256 + 1), l_nul;

    /* Find , check and remove 'precision' dot symbol */
    memcpy (l_buf, a_coins, l_len);                                         /* Make local copy */
    if ( !(l_point = memchr(l_buf, '.', l_len)) )                           /* Is there 'dot' ? */
        return  log_it(L_WARNING, "Incorrect balance format of '%s' - no precision mark", a_coins),
                l_nul;

    l_pos = l_len - (l_point - l_buf);                                      /* Check number of decimals after dot */
    l_pos--;
    if ( (l_pos ) >  DATOSHI_DEGREE )
        return  log_it(L_WARNING, "Incorrect balance format of '%s' - too much precision", l_buf), l_nul;

    /* "123.456" -> "123456" */
    memmove(l_point, l_point + 1, l_pos);                                   /* Shift left a right part of the decimal string
                                                                              to dot symbol place */
    *(l_point + l_pos) = '\0';

    /* Add trailer zeros:
     *                pos
     *                 |
     * 123456 -> 12345600...000
     *           ^            ^
     *           |            |
     *           +-18 digits--+
     */
    memset(l_point + l_pos, '0', DATOSHI_DEGREE - l_pos);

    return dap_cvt_str_to_uint256 (l_buf);
}



char *dap_cvt_uint256_to_str(uint256_t a_uint256) {
    char *l_buf = DAP_NEW_Z_SIZE(char, DATOSHI_POW256 + 2); // for decimal dot and trailing zero
#ifdef DAP_GLOBAL_IS_INT128
    int l_pos = 0;
    uint256_t l_value = a_uint256;
    uint256_t uint256_ten = GET_256_FROM_64(10);
    uint256_t rem;
    do {
        divmod_impl_256(l_value, uint256_ten, &l_value, &rem);
        l_buf[l_pos++] = rem.lo + '0';
    } while (!IS_ZERO_256(l_value));
#else
    int l_pos = 0;
    uint256_t l_value = a_uint256;
    uint256_t uint256_ten = GET_256_FROM_64(10);
    uint256_t rem;
    do {
        divmod_impl_256(l_value, uint256_ten, &l_value, &rem);
        l_buf[l_pos++] = rem.lo.lo + (unsigned long long) '0';
    } while (!IS_ZERO_256(l_value));
#endif
    int l_strlen = strlen(l_buf) - 1;
    for (int i = 0; i < (l_strlen + 1) / 2; i++) {
        char c = l_buf[i];
        l_buf[i] = l_buf[l_strlen - i];
        l_buf[l_strlen - i] = c;
    }
    return l_buf;
}


const union __c_pow10_double__ {
    uint64_t u64[4];
    uint32_t u32[8];
} DAP_ALIGN_PACKED c_pow10_double[DATOSHI_POW256] = {
#ifdef DAP_GLOBAL_IS_INT128
        { .u64 = {0,                            0,                           0,                         1ULL} },                          // 0
        { .u64 = {0,                            0,                           0,                         10ULL} },                         // 1
        { .u64 = {0,                            0,                           0,                         100ULL} },                        // 2
        { .u64 = {0,                            0,                           0,                         1000ULL} },                       // 3
        { .u64 = {0,                            0,                           0,                         10000ULL} },                      // 4
        { .u64 = {0,                            0,                           0,                         100000ULL} },                     // 5
        { .u64 = {0,                            0,                           0,                         1000000ULL} },                    // 6
        { .u64 = {0,                            0,                           0,                         10000000ULL} },                   // 7
        { .u64 = {0,                            0,                           0,                         100000000ULL} },                  // 8
        { .u64 = {0,                            0,                           0,                         1000000000ULL} },                 // 9
        { .u64 = {0,                            0,                           0,                         10000000000ULL} },                // 10
        { .u64 = {0,                            0,                           0,                         100000000000ULL} },               // 11
        { .u64 = {0,                            0,                           0,                         1000000000000ULL} },              // 12
        { .u64 = {0,                            0,                           0,                         10000000000000ULL} },             // 13
        { .u64 = {0,                            0,                           0,                         100000000000000ULL} },            // 14
        { .u64 = {0,                            0,                           0,                         1000000000000000ULL} },           // 15
        { .u64 = {0,                            0,                           0,                         10000000000000000ULL} },          // 16
        { .u64 = {0,                            0,                           0,                         100000000000000000ULL} },         // 17
        { .u64 = {0,                            0,                           0,                         1000000000000000000ULL} },        // 18
        { .u64 = {0,                            0,                           0,                         10000000000000000000ULL} },       // 19
        { .u64 = {0,                            0,                           5ULL,                      7766279631452241920ULL} },        // 20
        { .u64 = {0,                            0,                           54ULL,                     3875820019684212736ULL} },        // 21
        { .u64 = {0,                            0,                           542ULL,                    1864712049423024128ULL} },        // 22
        { .u64 = {0,                            0,                           5421ULL,                   200376420520689664ULL} },         // 23
        { .u64 = {0,                            0,                           54210ULL,                  2003764205206896640ULL} },        // 24
        { .u64 = {0,                            0,                           542101ULL,                 1590897978359414784ULL} },        // 25
        { .u64 = {0,                            0,                           5421010ULL,                15908979783594147840ULL} },       // 26
        { .u64 = {0,                            0,                           54210108ULL,               11515845246265065472ULL} },       // 27
        { .u64 = {0,                            0,                           542101086ULL,              4477988020393345024ULL} },        // 28
        { .u64 = {0,                            0,                           5421010862ULL,             7886392056514347008ULL} },        // 29
        { .u64 = {0,                            0,                           54210108624ULL,            5076944270305263616ULL} },        // 30
        { .u64 = {0,                            0,                           542101086242ULL,           13875954555633532928ULL} },       // 31
        { .u64 = {0,                            0,                           5421010862427ULL,          9632337040368467968ULL} },        // 32
        { .u64 = {0,                            0,                           54210108624275ULL,         4089650035136921600ULL} },        // 33
        { .u64 = {0,                            0,                           542101086242752ULL,        4003012203950112768ULL} },        // 34
        { .u64 = {0,                            0,                           5421010862427522ULL,       3136633892082024448ULL} },        // 35
        { .u64 = {0,                            0,                           54210108624275221ULL,      12919594847110692864ULL} },       // 36
        { .u64 = {0,                            0,                           542101086242752217ULL,     68739955140067328ULL} },          // 37
        { .u64 = {0,                            0,                           5421010862427522170ULL,    687399551400673280ULL} },         // 38
        { .u64 = {0,                            2ULL,                        17316620476856118468ULL,   6873995514006732800ULL} },        // 39
        { .u64 = {0,                            29ULL,                       7145508105175220139ULL,    13399722918938673152ULL} },       // 40
        { .u64 = {0,                            293ULL,                      16114848830623546549ULL,   4870020673419870208ULL} },        // 41
        { .u64 = {0,                            2938ULL,                     13574535716559052564ULL,   11806718586779598848ULL} },       // 42
        { .u64 = {0,                            29387ULL,                    6618148649623664334ULL,    7386721425538678784ULL} },        // 43
        { .u64 = {0,                            293873ULL,                   10841254275107988496ULL,   80237960548581376ULL} },          // 44
        { .u64 = {0,                            2938735ULL,                  16178822382532126880ULL,   802379605485813760ULL} },          // 45
        { .u64 = {0,                            29387358ULL,                 14214271235644855872ULL,   8023796054858137600ULL} },          // 46
        { .u64 = {0,                            293873587ULL,                13015503840481697412ULL,   6450984253743169536ULL} },          // 47
        { .u64 = {0,                            2938735877ULL,               1027829888850112811ULL,    9169610316303040512ULL} },          // 48
        { .u64 = {0,                            29387358770ULL,              10278298888501128114ULL,   17909126868192198656ULL} },          // 49
        { .u64 = {0,                            293873587705ULL,             10549268516463523069ULL,   13070572018536022016ULL} },          // 50
        { .u64 = {0,                            2938735877055ULL,            13258964796087472617ULL,   1578511669393358848ULL} },          // 51
        { .u64 = {0,                            29387358770557ULL,           3462439444907864858ULL,    15785116693933588480ULL} },          // 52
        { .u64 = {0,                            293873587705571ULL,          16177650375369096972ULL,   10277214349659471872ULL} },          // 53
        { .u64 = {0,                            2938735877055718ULL,         14202551164014556797ULL,   10538423128046960640ULL} },          // 54
        { .u64 = {0,                            29387358770557187ULL,        12898303124178706663ULL,   13150510911921848320ULL} },          // 55
        { .u64 = {0,                            293873587705571876ULL,       18302566799529756941ULL,   2377900603251621888ULL} },          // 56
        { .u64 = {0,                            2938735877055718769ULL,      17004971331911604867ULL,   5332261958806667264ULL} },          // 57
        { .u64 = {1,                            10940614696847636083ULL,     4029016655730084128ULL,    16429131440647569408ULL} },          // 58
        { .u64 = {15ULL,                        17172426599928602752ULL,     3396678409881738056ULL,    16717361816799281152ULL} },          // 59
        { .u64 = {159ULL,                       5703569335900062977ULL,      15520040025107828953ULL,   1152921504606846976ULL} },          // 60
        { .u64 = {1593ULL,                      1695461137871974930ULL,      7626447661401876602ULL,    11529215046068469760ULL} },          // 61
        { .u64 = {15930ULL,                     16954611378719749304ULL,     2477500319180559562ULL,    4611686018427387904ULL} },          // 62
        { .u64 = {159309ULL,                    3525417123811528497ULL,      6328259118096044006ULL,    9223372036854775808ULL} },          // 63
        { .u64 = {1593091ULL,                   16807427164405733357ULL,     7942358959831785217ULL,    0ULL} },                            // 64
        { .u64 = {15930919ULL,                  2053574980671369030ULL,      5636613303479645706ULL,    0ULL} },                            // 65
        { .u64 = {159309191ULL,                 2089005733004138687ULL,      1025900813667802212ULL,    0ULL} },                            // 66
        { .u64 = {1593091911ULL,                2443313256331835254ULL,      10259008136678022120ULL,   0ULL} },                            // 67
        { .u64 = {15930919111ULL,               5986388489608800929ULL,      10356360998232463120ULL,   0ULL} },                            // 68
        { .u64 = {159309191113ULL,              4523652674959354447ULL,      11329889613776873120ULL,   0ULL} },                            // 69
        { .u64 = {1593091911132ULL,             8343038602174441244ULL,      2618431695511421504ULL,    0ULL} },                            // 70
        { .u64 = {15930919111324ULL,            9643409726906205977ULL,      7737572881404663424ULL,    0ULL} },                            // 71
        { .u64 = {159309191113245ULL,           4200376900514301694ULL,      3588752519208427776ULL,    0ULL} },                            // 72
        { .u64 = {1593091911132452ULL,          5110280857723913709ULL,      17440781118374726144ULL,   0ULL} },                            // 73
        { .u64 = {15930919111324522ULL,         14209320429820033867ULL,     8387114520361296896ULL,    0ULL} },                            // 74
        { .u64 = {159309191113245227ULL,        12965995782233477362ULL,     10084168908774762496ULL,   0ULL} },                            // 75
        { .u64 = {1593091911132452277ULL,       532749306367912313ULL,       8607968719199866880ULL,    0ULL} },                            // 76
        { .u64 = {15930919111324522770ULL,       5327493063679123134ULL,       12292710897160462336ULL,    0ULL} },                         // 77
#else
        { .u32 = {0, 0, 0, 0, 0, 0, 0, 1, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 0, 10, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 0, 100, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 0, 1000, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 0, 10000, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 0, 100000, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 0, 1000000, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 0, 10000000, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 0, 100000000, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 0, 1000000000, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 2, 1410065408, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 23, 1215752192, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 232, 3567587328, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 2328, 1316134912, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 23283, 276447232, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 232830, 2764472320, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 2328306, 1874919424, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 23283064, 1569325056, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 232830643, 2808348672, } },
        { .u32 = {0, 0, 0, 0, 0, 0, 2328306436, 2313682944, } },
        { .u32 = {0, 0, 0, 0, 0, 5, 1808227885, 1661992960, } },
        { .u32 = {0, 0, 0, 0, 0, 54, 902409669, 3735027712, } },
        { .u32 = {0, 0, 0, 0, 0, 542, 434162106, 2990538752, } },
        { .u32 = {0, 0, 0, 0, 0, 5421, 46653770, 4135583744, } },
        { .u32 = {0, 0, 0, 0, 0, 54210, 466537709, 2701131776, } },
        { .u32 = {0, 0, 0, 0, 0, 542101, 370409800, 1241513984, } },
        { .u32 = {0, 0, 0, 0, 0, 5421010, 3704098002, 3825205248, } },
        { .u32 = {0, 0, 0, 0, 0, 54210108, 2681241660, 3892314112, } },
        { .u32 = {0, 0, 0, 0, 0, 542101086, 1042612833, 268435456, } },
        { .u32 = {0, 0, 0, 0, 1, 1126043566, 1836193738, 2684354560, } },
        { .u32 = {0, 0, 0, 0, 12, 2670501072, 1182068202, 1073741824, } },
        { .u32 = {0, 0, 0, 0, 126, 935206946, 3230747430, 2147483648, } },
        { .u32 = {0, 0, 0, 0, 1262, 762134875, 2242703233, 0, } },
        { .u32 = {0, 0, 0, 0, 12621, 3326381459, 952195850, 0, } },
        { .u32 = {0, 0, 0, 0, 126217, 3199043520, 932023908, 0, } },
        { .u32 = {0, 0, 0, 0, 1262177, 1925664130, 730304488, 0, } },
        { .u32 = {0, 0, 0, 0, 12621774, 2076772117, 3008077584, 0, } },
        { .u32 = {0, 0, 0, 0, 126217744, 3587851993, 16004768, 0, } },
        { .u32 = {0, 0, 0, 0, 1262177448, 1518781562, 160047680, 0, } },
        { .u32 = {0, 0, 0, 2, 4031839891, 2302913732, 1600476800, 0, } },
        { .u32 = {0, 0, 0, 29, 1663693251, 1554300843, 3119866112, 0, } },
        { .u32 = {0, 0, 0, 293, 3752030625, 2658106549, 1133890048, 0, } },
        { .u32 = {0, 0, 0, 2938, 3160567888, 811261716, 2748965888, 0, } },
        { .u32 = {0, 0, 0, 29387, 1540907809, 3817649870, 1719855104, 0, } },
        { .u32 = {0, 0, 0, 293873, 2524176210, 3816760336, 18681856, 0, } },
        { .u32 = {0, 0, 0, 2938735, 3766925628, 3807864992, 186818560, 0, } },
        { .u32 = {0, 0, 0, 29387358, 3309517920, 3718911552, 1868185600, 0, } },
        { .u32 = {0, 0, 0, 293873587, 3030408136, 2829377156, 1501986816, 0, } },
        { .u32 = {0, 0, 0, 2938735877, 239310294, 2523967787, 2134966272, 0, } },
        { .u32 = {0, 0, 6, 3617554994, 2393102945, 3764841394, 4169793536, 0, } },
        { .u32 = {0, 0, 68, 1815811577, 2456192978, 3288675581, 3043229696, 0, } },
        { .u32 = {0, 0, 684, 978246591, 3087093307, 2821984745, 367525888, 0, } },
        { .u32 = {0, 0, 6842, 1192531325, 806162004, 2450043674, 3675258880, 0, } },
        { .u32 = {0, 0, 68422, 3335378659, 3766652749, 3025600268, 2392850432, 0, } },
        { .u32 = {0, 0, 684227, 3289015526, 3306789129, 191231613, 2453667840, 0, } },
        { .u32 = {0, 0, 6842277, 2825384195, 3003120218, 1912316135, 3061841920, 0, } },
        { .u32 = {0, 0, 68422776, 2484038180, 4261398408, 1943292173, 553648128, 0, } },
        { .u32 = {0, 0, 684227765, 3365545329, 3959278420, 2253052547, 1241513984, 0, } },
        { .u32 = {0, 1, 2547310361, 3590682227, 938078541, 1055688992, 3825205248, 0, } },
        { .u32 = {0, 15, 3998267138, 1547083904, 790850820, 1966955336, 3892314112, 0, } },
        { .u32 = {0, 159, 1327965719, 2585937153, 3613540908, 2489684185, 268435456, 0, } },
        { .u32 = {0, 1593, 394755308, 89567762, 1775670717, 3422005370, 2684354560, 0, } },
        { .u32 = {0, 15930, 3947553080, 895677624, 576837993, 4155282634, 1073741824, 0, } },
        { .u32 = {0, 159309, 820825138, 366841649, 1473412643, 2898120678, 2147483648, 0, } },
        { .u32 = {0, 1593091, 3913284084, 3668416493, 1849224548, 3211403009, 0, 0, } },
        { .u32 = {0, 15930919, 478135184, 2324426566, 1312376303, 2049259018, 0, 0, } },
        { .u32 = {0, 159309191, 486384549, 1769429183, 238861146, 3312720996, 0, 0, } },
        { .u32 = {0, 1593091911, 568878198, 514422646, 2388611467, 3062438888, 0, 0, } },
        { .u32 = {3, 3046017223, 1393814685, 849259169, 2411278197, 559617808, 0, 0, } },
        { .u32 = {37, 395401161, 1053244963, 4197624399, 2637945491, 1301210784, 0, 0, } },
        { .u32 = {370, 3954011612, 1942515047, 3321538332, 609651137, 127205952, 0, 0, } },
        { .u32 = {3709, 885410460, 2245281293, 3150612249, 1801544074, 1272059520, 0, 0, } },
        { .u32 = {37092, 264170013, 977976457, 1441351422, 835571558, 4130660608, 0, 0, } },
        { .u32 = {370920, 2641700132, 1189829981, 1528612333, 4060748293, 2651900416, 0, 0, } },
        { .u32 = {3709206, 647197546, 3308365221, 2401221451, 1952777272, 749200384, 0, 0, } },
        { .u32 = {37092061, 2177008171, 3018881143, 2537378034, 2347903537, 3197036544, 0, 0, } },
        { .u32 = {370920615, 295245237, 124040363, 3898943865, 2004198897, 1905594368, 0, 0, } },
        { .u32 = {3709206150, 2952452370, 1240403639, 334732990, 2862119790, 1876074496, 0, 0, } },
#endif
};


/*
 *   DESCRIPTION: Convert decimal text string into the uint256_t binary representative.
 *      We calling twice 128 bit variant of convertors
 *
 *   INPUTS:
 *      a_256bit_num:   Decimal string to be converted
 *
 *   OUTPUTS:
 *      NONE
 *
 *   RETURNS:
 *      256 bit value
 *      0 - on coversion error
 */

uint256_t dap_cvt_str_to_uint256(const char *a_256bit_num)
{
    uint256_t l_ret = uint256_0, l_nul = uint256_0;
    int  l_strlen;
    char l_256bit_num[DAP_CHAIN$SZ_MAX256DEC + 1];
    int overflow_flag = 0;

    if (!a_256bit_num) {
        return log_it(L_ERROR, "NULL as an argument"), l_nul;
    }

    /* Convert number from xxx.yyyyE+zz to xxxyyyy0000... */
    char *l_eptr = strchr(a_256bit_num, 'e');
    if (!l_eptr)
        l_eptr = strchr(a_256bit_num, 'E');
    if (l_eptr) {
        /* Compute & check length */
        if ( (l_strlen = strnlen(a_256bit_num, DAP_SZ_MAX256SCINOT + 1) ) > DAP_SZ_MAX256SCINOT)
            return  log_it(L_ERROR, "Too many digits in `%s` (%d > %d)", a_256bit_num, l_strlen, DAP_SZ_MAX256SCINOT), l_nul;
        char *l_exp_ptr = l_eptr + 1;
        if (*l_exp_ptr == '+')
            l_exp_ptr++;
        int l_exp = atoi(l_exp_ptr);
        if (!l_exp)
            return  log_it(L_ERROR, "Invalid exponent %s", l_eptr), uint256_0;
        char *l_dot_ptr = strchr(a_256bit_num, '.');
        if (!l_dot_ptr || l_dot_ptr > l_eptr)
            return  log_it(L_ERROR, "Invalid number format with exponent %d", l_exp), uint256_0;
        int l_dot_len = l_dot_ptr - a_256bit_num;
        if (l_dot_len >= DATOSHI_POW256)
            return log_it(L_ERROR, "Too many digits in '%s'", a_256bit_num), uint256_0;
        int l_exp_len = l_eptr - a_256bit_num - l_dot_len - 1;
        if (l_exp_len + l_dot_len > DATOSHI_POW256)
            return log_it(L_ERROR, "Too many digits in '%s'", a_256bit_num), uint256_0;
        if (l_exp < l_exp_len) {
            //todo: we need to handle numbers like 1.23456789000000e9
            return log_it(L_ERROR, "Invalid number format with exponent %d and number count after dot %d", l_exp,
                          l_exp_len), uint256_0;
        }
        memcpy(l_256bit_num, a_256bit_num, l_dot_len);
        memcpy(l_256bit_num + l_dot_len, a_256bit_num + l_dot_len + 1, l_exp_len);
        int l_zero_cnt = l_exp - l_exp_len;
        if (l_zero_cnt > DATOSHI_POW256) {
            //todo: need to handle leading zeroes, like 0.000...123e100
            return log_it(L_ERROR, "Too long number for 256 bit: `%s` (%d > %d)", a_256bit_num, l_strlen, DAP_CHAIN$SZ_MAX256DEC), l_nul;
        }
        size_t l_pos = l_dot_len + l_exp_len;
        for (int i = l_zero_cnt; i && l_pos < DATOSHI_POW256; i--)
            l_256bit_num[l_pos++] = '0';
        l_256bit_num[l_pos] = '\0';
        l_strlen = l_pos;

    } else {
        //we have a decimal string, not sci notation
        /* Compute & check length */
        if ( (l_strlen = strnlen(a_256bit_num, DATOSHI_POW256 + 1) ) > DATOSHI_POW256)
            return  log_it(L_ERROR, "Too many digits in `%s` (%d > %d)", a_256bit_num, l_strlen, DATOSHI_POW256), l_nul;
        memcpy(l_256bit_num, a_256bit_num, l_strlen);
        l_256bit_num[l_strlen] = '\0';
    }

    for (int i = 0; i < l_strlen ; i++) {
        char c = l_256bit_num[l_strlen - i - 1];
        if (!isdigit(c)) {
            log_it(L_WARNING, "Incorrect input number");
            return l_nul;
        }
        uint8_t l_digit = c - '0';
        if (!l_digit)
            continue;
#ifdef DAP_GLOBAL_IS_INT128
        uint256_t l_tmp;
        l_tmp.hi = 0;
        l_tmp.lo = (uint128_t)c_pow10_double[i].u64[3] * (uint128_t) l_digit;
        overflow_flag = SUM_256_256(l_ret, l_tmp, &l_ret);
        if (overflow_flag) {
            //todo: change string to uint256_max after implementation
            return log_it(L_ERROR, "Too big number '%s', max number is '%s'", a_256bit_num, "115792089237316195423570985008687907853269984665640564039457584007913129639935"), l_nul;
        }
//        if (l_ret.hi == 0 && l_ret.lo == 0) {
//            return l_nul;
//        }
        uint128_t l_mul = (uint128_t) c_pow10_double[i].u64[2] * (uint128_t) l_digit;
        l_tmp.lo = l_mul << 64;
        l_tmp.hi = l_mul >> 64;
        overflow_flag = SUM_256_256(l_ret, l_tmp, &l_ret);
        if (overflow_flag) {
            //todo: change string to uint256_max after implementation
            return log_it(L_ERROR, "Too big number '%s', max number is '%s'", a_256bit_num, "115792089237316195423570985008687907853269984665640564039457584007913129639935"), l_nul;
        }

        if (l_ret.hi == 0 && l_ret.lo == 0) {
            return l_nul;
        }

        l_tmp.lo = 0;
        l_tmp.hi = (uint128_t) c_pow10_double[i].u64[1] * (uint128_t) l_digit;
        overflow_flag = SUM_256_256(l_ret, l_tmp, &l_ret);
        if (overflow_flag) {
            //todo: change string to uint256_max after implementation
            return log_it(L_ERROR, "Too big number '%s', max number is '%s'", a_256bit_num, "115792089237316195423570985008687907853269984665640564039457584007913129639935"), l_nul;
        }
        if (l_ret.hi == 0 && l_ret.lo == 0) {
            return l_nul;
        }

        l_mul = (uint128_t) c_pow10_double[i].u64[0] * (uint128_t) l_digit;
        if (l_mul >> 64) {
            log_it(L_WARNING, "Input number is too big");
            return l_nul;
        }
        l_tmp.hi = l_mul << 64;
        overflow_flag = SUM_256_256(l_ret, l_tmp, &l_ret);
        if (overflow_flag) {
            //todo: change string to uint256_max after implementation
            return log_it(L_ERROR, "Too big number '%s', max number is '%s'", a_256bit_num, "115792089237316195423570985008687907853269984665640564039457584007913129639935"), l_nul;
        }
        if (l_ret.hi == 0 && l_ret.lo == 0) {
            return l_nul;
        }
#else
        uint256_t l_tmp;
        for (int j = 7; j>=0; j--) {
            l_tmp = GET_256_FROM_64((uint64_t) c_pow10_double[i].u32[j]);
            if (IS_ZERO_256(l_tmp)) {
                if (j < 6) { // in table, we have only 7 and 6 position with 0-es but 5..0 non-zeroes, so if we have zero on 5 or less, there is no significant position anymore
                    break;
                }
                else {
                    continue;
                }
            }
            LEFT_SHIFT_256(l_tmp, &l_tmp, 32 * (7-j));
            overflow_flag = MULT_256_256(l_tmp, GET_256_FROM_64(l_digit), &l_tmp);
            if (overflow_flag) {
                //todo: change string to uint256_max after implementation
                return log_it(L_ERROR, "Too big number '%s', max number is '%s'", a_256bit_num, "115792089237316195423570985008687907853269984665640564039457584007913129639935"), l_nul;
            }
            overflow_flag = SUM_256_256(l_ret, l_tmp, &l_ret);
            if (overflow_flag) {
                //todo: change string to uint256_max after implementation
                return log_it(L_ERROR, "Too big number '%s', max number is '%s'", a_256bit_num, "115792089237316195423570985008687907853269984665640564039457584007913129639935"), l_nul;
            }
        }
#endif
    }
    return l_ret;
}


inline uint256_t dap_chain_coins_to_balance(const char *a_coins)
{
    return  dap_chain_coins_to_balance256(a_coins);
    // return GET_256_FROM_128(dap_chain_coins_to_balance128(a_coins));
}



inline char *dap_chain_balance_to_coins(uint256_t a_balance)
{
    return dap_chain_balance_to_coins256(a_balance); /* @RRL */
    //return dap_chain_balance_to_coins128(a_balance.lo);
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
    free(cp);

    uint256 = uint256_zero;
    uint256.__lo.c = 1;
    cp = dap_chain_balance_to_coins(uint256);
    uint256 = dap_chain_coins_to_balance(cp);
    free(cp);

    uint256 = uint256_zero;
    uint256.__lo.c = 100000000;
    cp = dap_chain_balance_to_coins(uint256);
    uint256 = dap_chain_coins_to_balance(cp);
    free(cp);




    cp = dap_chain_balance_print333(uint256);
    free(cp);



    uint256.hi = dap_chain_uint128_from(-1);
    uint256.lo = dap_chain_uint128_from(-1);
    cp = dap_chain_balance_print333(uint256);
    free(cp);

    cp = dap_chain_balance_print(uint256);
    free(cp);

    cp = dap_cvt_uint256_to_str(uint256 );
    uint256 = dap_cvt_str_to_uint256(cp);
    free(cp);

    uint256.hi = dap_chain_uint128_from(-1);
    uint256.lo = dap_chain_uint128_from(-1);
    cp = dap_cvt_uint256_to_str(uint256 );
    free(cp);

    uint256.hi = dap_chain_uint128_from(123);
    uint256.lo = dap_chain_uint128_from(374607431768211455);

    cp = dap_chain_balance_to_coins256(uint256);
    uint256 = dap_chain_coins_to_balance(cp);
    free(cp);
}
#endif
