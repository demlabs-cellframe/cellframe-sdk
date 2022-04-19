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

/*
 * Forward declarations
 */
#define DAP_CHAIN$SZ_MAX128DEC 39                                           /* "340282366920938463463374607431768211455" */
#define DAP_CHAIN$SZ_MAX256DEC (2*39)                                       /* 2 * "340282366920938463463374607431768211455" */

char        *dap_cvt_uint256_to_str (uint256_t a_uint256);
uint256_t   dap_cvt_str_to_uint256 (const char *a_256bit_num);

dap_chain_time_t dap_chain_time_now()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    dap_chain_time_t ret = ts.tv_sec << 32 | ts.tv_nsec;
    return ret;
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
dap_chain_net_id_t dap_chain_net_id_from_str(const char * a_net_str)
{
    dap_chain_net_id_t l_ret={ 0 };
    log_it(L_DEBUG, "net id: %s", a_net_str);

    a_net_str += 2;
    if (!(l_ret.uint64 = strtoll(a_net_str, NULL, 0))) {
        log_it(L_ERROR, "Wrong input string \"%s\" not recognized as network id", a_net_str);
        return l_ret;
    }
    return l_ret;
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
void dap_chain_addr_fill_from_key(dap_chain_addr_t *a_addr, dap_enc_key_t *a_key, dap_chain_net_id_t a_net_id) {
    dap_sign_type_t l_type = dap_sign_type_from_key_type(a_key->type);
    size_t l_pub_key_data_size;
    uint8_t *l_pub_key_data = dap_enc_key_serealize_pub_key(a_key, &l_pub_key_data_size);
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
    char *l_buf = DAP_NEW_Z_SIZE(char, DATOSHI_POW + 3);
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
        return  NULL;

    l_strlen = strlen(l_buf);

    if ( 0 < (l_len = (l_strlen - DATOSHI_DEGREE_18)) )
        {
        l_cp = l_buf + l_len;                                               /* Move last 18 symbols to one position right */
        memmove(l_cp + 1, l_cp, DATOSHI_DEGREE_18);
        *l_cp = '.';                                                        /* Insert '.' separator */

        l_strlen++;                                                         /* Adjust string len in the buffer */
    } else {
        l_len = DATOSHI_DEGREE_18 - l_strlen + 2;                           /* Add leading "0." */
        l_cp = l_buf;
        memmove(l_cp + 2, l_cp, l_len);                                     /* Move last 18 symbols to 2 positions right */
        *(l_cp++) = '0';
        *(l_cp++) = '.';

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

    for ( l_cp = l_buf + l_strlen -1; *l_cp == '0'; l_cp--)
        *l_cp = '\0';


    return l_buf;
}

const union __c_pow10__ {
    uint64_t u64[2];
    uint32_t u32[4];
} DAP_ALIGN_PACKED c_pow10[DATOSHI_POW + 1] = {
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
    if (l_strlen > DATOSHI_POW + 1)
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
    char l_buf [DATOSHI_POW + 3] = {0};
    uint128_t l_ret = uint128_0, l_nul = uint128_0;

    if (strlen(a_coins) > DATOSHI_POW + 2) {
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
    if ( (l_len = strnlen(a_coins, 2*DATOSHI_POW + 2 )) > 2*DATOSHI_POW + 2)/* Check for legal length */
        return  log_it(L_WARNING, "Incorrect balance format of '%s' - too long (%d > %d)", a_coins,
                l_len, 2*DATOSHI_POW + 2), l_nul;

    /* Find , check and remove 'precision' dot symbol */
    memcpy (l_buf, a_coins, l_len);                                         /* Make local coy */
    if ( !(l_point = memchr(l_buf, '.', l_len)) )                            /* Is there 'dot' ? */
        return  log_it(L_WARNING, "Incorrect balance format of '%s' - no precision mark", a_coins),
                l_nul;

    l_pos = l_len - (l_point - l_buf);                                      /* Check number of decimals after dot */
    l_pos--;
    if ( (l_pos ) >  DATOSHI_DEGREE_18 )
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
    memset(l_point + l_pos, '0', DATOSHI_DEGREE_18 - l_pos);

    return dap_cvt_str_to_uint256 (l_buf);
}



/*
 *   DESCRIPTION: Convert 256-bit unsigned integer into the decimal text string representation
 *
 *   INPUTS:
 *      a_uint256:  A value to convert
 *
 *   OUTPUTS:
 *      NONE
 *
 *   RETURNS:
 *      an address of the decimal representation text string , shoud be deallocated  by free()
 */
#ifdef DAP_GLOBAL_IS_INT128
char *dap_cvt_uint256_to_str (uint256_t a_uint256)
{
char *l_buf, *l_cp, *l_cp2, *l_cps, *l_cpe, l_chr;
int     l_len;
uint128_t l_nibble;


    l_len = (DAP_CHAIN$SZ_MAX256DEC + 8) & (~7);                            /* Align size of the buffer to 8 bytes */

    if ( !(l_buf = DAP_NEW_Z_SIZE(char, l_len)) )
        return  log_it(L_ERROR, "Cannot allocate %d octets, errno=%d", l_len, errno), NULL;

    l_cp = l_buf;


    /* hi = 123, lo = 0...0456 */
    if ( a_uint256.hi )
    {
        /* 123 - > "321" */
        l_nibble = a_uint256.hi;
        do { *(l_cp++) = (l_nibble % 10) + '0'; } while (l_nibble /= 10);

        l_len = l_cp - l_buf;                                                   /* Length of the decimal string */
        l_len = l_len / 2;                                                      /* A number of swaps */

        l_cps = l_buf;                                                          /* Pointer to head */
        l_cpe = l_cp - 1;                                                       /* -- // -- to tail of the string */

        for (int i = l_len; i--; l_cps++, l_cpe--)                              /* Do swaps ... */
        {
            l_chr = *l_cps;
            *l_cps = *l_cpe;
            *l_cpe = l_chr;
        }
    }

    /* 456 - > "456" */
    l_cp2 = l_cp;
    l_nibble = a_uint256.lo;

    do {
        *(l_cp2++) = (l_nibble % 10) + '0';
    } while (l_nibble /= 10);


    l_len = l_cp2 - l_cp;
    l_len = l_len / 2;

    l_cps = l_cp;
    l_cpe = l_cp2 - 1;

    for (int i = l_len; i--; l_cps++, l_cpe--)
    {
        l_chr = *l_cps;
        *l_cps = *l_cpe;
        *l_cpe = l_chr;
    }

    if (  DAP_CHAIN$SZ_MAX128DEC > (l_len = l_cp2 - l_cp) ) {
        /* "123456" -> 123000...000456" */
        memmove(l_cp + ( DAP_CHAIN$SZ_MAX128DEC - l_len), l_cp, l_len);
        memset(l_cp, '0', ( DAP_CHAIN$SZ_MAX128DEC - l_len));
    }

    return l_buf;
}

#else
static const   char l_zero[sizeof(uint256_t)] = {0};

char *dap_cvt_uint256_to_str(uint256_t a_balance)
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

        l_pos = l_len_hi / 2;                                               /* A number of swaps */
        l_cpe = l_cp - 1;                                                   /* -- // -- to tail of the string */

        for (int i = l_pos; i--; l_cps++, l_cpe--)                          /* Do swaps ... */
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

    if (  l_len_hi && (DAP_CHAIN$SZ_MAX128DEC > l_len_lo) )                 /* Do we need to add leading zeroes ? */
    {
        /* "123456" -> 123000...000456" */
        memmove(l_cp2 + ( DAP_CHAIN$SZ_MAX128DEC - l_len), l_cp2, l_len_lo);
        memset(l_cp2, '0', ( DAP_CHAIN$SZ_MAX128DEC - l_len_lo));
    }

    return  l_buf;
}
#endif






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
int  l_strlen, l_len, l_exp;
uint256_t l_ret = {}, l_nul = uint256_0;
char    l_128bit_num  [DAP_CHAIN$SZ_MAX128DEC + 8],
        l_256bit_num  [DAP_CHAIN$SZ_MAX256DEC];

    /* Compute & check length */
    if ( (l_strlen = strnlen(a_256bit_num, DAP_CHAIN$SZ_MAX256DEC + 1) ) > DAP_CHAIN$SZ_MAX256DEC)
        return  log_it(L_ERROR, "Too many digits in `%s` (%d > %d)", a_256bit_num, l_strlen, DAP_CHAIN$SZ_MAX256DEC), l_nul;

    /* Convert number from xxx.yyyyE+zz to xxxyyyy0000... */
    char *l_eptr = strchr(a_256bit_num, 'e');
    if (!l_eptr)
        l_eptr = strchr(a_256bit_num, 'E');
    if (l_eptr) {
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
        if (l_dot_len >= DAP_CHAIN$SZ_MAX256DEC)
            return log_it(L_ERROR, "Too many digits in '%s'", a_256bit_num), uint256_0;
        int l_exp_len = l_eptr - a_256bit_num - l_dot_len - 1;
        if (l_exp_len + l_dot_len + 1 >= DAP_CHAIN$SZ_MAX256DEC)
            return log_it(L_ERROR, "Too many digits in '%s'", a_256bit_num), uint256_0;
        if (l_exp < l_exp_len)
            return  log_it(L_ERROR, "Invalid number format with exponent %d and nuber coun after dot %d", l_exp, l_exp_len), uint256_0;
        memcpy(l_256bit_num, a_256bit_num, l_dot_len);
        memcpy(l_256bit_num + l_dot_len, a_256bit_num + l_dot_len + 1, l_exp_len);
        int l_zero_cnt = l_exp - l_exp_len;
        size_t l_pos = l_dot_len + l_exp_len;
        for (int i = l_zero_cnt; i && l_pos < DAP_CHAIN$SZ_MAX256DEC; i--)
            l_256bit_num[l_pos++] = '0';
        l_256bit_num[l_pos] = '\0';
    } else {
        memcpy(l_256bit_num, a_256bit_num, l_strlen);
        l_256bit_num[l_strlen] = '\0';
    }

    /* Convert firstly low part of the decimal string */
    l_len = (l_strlen > DAP_CHAIN$SZ_MAX128DEC) ? DAP_CHAIN$SZ_MAX128DEC : l_strlen;
    l_ret.lo =  dap_chain_balance_scan128(l_256bit_num + (l_strlen - l_len));


    /* Convert a high part of the decimal string is need */
    if ( 0 < (l_len = (l_strlen -  DAP_CHAIN$SZ_MAX128DEC)) )
    {
        memcpy(l_128bit_num, l_256bit_num, l_len);
        l_128bit_num[l_len] = '\0';
        l_ret.hi =  dap_chain_balance_scan128(l_128bit_num);
    }

    return l_ret;
}


uint256_t dap_chain_coins_to_balance(const char *a_coins)
{
    return  dap_chain_coins_to_balance256(a_coins);
    // return GET_256_FROM_128(dap_chain_coins_to_balance128(a_coins));
}



char *dap_chain_balance_to_coins(uint256_t a_balance)
{
    return dap_chain_balance_to_coins256(a_balance); /* @RRL */
    //return dap_chain_balance_to_coins128(a_balance.lo);
}


#define __NEW_STARLET__ "BMF"
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
