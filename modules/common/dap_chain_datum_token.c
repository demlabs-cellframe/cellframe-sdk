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
#include <string.h>
#include "dap_strfuncs.h"
#include "dap_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_token.h"
#include "dap_uuid.h"
#include "dap_enc_base58.h"

#define LOG_TAG "dap_chain_datum_token"

const char *c_dap_chain_datum_token_emission_type_str[]={
    [DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_UNDEFINED] = "UNDEFINED",
    [DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH] = "AUTH",
    [DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ALGO] = "ALGO",
    [DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ATOM_OWNER] = "OWNER",
    [DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_SMART_CONTRACT] = "SMART_CONTRACT"
// 256 types
    // [DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_256_UNDEFINED] = "UNDEFINED",
    // [DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_256_AUTH] = "AUTH",
    // [DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_256_ALGO] = "ALGO",
    // [DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_256_ATOM_OWNER] = "OWNER",
    // [DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_256_SMART_CONTRACT] = "SMART_CONTRACT"
};

const char *c_dap_chain_datum_token_flag_str[] = {
    [DAP_CHAIN_DATUM_TOKEN_FLAG_NONE] = "NONE",
    [DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_BLOCKED] = "ALL_SENDER_BLOCKED",
    [DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_ALLOWED] = "ALL_SENDER_ALLOWED",
    [DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_FROZEN] = "ALL_SENDER_FROZEN",
    [DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_UNFROZEN] = "ALL_SENDER_UNFROZEN",
    [DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_BLOCKED] = "ALL_RECEIVER_BLOCKED",
    [DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_ALLOWED] = "ALL_RECEIVER_ALLOWED",
    [DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_FROZEN] = "ALL_RECEIVER_FROZEN",
    [DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_UNFROZEN] = "ALL_RECEIVER_UNFROZEN",
};

/**
 * @brief dap_chain_datum_token_tsd_get
 * @param a_token
 * @param a_token_size
 * @return
 */
dap_tsd_t* dap_chain_datum_token_tsd_get(dap_chain_datum_token_t *a_token, size_t a_token_size)
{
    // Check if token type could have tsd section
    size_t l_hdr_size = sizeof(dap_chain_datum_token_t);
    if (l_hdr_size > a_token_size){
        log_it(L_WARNING, "Token size smaller then header, corrupted data");
        return NULL;
    }
    return (dap_tsd_t *)a_token->data_n_tsd;
}

dap_chain_datum_token_t *dap_chain_datum_token_read(byte_t *a_token_serial, size_t *a_token_size) {

    uint16_t l_token_type = ((dap_chain_datum_token_t *)a_token_serial)->type;
    if ( dap_chain_datum_token_is_old(l_token_type) ) {
        dap_chain_datum_token_old_t *l_token_old = (dap_chain_datum_token_old_t *)a_token_serial;
        size_t l_token_size = (*a_token_size) - sizeof(*l_token_old) + sizeof(dap_chain_datum_token_t);
        dap_chain_datum_token_t * l_token = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, l_token_size);
        memcpy(l_token->ticker, l_token_old->ticker, sizeof(l_token_old->ticker));
        l_token->ticker[sizeof(l_token_old->ticker) - 1] = '\0';
        size_t l_token_tsd_size = (*a_token_size) - sizeof(*l_token_old);
        memcpy(l_token->data_n_tsd, l_token_old->data_n_tsd, l_token_tsd_size);

        switch( l_token_type ){
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_SIMPLE: {
                l_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_SIMPLE; // 256
                l_token->total_supply = GET_256_FROM_64(l_token_old->header_simple.total_supply);
                l_token->signs_valid = l_token_old->header_simple.signs_valid;
                l_token->signs_total = l_token_old->header_simple.signs_total;
                break;
            }
            default:
                return NULL;
        }
        return l_token;
    } else {
        return DAP_DUP_SIZE(a_token_serial, *a_token_size);
    }
    return NULL;
}

/**
 * @brief dap_chain_datum_token_flags_dump
 * @param a_str_out
 * @param a_flags
 */
void dap_chain_datum_token_flags_dump(dap_string_t * a_str_out, uint16_t a_flags)
{
    if(!a_flags){
        dap_string_append_printf(a_str_out, "%s\n",
                c_dap_chain_datum_token_flag_str[DAP_CHAIN_DATUM_TOKEN_FLAG_NONE]);
        return;
    }
    bool is_first = true;
    for ( uint16_t i = 0;  i <= DAP_CHAIN_DATUM_TOKEN_FLAG_MAX; i++){
        if(   a_flags &  (1 << i) ){
            if(is_first)
                is_first = false;
            else
                dap_string_append_printf(a_str_out,", ");
            dap_string_append_printf(a_str_out,"%s", c_dap_chain_datum_token_flag_str[i]);
        }
        if(i == DAP_CHAIN_DATUM_TOKEN_FLAG_MAX)
            dap_string_append_printf(a_str_out, "\n");
    }
}


/**
 * @brief dap_chain_datum_token_certs_dump
 * @param a_str_out
 * @param a_data_n_tsd
 * @param a_certs_size
 */
void dap_chain_datum_token_certs_dump(dap_string_t * a_str_out, byte_t * a_data_n_tsd, size_t a_certs_size, const char *a_hash_out_type)
{
    dap_string_append_printf(a_str_out, "signatures: ");
    if (!a_certs_size) {
        dap_string_append_printf(a_str_out, "<NONE>\n");
        return;
    }

    dap_string_append_printf(a_str_out, "\n");

    size_t l_offset = 0;
    for (int i = 1; l_offset < (a_certs_size); i++) {
        dap_sign_t *l_sign = (dap_sign_t *) (a_data_n_tsd + l_offset);
        l_offset += dap_sign_get_size(l_sign);
        if (l_sign->header.sign_size == 0) {
            dap_string_append_printf(a_str_out, "<CORRUPTED - 0 size signature>\n");
            continue;
        }

        dap_chain_hash_fast_t l_pkey_hash = {0};
        if (dap_sign_get_pkey_hash(l_sign, &l_pkey_hash) == false) {
            dap_string_append_printf(a_str_out, "<CORRUPTED - can't calc hash>\n");
            continue;
        }

        char *l_hash_str = NULL;
        if(!dap_strcmp(a_hash_out_type, "hex"))
            l_hash_str = dap_chain_hash_fast_to_str_new(&l_pkey_hash);
        else
            l_hash_str = dap_enc_base58_encode_hash_to_str(&l_pkey_hash);

        dap_string_append_printf(a_str_out, "%d) %s, %s, %u bytes\n", i, l_hash_str,
                                 dap_sign_type_to_str(l_sign->header.type), l_sign->header.sign_size);
    }
}

dap_sign_t ** dap_chain_datum_token_signs_parse(dap_chain_datum_token_t * a_datum_token, size_t a_datum_token_size, size_t *a_signs_total, size_t * a_signs_valid)
{
    assert(a_datum_token_size);
    assert(a_datum_token);
    assert(a_signs_total);
    assert(a_signs_valid);
    assert(a_datum_token_size >= sizeof(dap_chain_datum_token_old_t));
    dap_sign_t ** l_ret = DAP_NEW_Z_SIZE(dap_sign_t*, sizeof (dap_sign_t*)*a_datum_token->signs_total);
    *a_signs_total = 0;
    *a_signs_valid = a_datum_token->signs_valid;
    size_t l_offset = 0;
    uint16_t n = 0;
    size_t l_signs_offset = a_datum_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_SIMPLE
                                                 ? sizeof(dap_chain_datum_token_old_t)
                                                 : sizeof(dap_chain_datum_token_t);
    if ((a_datum_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_DECL) ||
            (a_datum_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL)) {
        l_signs_offset += a_datum_token->header_native_decl.tsd_total_size;
    }
    while( l_offset < (a_datum_token_size - l_signs_offset) && n < a_datum_token->signs_total ) {
        dap_sign_t *l_sign = (dap_sign_t *)((byte_t *)a_datum_token + l_signs_offset + l_offset);
        size_t l_sign_size = dap_sign_get_size(l_sign);
        if(!l_sign_size ){
            log_it(L_WARNING,"Corrupted signature: size is zero");
            goto err;
        }
        if(l_sign_size> (a_datum_token_size-l_offset ) ){
            log_it(L_WARNING,"Corrupted signature: size %zd is too big", l_sign_size);
            goto err;
        }
        l_ret[n] = l_sign;
        n++;
        (*a_signs_total)++;
        l_offset += l_sign_size;
    }
    return l_ret;
err:
    *a_signs_total = 0;
    if(l_ret)
        DAP_DELETE(l_ret);
    return NULL;

}

dap_chain_datum_token_emission_t *dap_chain_datum_emission_create(uint256_t a_value, const char *a_ticker, dap_chain_addr_t *a_addr)
{
    dap_chain_datum_token_emission_t *l_emission = DAP_NEW_Z(dap_chain_datum_token_emission_t);
    l_emission->hdr.version = 2;
    l_emission->hdr.value_256 = a_value;
    strncpy(l_emission->hdr.ticker, a_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_emission->hdr.ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
    l_emission->hdr.type = DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH;
    memcpy(&l_emission->hdr.address, a_addr, sizeof(l_emission->hdr.address));
    dap_uuid_generate_nonce(&l_emission->hdr.nonce, DAP_CHAIN_DATUM_NONCE_SIZE);
    return l_emission;
}

size_t dap_chain_datum_emission_get_size(uint8_t *a_emission_serial)
{
    size_t l_ret = 0;
    dap_chain_datum_token_emission_t *l_emission = (dap_chain_datum_token_emission_t *)a_emission_serial;
    if (l_emission->hdr.version == 0) {
        l_ret = sizeof(struct dap_chain_emission_header_v0);
    } else {
        l_ret = sizeof(l_emission->hdr);
    }
    if (l_emission->hdr.type == DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH) {
        uint64_t l_size = *(uint64_t *)(a_emission_serial + l_ret);
        l_ret += l_size;
    }
    l_ret += sizeof(l_emission->data);
    return l_ret;
}

dap_chain_datum_token_emission_t *dap_chain_datum_emission_read(byte_t *a_emission_serial, size_t *a_emission_size)
{
    assert(a_emission_serial);
    assert(a_emission_size);
    dap_chain_datum_token_emission_t *l_emission = NULL;
    if (((dap_chain_datum_token_emission_t *)a_emission_serial)->hdr.version == 0) {
        size_t l_emission_size = *a_emission_size;
        size_t l_old_hdr_size = sizeof(struct dap_chain_emission_header_v0);
        size_t l_add_size = sizeof(l_emission->hdr) - l_old_hdr_size;
        l_emission = DAP_NEW_Z_SIZE(dap_chain_datum_token_emission_t, l_emission_size + l_add_size);
        l_emission->hdr.version = 2;
        memcpy(l_emission, a_emission_serial, l_old_hdr_size);
        memcpy((byte_t *)l_emission + sizeof(l_emission->hdr),
               a_emission_serial + l_old_hdr_size,
               l_emission_size - l_old_hdr_size);
        l_emission->hdr.value_256 = dap_chain_uint256_from(
                    ((dap_chain_datum_token_emission_t *)a_emission_serial)->hdr.value);
        l_emission_size += l_add_size;
        (*a_emission_size) = l_emission_size;
    } else {
        l_emission = DAP_DUP_SIZE(a_emission_serial, *a_emission_size);
        if (((dap_chain_datum_token_emission_t *)a_emission_serial)->hdr.version == 1)
            l_emission->hdr.value_256 = dap_chain_uint256_from(
                        ((dap_chain_datum_token_emission_t *)a_emission_serial)->hdr.value);
    }
    return l_emission;
}

dap_chain_datum_token_emission_t *dap_chain_datum_emission_add_tsd(dap_chain_datum_token_emission_t *a_emission, int a_type, size_t a_size, void *a_data)
{
    if (!a_emission || a_emission->hdr.type != DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH)
        return NULL;
    dap_tsd_t *l_tsd = dap_tsd_create(a_type, a_data, a_size);
    size_t l_tsd_size = sizeof(dap_tsd_t) + a_size;
    size_t l_emission_size = dap_chain_datum_emission_get_size((uint8_t *)a_emission);
    dap_chain_datum_token_emission_t *l_emission = DAP_REALLOC(a_emission, l_emission_size + l_tsd_size);
    memcpy(l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size, l_tsd, l_tsd_size);
    DAP_DELETE(l_tsd);
    l_emission->data.type_auth.tsd_total_size += l_tsd_size;
    l_emission->data.type_auth.size += l_tsd_size;
    return l_emission;
}

byte_t *dap_chain_emission_get_tsd(dap_chain_datum_token_emission_t *a_emission, int a_type, size_t *a_size)
{
    if (!a_emission || a_emission->hdr.type != DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH ||
            a_emission->data.type_auth.tsd_total_size == 0)
        return NULL;
    dap_tsd_t *l_tsd = (dap_tsd_t *)a_emission->tsd_n_signs;
    do {
        if (l_tsd->type == a_type) {
            if (a_size)
                *a_size = l_tsd->size;
            return l_tsd->data;
        }
        l_tsd = (dap_tsd_t *)((byte_t *)l_tsd + dap_tsd_size(l_tsd));
    } while ((byte_t *)l_tsd < a_emission->tsd_n_signs + a_emission->data.type_auth.tsd_total_size);
    return NULL;
}

dap_chain_datum_token_emission_t *dap_chain_datum_emission_add_sign(dap_enc_key_t *a_sign_key, dap_chain_datum_token_emission_t *a_emission)
{
    if (!a_emission || a_emission->hdr.type != DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH)
        return NULL;

    dap_sign_t *l_sign = NULL;

    if (a_emission->data.type_auth.size > a_emission->data.type_auth.tsd_total_size)
    {
        size_t l_pub_key_size = 0;
        dap_sign_t *l_sign = (dap_sign_t *)(a_emission->tsd_n_signs + a_emission->data.type_auth.tsd_total_size);
        uint8_t *l_pub_key = dap_enc_key_serealize_pub_key(a_sign_key, &l_pub_key_size);
        for (int i = 0; i < a_emission->data.type_auth.signs_count; i++) {
            if (l_sign->header.sign_pkey_size == l_pub_key_size &&
                    !memcmp(l_sign->pkey_n_sign, l_pub_key, l_pub_key_size))
                return a_emission;  // this sign already exists
            l_sign = (dap_sign_t *)((byte_t *)l_sign + dap_sign_get_size(l_sign));
        }
        DAP_DELETE(l_pub_key);
    }

    l_sign = dap_sign_create(a_sign_key, a_emission, sizeof(a_emission->hdr), 0);
    if (!l_sign)
        return NULL;
    size_t l_emission_size = dap_chain_datum_emission_get_size((uint8_t *)a_emission);
    dap_chain_datum_token_emission_t *l_ret = DAP_REALLOC(a_emission, l_emission_size + dap_sign_get_size(l_sign));
    size_t l_sign_size = dap_sign_get_size(l_sign);
    memcpy(l_ret->tsd_n_signs + l_ret->data.type_auth.size, l_sign, l_sign_size);
    DAP_DELETE(l_sign);
    l_ret->data.type_auth.size += l_sign_size;
    l_ret->data.type_auth.signs_count++;
    return l_ret;
}

// #define DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_SIMPLE           0x0001
// Extended declaration of privatetoken with in-time control
// #define DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_DECL     0x0002
// Token update
// #define DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_UPDATE   0x0003
// Open token with now ownership
// #define DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PUBLIC           0x0004

// 256 TYPE
bool dap_chain_datum_token_is_old(uint8_t a_type) {
    switch(a_type) {
        case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_SIMPLE:
        case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PUBLIC:
            return true;
        default:
            return false;
    }
}
