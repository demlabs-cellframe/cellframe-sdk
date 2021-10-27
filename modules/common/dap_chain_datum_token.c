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
#include "dap_chain_datum_token.h"

#define LOG_TAG "dap_chain_datum_token"

const char *c_dap_chain_datum_token_emission_type_str[]={
    [DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_UNDEFINED] = "UNDEFINED",
    [DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH] = "AUTH",
    [DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ALGO] = "ALGO",
    [DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ATOM_OWNER] = "OWNER",
    [DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_SMART_CONTRACT] = "SMART_CONTRACT",
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
dap_tsd_t* dap_chain_datum_token_tsd_get(dap_chain_datum_token_t * a_token, size_t a_token_size)
{
    // Check if token type could have tsd section
    size_t l_hdr_size = sizeof(*a_token);
    size_t l_tsd_size;

    if (l_hdr_size > a_token_size){
        log_it(L_WARNING, "Token size smaller then header, corrupted data");
        return NULL;
    }

    switch( a_token->type){
        case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL:
            l_tsd_size = a_token->header_private_decl.tsd_total_size;
        break;
        case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE:
            l_tsd_size = a_token->header_private_update.tsd_total_size;
        break;
        default: return NULL;
    }

    if (l_tsd_size+l_hdr_size > a_token_size){
        log_it(L_WARNING, "TSD size %zd overlaps with header, corrupted data", l_tsd_size);
    }else if (l_tsd_size +l_hdr_size == a_token_size){
        log_it(L_INFO, "No signatures at all, returning pointer to the top of data");
        return (dap_tsd_t*) a_token->data_n_tsd;
    }

    // Pass through signatures to find top of TSD section
    size_t l_offset = 0;
    while( l_offset < (a_token_size - l_hdr_size-l_tsd_size) ){
        dap_sign_t* l_sign = (dap_sign_t*) (a_token->data_n_tsd + l_offset);
        if (l_sign->header.sign_size == 0){
            log_it( L_WARNING, "Corrupted signature, 0 size");
            return NULL;
        }
        l_offset += dap_sign_get_size( l_sign);
    }
    if ( l_offset + l_hdr_size +l_tsd_size <= a_token_size  )
        return (dap_tsd_t*) (a_token->data_n_tsd+l_offset);
    else{
        log_it(L_WARNING, "Signatures overlaps with TSD section, corrupted data");
        return NULL;
    }
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
void dap_chain_datum_token_certs_dump(dap_string_t * a_str_out, byte_t * a_data_n_tsd, size_t a_certs_size) {
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

        char *l_hash_str = dap_chain_hash_fast_to_str_new(&l_pkey_hash);

        dap_string_append_printf(a_str_out, "%d) %s, %s, %u bytes\n", i, l_hash_str,
                                 dap_sign_type_to_str(l_sign->header.type), l_sign->header.sign_size);
    }
}

dap_sign_t ** dap_chain_datum_token_simple_signs_parse(dap_chain_datum_token_t * a_datum_token, size_t a_datum_token_size, size_t *a_signs_total, size_t * a_signs_valid)
{
    assert(a_datum_token_size);
    assert(a_datum_token);
    assert(a_signs_total);
    assert(a_signs_valid);
    assert( a_datum_token_size >= sizeof (a_datum_token));
    dap_sign_t ** l_ret = DAP_NEW_Z_SIZE(dap_sign_t*, sizeof (dap_sign_t*)*a_datum_token->header_private.signs_total );
    *a_signs_total=0;
    *a_signs_valid = a_datum_token->header_private.signs_valid;
    size_t l_offset = 0;
    uint16_t n = 0;
    while( l_offset < (a_datum_token_size-sizeof (a_datum_token) ) && n < a_datum_token->header_private.signs_total ) {
        dap_sign_t *l_sign = (dap_sign_t *) ( a_datum_token->data_n_tsd + l_offset);
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
