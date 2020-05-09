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
    [DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_BLOCKED] = "ALL_BLOCKED",
    [DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_ALLOWED] = "ALL_ALLOWED",
    [DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_FROZEN] = "ALL_FROZEN",
    [DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_UNFROZEN] = "ALL_UNFROZEN",
};

/**
 * @brief dap_chain_datum_token_tsd_create
 * @param a_type
 * @param a_data
 * @param a_data_size
 * @return
 */
dap_chain_datum_token_tsd_t * dap_chain_datum_token_tsd_create(uint16_t a_type, const void * a_data, size_t a_data_size)
{
    dap_chain_datum_token_tsd_t * l_tsd = DAP_NEW_Z_SIZE(dap_chain_datum_token_tsd_t,
                                                         sizeof(dap_chain_datum_token_tsd_t) + a_data_size );
    if ( l_tsd ){
        memcpy(l_tsd->data, a_data , a_data_size );
        l_tsd->type = a_type;
        l_tsd->size = a_data_size;
    }
    return l_tsd;

}

/**
 * @brief dap_chain_datum_token_tsd_get
 * @param a_token
 * @param a_token_size
 * @return
 */
dap_chain_datum_token_tsd_t* dap_chain_datum_token_tsd_get(dap_chain_datum_token_t * a_token, size_t a_token_size)
{
    // Check if token type could have tsd section
    size_t l_hdr_size;
    size_t l_tsd_size;
    switch( a_token->type){
        case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL:
            l_hdr_size = sizeof (a_token->header_private_decl);
            if (l_hdr_size> a_token_size){
                log_it(L_WARNING, "Token size smaller then header, corrupted data");
                return NULL;
            }
            l_tsd_size = a_token->header_private_decl.tsd_total_size;
        break;
        case DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE:
            l_hdr_size = sizeof(a_token->header_private_update);
            if (l_hdr_size> a_token_size){
                log_it(L_WARNING, "Token size smaller then header, corrupted data");
                return NULL;
            }
            l_tsd_size = a_token->header_private_update.tsd_total_size;
        break;
        default: return NULL;
    }

    if (l_tsd_size+l_hdr_size > a_token_size){
        log_it(L_WARNING, "TSD size %zd overlaps with header, corrupted data");
    }else if (l_tsd_size +l_hdr_size == a_token_size){
        log_it(L_INFO, "No signatures at all, returning pointer to the top of data");
        return (dap_chain_datum_token_tsd_t*) a_token->data_n_tsd;
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
        return (dap_chain_datum_token_tsd_t*) (a_token->data_n_tsd+l_offset);
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
        dap_string_append_printf(a_str_out, "<NONE>\n");
        return;
    }
    for ( uint16_t i = 0;  (2^i) <=DAP_CHAIN_DATUM_TOKEN_FLAG_MAX; i++ ){
        if(   a_flags & (2^i) )
            dap_string_append_printf(a_str_out,"%s%s", c_dap_chain_datum_token_flag_str[2^i],
                    (2^i)==DAP_CHAIN_DATUM_TOKEN_FLAG_MAX?",":"\n"  );
    }
}

