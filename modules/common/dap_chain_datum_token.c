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
        memcpy(l_tsd->data,&a_data , a_data_size );
        l_tsd->type = a_type;
        l_tsd->size = a_data_size;
    }
    return l_tsd;

}
