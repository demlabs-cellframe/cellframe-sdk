/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net    https:/gitlab.com/demlabs
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dap_chain_pvt.h"


#define LOG_TAG "dap_chain_pvt"

/**
 * @brief dap_chain_pvt_file_load
 * @param a_chain
 * @return
 */
int dap_chain_pvt_file_load( dap_chain_t * a_chain)
{
    DAP_CHAIN_PVT_LOCAL (a_chain);
    l_chain_pvt->file_storage = fopen(l_chain_pvt->file_storage_path,"r");
    if ( l_chain_pvt->file_storage ){
        dap_chain_file_header_t l_hdr = {0};
        if ( fread( &l_hdr,1,sizeof(l_hdr),l_chain_pvt->file_storage ) == sizeof (l_hdr) ) {
            if ( l_hdr.signature == DAP_CHAIN_FILE_SIGNATURE ) {
                size_t l_element_hdr_size = a_chain->callback_get_internal_hdr_size(a_chain);
                uint8_t * l_element_hdr = DAP_NEW_Z_SIZE(uint8_t,l_element_hdr_size);
                while ( feof( l_chain_pvt->file_storage) == 0 ){
                    if ( fread(l_element_hdr,1,l_element_hdr_size,l_chain_pvt->file_storage) == l_element_hdr_size ){
                        //size_t l_element_data_size = a_chain->callback_element_hdr_get_data_size ( a_chain , l_element_hdr ) ;
                       // uint8_t * l_element_data = DAP_NEW_Z_SIZE (uint8_t, l_element_size );
                    }
                }
                return 0;
            } else {
                log_it (L_ERROR,"Wrong signature in file \"%s\", possible file corrupt",l_chain_pvt->file_storage_path);
                return -3;
            }
        } else {
            log_it (L_ERROR,"Can't read dap_chain file header \"%s\"",l_chain_pvt->file_storage_path);
            return -2;
        }
    }else {
        log_it (L_ERROR,"Can't read dap_chain file \"%s\"",l_chain_pvt->file_storage_path);
        return -1;
    }
}

/**
 * @brief dap_chain_pvt_file_save
 * @param a_chain
 * @return
 */
int dap_chain_pvt_file_save( dap_chain_t * a_chain)
{
    return 0;
}

/**
 * @brief dap_chain_pvt_file_update
 * @param a_chain
 * @return
 */
int dap_chain_pvt_file_update( dap_chain_t * a_chain)
{
   return 0;
}
