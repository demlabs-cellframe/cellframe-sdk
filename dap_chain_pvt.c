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
#include <sys/types.h>
#include <dirent.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dap_chain_pvt.h"


#define LOG_TAG "dap_chain_pvt"

int dap_chain_pvt_cells_load( dap_chain_t * a_chain)
{

}

int dap_chain_pvt_cells_save( dap_chain_t * a_chain)
{

}

int dap_chain_pvt_cells_update( dap_chain_t * a_chain)
{

}

/**
 * @brief dap_chain_cell_load_file
 * @param a_cell
 * @param a_cell_file_path
 * @return
 */

int dap_chain_cell_load_file ( dap_chain_cell_t * a_cell, const char * a_cell_file_path )
{
    /**
    if( a_cell->file_storage_path )
        free ( a_cell->file_storage_path );
    a_cell->file_storage_path = strdup( a_cell_file_path );
    a_cell->file_storage = fopen(a_cell->file_storage_path,"r");

    if ( a_cell->file_storage ){
        dap_chain_cell_file_header_t l_hdr = {0};
        if ( fread( &l_hdr,1,sizeof(l_hdr),a_cell->file_storage ) == sizeof (l_hdr) ) {
            if ( l_hdr.signature == DAP_CHAIN_CELL_FILE_SIGNATURE ) {
                while ( feof( a_cell->file_storage) == 0 ){
                    size_t l_element_size = 0;
                    if ( fread(&l_element_size,1,sizeof(l_element_size),a_cell->file_storage) == sizeof(l_element_size) ){
                        if ( l_element_size > 0 ){
                            uint8_t * l_element_data = DAP_NEW_Z_SIZE (uint8_t, l_element_size );
                            if ( fread( l_element_data,1,l_element_size,a_cell->file_storage ) == l_element_size ) {
                                a_cell->chain->callback_atom_add (a_chain, l_element_data, l_element_size );
                            }
                        } else {
                            log_it (L_ERROR, "Zero element size, file is corrupted");
                            break;
                        }
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
        log_it (L_WARNING,"Can't read dap_chain file \"%s\"",l_chain_pvt->file_storage_path);
        return -1;
    }
**/
}

/**
 * @brief dap_chain_cell_save_file
 * @param a_cell
 * @param a_cell_file_path
 * @return
 */


int dap_chain_cell_save_file ( dap_chain_cell_t * a_cell, const char * a_cell_file_path)
{
/**
    a_cell->file_storage = fopen(a_cell->file_storage_path,"w");
    if ( a_cell->file_storage ){
        dap_chain_cell_file_header_t l_hdr = {
            .signature = DAP_CHAIN_CELL_FILE_SIGNATURE,
            .version = DAP_CHAIN_CELL_FILE_VERSION,
            .type = DAP_CHAIN_CELL_FILE_TYPE_RAW,
            .chain_id = a_chain->id,
            .chain_net_id = a_chain->net_id
        };
        if ( fwrite( &l_hdr,1,sizeof(l_hdr),l_chain_pvt->file_storage ) == sizeof (l_hdr) ) {
            size_t l_element_size = 0;
            void *l_element_data = NULL;
            a_chain->callback_element_get_first (a_chain, &l_element_data, &l_element_size);
            while ( l_element_data && l_element_size ){
                if ( fwrite(&l_element_size,1,sizeof(l_element_size),l_chain_pvt->file_storage) == sizeof(l_element_size) ){
                    if ( fwrite(&l_element_data,1,l_element_size,l_chain_pvt->file_storage) == l_element_size ){
                        a_chain->callback_element_get_next(a_chain, &l_element_data, &l_element_size);
                    } else {
                        log_it (L_ERROR, "Can't write data to the file");
                        break;
                    }
                } else {
                    log_it (L_ERROR, "Can't write data to the file");
                    break;
                }
            }
        } else {
            log_it (L_ERROR,"Can't write dap_chain file header \"%s\"",l_chain_pvt->file_storage_path);
            return -2;
        }
    }else {
        log_it (L_ERROR,"Can't write dap_chain file \"%s\"",l_chain_pvt->file_storage_path);
        return -1;
    }
    return 0;
**/
}




