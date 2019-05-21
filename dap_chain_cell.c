/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
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
#include "uthash.h"

#include "dap_common.h"
#include "dap_config.h"
#include "dap_strfuncs.h"
#include "dap_chain.h"
#include "dap_chain_cell.h"
#include "dap_chain_cs.h"

#define LOG_TAG "dap_chain_cell"



#define DAP_CHAIN_CELL_FILE_VERSION 1
#define DAP_CHAIN_CELL_FILE_SIGNATURE 0xfa340bef153eba48
#define DAP_CHAIN_CELL_FILE_TYPE_RAW 0
#define DAP_CHAIN_CELL_FILE_TYPE_COMPRESSED 1

/**
  * @struct dap_chain_cell_file_header
  */
typedef struct dap_chain_cell_file_header
{
    uint64_t signature;
    uint32_t version;
    uint8_t type;
    dap_chain_id_t chain_id;
    dap_chain_net_id_t chain_net_id;
    dap_chain_cell_id_t cell_id;
} DAP_ALIGN_PACKED dap_chain_cell_file_header_t;


static const char* s_cells_path = NULL;

/**
 * @brief dap_chain_cell_init
 * @return
 */
int dap_chain_cell_init(void)
{
    s_cells_path = dap_config_get_item_str(g_config,"resources","cells_storage");
    return  0;
}

/**
 * @brief dap_chain_cell_create
 * @return
 */
dap_chain_cell_t * dap_chain_cell_create()
{
    dap_chain_cell_t * l_cell = DAP_NEW_Z(dap_chain_cell_t);
    return  l_cell;
}

/**
 * @brief dap_chain_cell_load
 * @param a_chain
 * @param a_cell_file_path
 * @return
 */
int dap_chain_cell_load(dap_chain_t * a_chain, const char * a_cell_file_path)
{
    dap_chain_cell_t * l_cell = dap_chain_cell_create();

    l_cell->file_storage_path = dap_strdup( a_cell_file_path );


    l_cell->file_storage = fopen(l_cell->file_storage_path,"a+");

    if ( l_cell->file_storage ){
        dap_chain_cell_file_header_t l_hdr = {0};
        if ( fread( &l_hdr,1,sizeof(l_hdr),l_cell->file_storage ) == sizeof (l_hdr) ) {
            if ( l_hdr.signature == DAP_CHAIN_CELL_FILE_SIGNATURE ) {
                while ( feof( l_cell->file_storage) == 0 ){
                    size_t l_element_size = 0;
                    if ( fread(&l_element_size,1,sizeof(l_element_size),l_cell->file_storage) ==
                         sizeof(l_element_size) ){
                        if ( l_element_size > 0 ){
                            dap_chain_atom_ptr_t * l_element = DAP_NEW_Z_SIZE (dap_chain_atom_ptr_t, l_element_size );
                            if ( fread( l_element,1,l_element_size,l_cell->file_storage ) == l_element_size ) {
                                l_cell->chain->callback_atom_add (a_chain, l_element );
                            }
                        } else {
                            log_it (L_ERROR, "Zero element size, file is corrupted");
                            break;
                        }
                    }
                }
                return 0;
            } else {
                log_it (L_ERROR,"Wrong signature in file \"%s\", possible file corrupt",l_cell->file_storage_path);
                return -3;
            }
        } else {
            log_it (L_ERROR,"Can't read dap_chain file header \"%s\"",l_cell->file_storage_path);
            return -2;
        }
    }else {
        log_it (L_WARNING,"Can't read dap_chain file \"%s\"",l_cell->file_storage_path);
        return -1;
    }

}

/**
 * @brief s_cell_file_append
 * @param a_cell
 * @param a_atom
 * @param a_atom_size
 * @return
 */
int dap_chain_cell_file_append( dap_chain_cell_t * a_cell, const void* a_atom, size_t a_atom_size)
{
    size_t l_total_wrote_bytes = 0;
    if ( fwrite(&a_atom_size,1,sizeof(a_atom_size),a_cell->file_storage) == sizeof(a_atom_size) ){
        l_total_wrote_bytes += sizeof (a_atom_size);
        if ( fwrite(&a_atom,1,a_atom_size,a_cell->file_storage) == a_atom_size ){
            l_total_wrote_bytes += a_atom_size;
        } else {
            log_it (L_ERROR, "Can't write data from cell 0x%016X to the file \"%s\"",
                            a_cell->id.uint64,
                            a_cell->file_storage_path);
            return -1;
        }
    } else {
        log_it (L_ERROR,"Can't write atom data size from cell 0x%016X in \"%s\"",
                a_cell->id.uint64,
                a_cell->file_storage_path);
        return -2;
    }
    return (int)  l_total_wrote_bytes;
}

/**
 * @brief dap_chain_cell_file_update
 * @param a_cell
 * @return
 */
int dap_chain_cell_file_update( dap_chain_cell_t * a_cell)
{
    if(a_cell->file_storage == NULL ){ // File need to be created
        a_cell->file_storage = fopen(a_cell->file_storage_path,"w");
        if ( a_cell->file_storage ){
            dap_chain_cell_file_header_t l_hdr = {
                .signature = DAP_CHAIN_CELL_FILE_SIGNATURE,
                .version = DAP_CHAIN_CELL_FILE_VERSION,
                .type = DAP_CHAIN_CELL_FILE_TYPE_RAW,
                .chain_id = { .uint64 = a_cell->id.uint64 },
                .chain_net_id = a_cell->chain->net_id
            };
            if ( fwrite( &l_hdr,1,sizeof(l_hdr),a_cell->file_storage ) == sizeof (l_hdr) ) {
                log_it(L_NOTICE,"Initialized file storage for cell 0x%016X ( %s )",
                       a_cell->id.uint64,a_cell->file_storage_path);
            }else{
                log_it(L_ERROR,"Can't init file storage for cell 0x%016X ( %s )",
                       a_cell->id.uint64,a_cell->file_storage_path);
                fclose(a_cell->file_storage);
                a_cell->file_storage = NULL;
            }
        }
    }
    if ( a_cell->file_storage ){
        dap_chain_t * l_chain = a_cell->chain;
        dap_chain_atom_iter_t *l_atom_iter = l_chain->callback_atom_iter_create (l_chain);
        dap_chain_atom_ptr_t *l_atom = l_chain->callback_atom_iter_get_first(l_atom_iter);
        size_t l_atom_size = l_chain->callback_atom_get_size(l_atom);
        while ( l_atom  && l_atom_size){
            if ( dap_chain_cell_file_append (a_cell,l_atom, l_atom_size) <0 )
                break;
            l_atom = l_chain->callback_atom_iter_get_next( l_atom_iter );
            l_atom_size = l_chain->callback_atom_get_size(l_atom);
        }
    }else {
            log_it (L_ERROR,"Can't write cell 0x%016X file \"%s\"",a_cell->id.uint64, a_cell->file_storage_path);
            return -1;
    }
    return 0;
}
