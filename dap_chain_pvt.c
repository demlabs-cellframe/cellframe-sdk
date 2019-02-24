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

/**
 * @brief dap_chain_pvt_file_load
 * @param a_chain
 * @return
 */
int dap_chain_pvt_cells_load( dap_chain_t * a_chain)
{
    DAP_CHAIN_PVT_LOCAL (a_chain);

    struct dirent *l_dir_entry;
    DIR * l_dir_fd = opendir( l_chain_pvt->file_storage_dir );
    if( l_dir_fd != NULL ) {
        while( l_dir_entry = readdir( l_dir_fd ) ){
            char * l_entry_name = strdup(l_dir_entry->d_name);

            size_t l_chains_path_size = strlen(l_chain_pvt->file_storage_dir)+1+strlen("network")+1;
            l_chains_path = DAP_NEW_Z_SIZE(char, l_chains_path_size);

            if (strlen (l_entry_name) > 4 ){ // It has non zero name excluding file extension
                if ( strncmp (l_entry_name+ strlen(l_entry_name)-4,".cfg",4) == 0 ) { // its .cfg file
                    l_entry_name [strlen(l_entry_name)-4] = 0;
                    log_it(L_DEBUG,"Open chain config \"%s\"...",l_entry_name);
                    snprintf(l_chains_path,l_chains_path_size,"network/%s/%s",l_net->pub.name,l_entry_name);
                    //dap_config_open(l_chains_path);

                    // Create chain object
                    dap_chain_t * l_chain = dap_chain_load_from_cfg(l_net->pub.name,l_entry_name);
                    DL_APPEND( l_net->pub.chains, l_chain);
                    free(l_entry_name);
                }
            }
            DAP_DELETE (l_chains_path);
        }
        closedir(dfd);
    }



}

/**
 * @brief dap_chain_pvt_file_save
 * @param a_chain
 * @return
 */


/**
 * @brief dap_chain_pvt_file_update
 * @param a_chain
 * @return
 */
int dap_chain_pvt_cells_update( dap_chain_t * a_chain)
{
   return 0;
}
