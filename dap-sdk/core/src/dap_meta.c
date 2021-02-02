/* Authors:
* Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
* Demlabs Ltd   https://demlabs.net
* DAP SDK  https://gitlab.demlabs.net/dap/dap-sdk
* Copyright  (c) 2021
* All rights reserved.

This file is part of DAP SDK the open source project

   DAP SDK is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   DAP SDK is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "dap_meta.h"

#define LOG_TAG "dap_meta"

/**
 * @brief dap_meta_create
 * @param a_name
 * @param a_data
 * @param a_data_size
 * @return
 */
dap_meta_t * dap_meta_create(const char * a_name,  const void * a_data, size_t a_data_size)
{
    if ( !a_name)
        return NULL;
    size_t a_name_len = strlen(a_name);

    if( ! a_name_len )
        return NULL;

    dap_meta_t * l_ret = DAP_NEW_Z_SIZE(dap_meta_t, sizeof (dap_meta_t)+a_name_len+1+a_data_size );
    if (l_ret){
        memcpy(l_ret->name_n_value,a_name,a_name_len);
        if(a_data_size)
            memcpy(l_ret->name_n_value+a_name_len+1,a_data,a_data_size);
    }
    return l_ret;
}

/**
 * @brief dap_meta_find
 * @param a_data
 * @param a_data_size
 * @param a_name
 * @return
 */
dap_meta_t* dap_meta_find(byte_t * a_data,  size_t a_data_size, const char * a_name)
{
    dap_meta_t * l_ret = NULL;
    for(size_t l_offset=0; l_offset<a_data_size; ){
        dap_meta_t * l_meta =(dap_meta_t*) (a_data + l_offset);
        size_t l_meta_size = dap_meta_size(l_meta);
        if( !l_meta_size || l_meta_size +l_offset > a_data_size){
            break;
        }

        if (strcmp( dap_meta_name(l_meta), a_name) == 0 ){
            l_ret = l_meta;
            break;
        }

        l_offset+=l_meta_size;
    }
    return l_ret;
}

/**
 * @brief dap_meta_check
 * @param a_meta
 * @return
 */
int dap_meta_check(dap_meta_t * a_meta)
{
    return -1;
}
