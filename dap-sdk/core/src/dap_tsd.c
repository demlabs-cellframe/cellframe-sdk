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
#include "dap_tsd.h"
#define LOG_TAG "dap_tsd"

/**
 * @brief dap_tsd_create
 * @param a_type
 * @param a_data
 * @param a_data_size
 * @return
 */
dap_tsd_t * dap_tsd_create(uint16_t a_type, const void * a_data, size_t a_data_size)
{
    dap_tsd_t * l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, sizeof(dap_tsd_t) + a_data_size );
    if ( l_tsd ){
        if (a_data && a_data_size)
            memcpy(l_tsd->data, a_data , a_data_size );
        l_tsd->type = a_type;
        l_tsd->size = a_data_size;
    }
    return l_tsd;

}

/**
 * @brief dap_tsd_find
 * @param a_data
 * @param a_data_size
 * @param a_typeid
 * @return
 */
dap_tsd_t* dap_tsd_find(byte_t * a_data, size_t a_data_size,uint16_t a_type)
{
    dap_tsd_t * l_ret = NULL;
    for(size_t l_offset=0; l_offset<a_data_size; ){
        dap_tsd_t * l_tsd =(dap_tsd_t*) (a_data + l_offset);
        size_t l_tsd_size = dap_tsd_size(l_tsd);
        if( !l_tsd_size || l_tsd_size +l_offset > a_data_size){
            break;
        }

        if ( l_tsd->type == a_type ){
            l_ret = l_tsd;
            break;
        }

        l_offset+=l_tsd_size;
    }
    return l_ret;

}
