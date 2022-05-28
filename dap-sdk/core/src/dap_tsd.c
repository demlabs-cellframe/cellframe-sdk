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

#include <errno.h>
#include "dap_tsd.h"
#define LOG_TAG "dap_tsd"


/*
 *  DESCRIPTION: Encapsulate TSD/TLV into the given buffer
 *
 *  INPUTS:
 *      a_type:     Type/Tag for the new TSD element
 *      a_data:     A data buffer to be inserted
 *      a_data_size:A size of the data buffer
 *      a_dst_sz:   A size of the output buffer
 *
 *  OUTPUTS:
 *      a_dst:      A buffer with the has been formed TSD
 *
 *  RETURNS:
 *      -ENOMEM:    No space in the output buffer
 *      0+ :        A size of the whole TSD (header + data)
*/

size_t  dap_tsd_put(uint16_t a_type, const void * a_data, size_t a_data_size,
                    void *a_dst, size_t a_dst_sz
                    )
{
dap_tsd_t   *l_tsd;

    assert ( a_data );
    assert ( (l_tsd = (dap_tsd_t *) a_dst) );


    if ( a_dst_sz < (a_data_size + sizeof(dap_tsd_t)) )                     /* Check a space for new TSD/TLV in the output buffer */
        return  log_it(L_ERROR, "No space for TSD, %d < %d", a_dst_sz, (a_data_size + sizeof(dap_tsd_t)) ), -ENOMEM;

    l_tsd->type = a_type;
    memcpy(l_tsd->data, a_data , l_tsd->size = (uint32_t) a_data_size );

    return (a_data_size + sizeof(dap_tsd_t));
}



/*
 *  DESCRIPTION: Retrieve TSD's attributes from the buffer
 *
 *  INPUTS:
 *      a_src:          A source buffer with the TSD to be processed
 *      a_src_sz:       A size of the source buffer
 *      a_data_size:    A size of the buffer to accept TSD's value
 *
 *  OUTPUTS:
 *      a_type:         A TSD's type/tag
 *      a_data:         A TSD's value has been exctracted from the TSD
 *      a_data_size:    A size of the value
 *
 *  RETURNS:
 *      -EINVAL:        A value size of the TSD is out of source buffer
 *      -ENOMEM:        A value's buffer size is too small
 *      0:              No data processed, may be source buffer is empty
 *      0+:             A size of the whole TSD has been processed
 */
size_t  dap_tsd_get(void *a_src, size_t a_src_sz,
                    uint16_t *a_type, void *a_data, size_t *a_data_size
                    )
{
dap_tsd_t   *l_tsd = a_src;

    if ( a_src_sz )
        return  0;                                                          /* Nothing to do */


    assert ( a_data );
    assert ( (l_tsd = (dap_tsd_t *) a_src) );

    if ( l_tsd->size > (a_src_sz - sizeof(dap_tsd_t)) )
        return  log_it(L_ERROR, "TSD's data size is out of the source buffer, %d > %d",
                       l_tsd->size, (a_src_sz - sizeof(dap_tsd_t))), -EINVAL;


    if ( *a_data_size < l_tsd->size )                                     /* Check a space for TSD's value */
        return  log_it(L_ERROR, "No space for TSD's value, %d < %d", *a_data_size, l_tsd->size ), -ENOMEM;

    *a_type = l_tsd->type;
    memcpy(a_data, l_tsd->data,*a_data_size =  l_tsd->size );

    return (*a_data_size + sizeof(dap_tsd_t));
}




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
dap_tsd_t* dap_tsd_find(byte_t *a_data, size_t a_data_size, uint16_t a_type)
{
dap_tsd_t *l_tsd;
size_t l_tsd_size;

    for(size_t l_offset = 0; l_offset < a_data_size; l_offset += l_tsd_size )
    {
        l_tsd = (dap_tsd_t*) (a_data + l_offset);
        l_tsd_size = dap_tsd_size(l_tsd);

        if ( !l_tsd_size || l_tsd_size + l_offset > a_data_size)
            return  NULL;

        if ( l_tsd->type == a_type )
            return  l_tsd;
    }

    return  NULL;
}
