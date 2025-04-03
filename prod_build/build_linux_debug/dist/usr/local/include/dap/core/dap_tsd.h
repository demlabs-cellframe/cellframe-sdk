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
#pragma once
#include "dap_common.h"
#include "dap_list.h"

typedef struct dap_tsd {
    uint16_t type;
    uint32_t size;
    byte_t data[];
} DAP_ALIGN_PACKED dap_tsd_t;

byte_t     *dap_tsd_write   (byte_t *a_ptr, uint16_t a_type, const void *a_data, size_t a_data_size);
dap_tsd_t  *dap_tsd_create  (uint16_t a_type, const void *a_data, size_t a_data_size);
dap_tsd_t  *dap_tsd_find    (byte_t *a_data, size_t a_data_size, uint16_t a_type);
dap_list_t *dap_tsd_find_all(byte_t *a_data, size_t a_data_size, uint16_t a_type);

#define dap_tsd_create_scalar(type,value) dap_tsd_create(type, &value, sizeof(value))
#define dap_tsd_get_scalar(a,typeconv) ( a->size >= sizeof(typeconv) ? *((typeconv*) a->data) : (typeconv) {0})
#define dap_tsd_get_object(a,typeconv) ( a->size >= sizeof(typeconv) ? ((typeconv*) a->data) : (typeconv *) {0})

#define _dap_tsd_get_scalar(tsd,dest) ({ tsd->size >= sizeof(*dest) ? memcpy(dest, tsd->data, sizeof(*dest)) : NULL; *dest; })
#define _dap_tsd_get_object(tsd,desttype) ( tsd->size >= sizeof(desttype) ? (desttype*)tsd->data : NULL )

#define DAP_TSD_CORRUPTED_STRING "<CORRUPTED STRING>"
// NULL-terminated string
#define dap_tsd_create_string(type,str) dap_tsd_create(type, str, dap_strlen(str) + 1)
#define dap_tsd_get_string(a)  ( ((char*) a->data )[a->size-1] == '\0'? (char*) a->data  : DAP_TSD_CORRUPTED_STRING )
#define dap_tsd_get_string_const(a)  ( ((const char*) a->data )[a->size-1] == '\0'? (const char*) a->data : DAP_TSD_CORRUPTED_STRING )

#define dap_tsd_size(a) ((uint64_t)sizeof(dap_tsd_t) + (a)->size)

#define dap_tsd_size_check(a, offset, total_size) ( (total_size) - (offset) >= dap_tsd_size(a) && (total_size) - (offset) <= (total_size) )

#define dap_tsd_iter(iter, iter_size, data, total_size)                                                                     \
    for (   byte_t *l_pos = (byte_t*)(data), *l_end = l_pos + (total_size) > l_pos ? l_pos + (total_size) : l_pos;          \
            !!( iter = l_pos < l_end - sizeof(dap_tsd_t) && l_pos <= l_end - (iter_size = dap_tsd_size((dap_tsd_t*)l_pos))  \
                ? (dap_tsd_t*)l_pos : NULL);                                                                                \
            l_pos += iter_size                                                                                              \
        )
