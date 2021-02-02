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
#include "dap_strfuncs.h"
typedef struct dap_tsd{
    uint16_t type;
    uint32_t size;
    byte_t data[];
} dap_tsd_t;

dap_tsd_t * dap_tsd_create(uint16_t a_type,  const void * a_data, size_t a_data_size);
dap_tsd_t* dap_tsd_find(byte_t * a_data, size_t a_data_size,uint16_t a_type);

#define dap_tsd_create_scalar(type,value) dap_tsd_create (type, &value, sizeof(value) )
#define dap_tsd_get_scalar(a,typeconv)  *((typeconv*) a->data)

// NULL-terminated string
#define dap_tsd_create_string(type,str) dap_tsd_create (type,str, dap_strlen(str)+1)
#define dap_tsd_get_string(a)  ( ((char*) a->data )[a->size-1] == '\0'? (char*) a->data  : "<CORRUPTED STRING>" )
#define dap_tsd_get_string_const(a)  ( ((const char*) a->data )[a->size-1] == '\0'? (const char*) a->data : "<CORRUPTED STRING>" )

#define dap_tsd_size(a) (sizeof(*a)+a->size)
