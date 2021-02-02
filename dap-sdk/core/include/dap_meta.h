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
typedef struct dap_meta{
    uint32_t value_length;
    byte_t name_n_value[]; // Name and value are splitted with terminated 0
} dap_meta_t;

dap_meta_t * dap_meta_create(const char * a_name,  const void * a_data, size_t a_data_size);
dap_meta_t* dap_meta_find(byte_t * a_data,  size_t a_data_size, const char * a_name);
int dap_meta_check(dap_meta_t * a_meta);

#define dap_meta_create_scalar(name,value) dap_meta_create (name, &value, sizeof(value) )
#define dap_meta_get_scalar(a,typeconv)  *((typeconv*) a->name_n_value + strlen(a->name_n_value)+1)

// NULL-terminated string
#define dap_meta_create_string(name,str) dap_meta_create (name,str, dap_strlen(str)+1)
#define dap_meta_get_string(a)  ( ((char*) a->name_n_value+ strlen((char*) a->name_n_value)+1)[a->value_length-1] == '\0'? (char*) a->name_n_value  : "<CORRUPTED STRING>" )
#define dap_meta_get_string_const(a)  ( ((const char*) a->name_n_value + strlen((char*) a->name_n_value)+1 )[a->value_length-1] == '\0'? (const char*) a->name_n_value : "<CORRUPTED STRING>" )

#define dap_meta_name(a)  ( ((char*) a->name_n_value+ strlen((char*) a->name_n_value)+1)[a->value_length-1] == '\0'? (char*) a->name_n_value  : "<CORRUPTED STRING>" )

#define dap_meta_size(a) (sizeof(*a)+a->value_length+ strlen((char*) a->name_n_value)+1)
