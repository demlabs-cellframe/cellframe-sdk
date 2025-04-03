/*
* Authors:
* Alexey V. Stratulat <alexey.stratulat@demlabs.net>
* Dmitriy Gerasimov <dmitriy.gerasimov@demlabs.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2022
* All rights reserved.

This file is part of DAP (Distributed Applications Platform) the open source project

   DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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

#pragma once

#ifdef __cplusplus
extern "C"{
#endif

#include "dap_config.h"
#include "dap_plugin_manifest.h"

typedef int (*dap_plugin_type_callback_load_t)(dap_plugin_manifest_t * a_manifest, void ** a_pvt_data, char ** a_error_str );
typedef int (*dap_plugin_type_callback_unload_t)(dap_plugin_manifest_t * a_manifest, void * a_pvt_data, char ** a_error_str );

typedef struct dap_plugin_type_callbacks
{
    dap_plugin_type_callback_load_t load;
    dap_plugin_type_callback_unload_t unload;
} dap_plugin_type_callbacks_t;
typedef enum dap_plugin_status{ STATUS_RUNNING, STATUS_STOPPED, STATUS_NONE } dap_plugin_status_t;

int dap_plugin_init(const char * a_root_path);
void dap_plugin_deinit();

int dap_plugin_type_create(const char* a_name, dap_plugin_type_callbacks_t *a_callbacks);
void dap_plugin_start_all();
void dap_plugin_stop_all();
dap_plugin_status_t dap_plugin_status(const char * a_name);
int dap_plugin_stop(const char * a_name);
int dap_plugin_start(const char * a_name);

#ifdef __cplusplus
}
#endif
