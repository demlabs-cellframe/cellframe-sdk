/*
* Authors:
* Alexey V. Stratulat <alexey.stratulat@demlabs.net>
* DeM Labs Inc.   https://demlabs.net
* DeM Labs Open source community https://gitlab.demlabs.net/cellframe/libdap-plugins-python
* Copyright  (c) 2017-2020
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

#include <stdbool.h>
#include "uthash.h"
#include "dap_config.h"

typedef struct dap_plugin_manifest{
    char name[64];
    char *version;
    char *author;
    char *description;


    char *type;             // Plugin type
    const char *path;       // Path to the directory
    dap_config_t * config;  // Config file

    // Dependencies
    struct dap_plugin_manifest_dependence *dependencies;  // Solved dependencies with links on same manifests
    char **dependencies_names; // String list of dependencies
    size_t dependencies_count; // Number of dependencies;

    // Additional params
    size_t params_count;
    char ** params;

    // Builtin plugin
    bool is_builtin; // Doesn't allow to unload if true

    // uthash handle
    UT_hash_handle hh;
}dap_plugin_manifest_t;

typedef struct dap_plugin_manifest_dependence{
    char name[64];
    dap_plugin_manifest_t * manifest;
    UT_hash_handle hh;
}dap_plugin_manifest_dependence_t;

int dap_plugin_manifest_init();
void dap_plugin_manifest_deinit();

dap_plugin_manifest_t* dap_plugin_manifest_all(void);
dap_plugin_manifest_t *dap_plugin_manifest_find(const char *a_name);

char* dap_plugin_manifests_get_list_dependencies(dap_plugin_manifest_t *a_element);

dap_plugin_manifest_t* dap_plugin_manifest_add_from_file(const char *a_file_path);
dap_plugin_manifest_t* dap_plugin_manifest_add_builtin(const char *a_name, const char * a_type,
                                                            const char * a_author, const char * a_version,
                                                            const char * a_description, char ** a_dependencies_names,
                                                            size_t a_dependencies_count, char ** a_params, size_t a_params_count);

bool dap_plugins_manifest_remove(const char *a_name);

#ifdef __cplusplus
}
#endif
