/*
 * Authors:
 * Aleksei I. Voronin <aleksei.voronin@demlabs.net>
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

#include "dap_modules_dynamic_cdb.h"
#include "dap_common.h"

#ifdef DAP_OS_LINUX
#include <dlfcn.h>
#endif

#define LOG_TAG "dap_http"

static const char * s_default_path_modules = "var/modules";

int dap_modules_dynamic_load_cdb(dap_http_t * a_server){
    char l_lib_path[MAX_PATH] = {'\0'};
#if defined (DAP_OS_LINUX) && !defined (__ANDROID__)
    const char * l_cdb_so_name = "libcellframe-node-cdb.so";
    dap_sprintf(l_lib_path, "%s/%s/%s", g_sys_dir_path, s_default_path_modules, l_cdb_so_name);

    void* l_cdb_handle = NULL;
    l_cdb_handle = dlopen(l_lib_path, RTLD_NOW);
    if(!l_cdb_handle){
        log_it(L_ERROR,"Can't load %s module: %s", l_cdb_so_name, dlerror());
        return -1;
    }

    int (*dap_chain_net_srv_vpn_cdb_init)(dap_http_t*);
    const char * l_init_func_name = "dap_chain_net_srv_vpn_cdb_init";
    *(void **) (&dap_chain_net_srv_vpn_cdb_init) = dlsym(l_cdb_handle, l_init_func_name);
    char* error;
    if (( error = dlerror()) != NULL) {
        log_it(L_ERROR,"%s module: %s error loading (%s)", l_cdb_so_name, l_init_func_name, error);
        return -2;
     }

    int l_init_res = (*dap_chain_net_srv_vpn_cdb_init)(a_server);
    if(l_init_res){
        log_it(L_ERROR,"%s: %s returns %d", l_cdb_so_name, l_init_func_name, error);
        return -3;
    }

    return 0;
#else
    log_it(L_ERROR,"%s: module is not supported on current platfrom", __PRETTY_FUNCTION__);
    return -3;
#endif
}
