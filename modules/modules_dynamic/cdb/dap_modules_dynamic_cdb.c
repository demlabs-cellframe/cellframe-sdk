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

#define LOG_TAG "dap_modules_dynamic"

static const char * s_default_path_modules = "var/modules";
static void *s_cdb_handle = NULL;
static bool s_cdb_was_init = false;

void dap_modules_dynamic_close_cdb()
{
    if (s_cdb_handle) {
        dlclose(s_cdb_handle);
        s_cdb_handle = NULL;
    }
    s_cdb_was_init = false;
}

void *dap_modules_dynamic_get_cdb_func(const char *a_func_name)
{
    if (!s_cdb_was_init)
        return NULL;
    char l_lib_path[MAX_PATH] = {'\0'};
    void *l_ref_func = NULL;
    //  find func from dynamic library
#if defined (DAP_OS_LINUX) && !defined (__ANDROID__)
    const char * l_cdb_so_name = "libcellframe-node-cdb.so";
    if (!s_cdb_handle) {
        dap_sprintf(l_lib_path, "%s/%s/%s", g_sys_dir_path, s_default_path_modules, l_cdb_so_name);

        s_cdb_handle = dlopen(l_lib_path, RTLD_NOW);
        if (!s_cdb_handle) {
            log_it(L_ERROR,"Can't load %s module: %s", l_cdb_so_name, dlerror());
            return NULL;
        }
    }

    l_ref_func = dlsym(s_cdb_handle, a_func_name);

    if (!l_ref_func) {
        log_it(L_ERROR,"%s module: %s error loading (%s)", l_cdb_so_name, a_func_name, dlerror());
        return NULL;
    }
#else
    log_it(L_ERROR,"%s: module is not supported on current platfrom", __PRETTY_FUNCTION__);
#endif
    return l_ref_func;
}

int dap_modules_dynamic_load_cdb(dap_http_t * a_server)
{
    s_cdb_was_init = true;
    int (*dap_chain_net_srv_vpn_cdb_init)(dap_http_t *);
    dap_chain_net_srv_vpn_cdb_init = dap_modules_dynamic_get_cdb_func("dap_chain_net_srv_vpn_cdb_init");
    if (!dap_chain_net_srv_vpn_cdb_init) {
        s_cdb_was_init = false;
        log_it(L_ERROR, "dap_modules_dynamic: dap_chain_net_srv_vpn_cdb_init not found");
        return -2;
    }
    int l_init_res = dap_chain_net_srv_vpn_cdb_init(a_server);
    if (l_init_res) {
        s_cdb_was_init = false;
        log_it(L_ERROR, "dap_modules_dynamic: dap_chain_net_srv_vpn_cdb_init returns %d", l_init_res);
        return -3;
    }
    s_cdb_was_init = true;
    return 0;
}
