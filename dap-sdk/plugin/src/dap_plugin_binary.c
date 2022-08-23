/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe  https://cellframe.net
 * Copyright  (c) 2022
 * All rights reserved.

 This file is part of Cellframe SDK

 Cellframe SDK is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Cellframe SDK is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any Cellframe SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dap_strfuncs.h"
#if defined(DAP_OS_UNIX)
#include <dlfcn.h>
#endif

#include <assert.h>
#include "dap_plugin.h"
#include "dap_plugin_binary.h"
#include "dap_plugin_manifest.h"

#define LOG_TAG "dap_plugin_binary"

typedef int (*plugin_init_callback_t)(dap_config_t * a_plugin_config, char ** a_error_str);
typedef void (*plugin_deinit_callback_t)(void);

static dap_plugin_manifest_t * s_manifest = NULL; // Own manifest

static int s_type_callback_load(dap_plugin_manifest_t * a_manifest, void ** a_pvt_data, char ** a_error_str );
static int s_type_callback_unload(dap_plugin_manifest_t * a_manifest, void * a_pvt_data, char ** a_error_str );

struct binary_pvt_data{
    void *handle;
    plugin_init_callback_t callback_init;
    plugin_deinit_callback_t callback_deinit;
};

/**
 * @brief dap_plugin_binary_init
 * @return
 */
int dap_plugin_binary_init()
{
    dap_plugin_type_callbacks_t l_callbacks={};
    l_callbacks.load = s_type_callback_load;
    l_callbacks.unload = s_type_callback_unload;
    dap_plugin_type_create("binary",&l_callbacks);
    s_manifest = dap_plugin_manifest_add_builtin("binary", "binary", "Demlabs Inc", "1.0","Binary shared library loader",NULL,0,NULL,0);
    return 0;
}

/**
 * @brief dap_plugin_binary_deinit
 */
void dap_plugin_binary_deinit()
{

}

/**
 * @brief s_type_callback_load
 * @param a_manifest
 * @param a_pvt_data
 * @param a_error_str
 * @return
 */
static int s_type_callback_load(dap_plugin_manifest_t * a_manifest, void ** a_pvt_data, char ** a_error_str )
{
    assert(a_pvt_data);
    if(a_manifest == s_manifest) // Its our own manifest, do nothing we're already loaded
        return 0;
    struct binary_pvt_data * l_pvt_data= DAP_NEW_Z(struct binary_pvt_data);
    *a_pvt_data = l_pvt_data;
#if defined (DAP_OS_UNIX) && !defined (__ANDROID__)

#if defined (DAP_OS_DARWIN)
    char * l_path = dap_strdup_printf("%s/%s.darwin.%s.dylib",a_manifest->path,a_manifest->name,dap_get_arch());
#elif defined (DAP_OS_LINUX)
    char * l_path = dap_strdup_printf("%s/lib%s.linux.common.%s.so",a_manifest->path,a_manifest->name,dap_get_arch());
#endif
    l_pvt_data->handle = dlopen(l_path, RTLD_NOW | RTLD_GLOBAL); // Try with specified architecture first
    if(l_pvt_data->handle){
        l_pvt_data->callback_init = dlsym(l_pvt_data->handle, "plugin_init");
        l_pvt_data->callback_deinit = dlsym(l_pvt_data->handle, "plugin_deinit");
    }else{
        log_it(L_ERROR,"Can't load %s module: %s (expected path %s)", a_manifest->name, l_path, dlerror());
        *a_error_str = dap_strdup_printf("Can't load %s module: %s (expected path %s)", a_manifest->name, l_path, dlerror());
        return -5;
    }
#endif
    if( l_pvt_data->callback_init){
        return l_pvt_data->callback_init(a_manifest->config,a_error_str);
    }else{
        log_it(L_ERROR,"No \"plugin_init\" entry point in binary plugin") ;
        *a_error_str = dap_strdup("No \"plugin_init\" entry point in binary plugin");
        DAP_DELETE(l_pvt_data);
        return -5;
    }
}

/**
 * @brief s_type_callback_unload
 * @param a_manifest
 * @param a_pvt_data
 * @param a_error_str
 * @return
 */
static int s_type_callback_unload(dap_plugin_manifest_t * a_manifest, void * a_pvt_data, char ** a_error_str )
{
    if(a_manifest == s_manifest) // Its our own manifest, do nothing we're can't be unloaded
        return 0;
    struct binary_pvt_data * l_pvt_data = (struct binary_pvt_data *) a_pvt_data;
    assert(l_pvt_data);
    if(l_pvt_data->callback_deinit)
        l_pvt_data->callback_deinit();
#if defined (DAP_OS_UNIX) && !defined (__ANDROID__)
    dlclose(l_pvt_data->handle);
#endif
    return 0;
}
