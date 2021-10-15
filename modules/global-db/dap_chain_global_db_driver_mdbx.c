/*
 * Authors:
 * Gerasimov Dmitriy <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2021
 * All rights reserved.

 This file is part of DAP SDK the open source project

 DAP SDK is free software: you can redistribute it and/or modify
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

#include <stddef.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>
#include <uthash.h>
#define _GNU_SOURCE

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"

#include "dap_chain_global_db_driver_mdbx.h"

#ifdef DAP_CHAIN_GDB_ENGINE_MDBX

#define LOG_TAG "dap_chain_global_db_mdbx"

static char *s_cdb_path = NULL;
static int s_driver_callback_deinit();
static int s_driver_callback_flush(void);
static int s_driver_callback_apply_store_obj(pdap_store_obj_t a_store_obj);
static dap_store_obj_t *s_driver_callback_read_last_store_obj(const char* a_group);
static bool s_driver_callback_is_obj(const char *a_group, const char *a_key);
static dap_store_obj_t *s_driver_callback_read_store_obj(const char *a_group, const char *a_key, size_t *a_count_out);
static dap_store_obj_t* s_driver_callback_read_cond_store_obj(const char *a_group, uint64_t a_id, size_t *a_count_out);
static size_t s_driver_callback_read_count_store(const char *a_group, uint64_t a_id);
static dap_list_t* s_driver_callback_get_groups_by_mask(const char *a_group_mask);

/**
 * @brief dap_db_driver_mdbx_init
 * @param a_cdb_path
 * @param a_drv_callback
 * @return
 */
int dap_db_driver_mdbx_init(const char *a_cdb_path, dap_db_driver_callbacks_t *a_drv_callback)
{
    s_cdb_path = dap_strdup(a_cdb_path);
    if(s_cdb_path[strlen(s_cdb_path)] == '/') {
        s_cdb_path[strlen(s_cdb_path)] = '\0';
    }
    dap_mkdir_with_parents(s_cdb_path);
    struct dirent *d;
    DIR *dir = opendir(s_cdb_path);
    if (!dir) {
        log_it(L_ERROR, "Couldn't open db directory");
        return -1;
    }
    for (d = readdir(dir); d; d = readdir(dir)) {
#ifdef _DIRENT_HAVE_D_TYPE
        if (d->d_type != DT_DIR)
            continue;
#else
        struct _stat buf;
        int res = _stat(d->d_name, &buf);
        if (!S_ISDIR(buf.st_mode) || !res) {
            continue;
        }
#endif
        if (!dap_strcmp(d->d_name, ".") || !dap_strcmp(d->d_name, "..")) {
            continue;
        }
        if (0) {
            s_driver_callback_deinit();
            closedir(dir);
            return -2;
        }
    }
    a_drv_callback->read_last_store_obj = s_driver_callback_read_last_store_obj;
    a_drv_callback->apply_store_obj     = s_driver_callback_apply_store_obj;
    a_drv_callback->read_store_obj      = s_driver_callback_read_store_obj;
    a_drv_callback->read_cond_store_obj = s_driver_callback_read_cond_store_obj;
    a_drv_callback->read_count_store    = s_driver_callback_read_count_store;
    a_drv_callback->get_groups_by_mask  = s_driver_callback_get_groups_by_mask;
    a_drv_callback->is_obj              = s_driver_callback_is_obj;
    a_drv_callback->deinit              = s_driver_callback_deinit;
    a_drv_callback->flush               = s_driver_callback_flush;

    closedir(dir);
    return 0;
}

/**
 * @brief s_driver_callback_deinit
 * @return
 */
static int s_driver_callback_deinit()
{
    return 0;
}

/**
 * @brief s_driver_callback_flush
 * @return
 */
static int s_driver_callback_flush(void)
{
    int ret = 0;
    log_it(L_DEBUG, "Flushing MDBX on the disk");
    return ret;
}

/**
 * @brief s_driver_callback_read_last_store_obj
 * @param a_group
 * @return
 */
static dap_store_obj_t *s_driver_callback_read_last_store_obj(const char* a_group)
{
    return NULL;
}

/**
 * @brief s_driver_callback_is_obj
 * @param a_group
 * @param a_key
 * @return
 */
static bool s_driver_callback_is_obj(const char *a_group, const char *a_key)
{
    return false;
}

/**
 * @brief s_driver_callback_read_store_obj
 * @param a_group
 * @param a_key
 * @param a_count_out
 * @return
 */
static dap_store_obj_t *s_driver_callback_read_store_obj(const char *a_group, const char *a_key, size_t *a_count_out)
{
    return NULL;
}

/**
 * @brief s_driver_callback_read_cond_store_obj
 * @param a_group
 * @param a_id
 * @param a_count_out
 * @return
 */
static dap_store_obj_t* s_driver_callback_read_cond_store_obj(const char *a_group, uint64_t a_id, size_t *a_count_out)
{
    return NULL;
}

/**
 * @brief s_driver_callback_read_count_store
 * @param a_group
 * @param a_id
 * @return
 */
static size_t s_driver_callback_read_count_store(const char *a_group, uint64_t a_id)
{
    return 0;
}

/**
 * @brief s_driver_callback_get_groups_by_mask
 * @details Check whether the groups match the pattern a_group_mask, which is a shell wildcard pattern
 * @param a_group_mask
 * @return
 */
static dap_list_t* s_driver_callback_get_groups_by_mask(const char *a_group_mask)
{
    return NULL;
}

/**
 * @brief s_driver_callback_apply_store_obj
 * @param a_store_obj
 * @return
 */
static int s_driver_callback_apply_store_obj(pdap_store_obj_t a_store_obj)
{
    if(!a_store_obj || !a_store_obj->group) {
        return -1;
    }
    int ret = 0;
    return ret;
}

#endif
