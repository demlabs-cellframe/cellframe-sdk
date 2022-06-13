/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Demlabs Ltd.   https://demlabs.net
 * Copyright  (c) 2022
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
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "uthash.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include "dap_chain_common.h"
#include "dap_time.h"

#define LOG_TAG "dap_global_db"

#include "dap_global_db.h"
#include "dap_chain_global_db_driver.h"

bool g_dap_global_db_debug_more = false;                                         /* Enable extensible debug output */

static uint32_t s_global_db_version = 0;
static int s_check_db_version();
static void s_check_db_version_callback_get (int a_errno, const char * a_group, const char * a_key, const void * a_value, const size_t a_value_len, void * a_arg);
static void s_check_db_version_callback_set (int a_errno, const char * a_group, const char * a_key, const void * a_value, const size_t a_value_len, void * a_arg);
static pthread_cond_t s_check_db_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t s_check_db_mutex = PTHREAD_MUTEX_INITIALIZER;
static int s_check_db_ret = 0;

static const char * s_storage_path = NULL;
static const char * s_driver_name = NULL;


/**
 * @brief dap_global_db_init
 * @param a_path
 * @param a_driver
 * @return
 */
int dap_global_db_init(const char * a_storage_path, const char * a_driver_name)
{
    int l_rc;
    static bool s_is_check_version = false;


    if ( a_storage_path == NULL && s_storage_path == NULL ){
        log_it(L_CRITICAL, "Can't initialize GlobalDB without storage path");
    }

    if ( a_driver_name == NULL && a_driver_name == NULL ){
        log_it(L_CRITICAL, "Can't initialize GlobalDB without driver name");
    }

    // For reinitialization it could be NULL but s_storage_path and s_driver_name have to be defined before

    if(a_storage_path)
        s_storage_path = dap_strdup(a_storage_path);

    if(a_driver_name)
        s_driver_name = dap_strdup(a_driver_name);

    // Debug config
    g_dap_global_db_debug_more = dap_config_get_item_bool(g_config, "global_db", "debug_more");


    // Driver initalization
    if( (l_rc = dap_db_driver_init(s_driver_name, s_storage_path, true))  )
        return  log_it(L_CRITICAL, "Hadn't initialized DB driver \"%s\" on path \"%s\", code: %d",
                       s_driver_name, s_storage_path, l_rc), l_rc;

    if(!s_is_check_version){

        s_is_check_version = true;

        if ( (l_rc = s_check_db_version()) )
            return  log_it(L_ERROR, "GlobalDB version changed, please export or remove old version!"), l_rc;
    }

    log_it(L_NOTICE, "GlobalDB initialized");

    l_rc = 0;
    return l_rc;
}

/**
 * @brief dap_global_db_deinit
 */
void dap_global_db_deinit()
{

}

/**
 * @brief s_check_db_version
 * @return
 */
static int s_check_db_version()
{
    int l_ret;
    pthread_mutex_lock(&s_check_db_mutex);
    l_ret = dap_global_db_get(DAP_GLOBAL_DB_LOCAL_GENERAL, "gdb_version",s_check_db_version_callback_get, NULL);
    if (l_ret == 0){
        pthread_cond_wait(&s_check_db_cond, &s_check_db_mutex);
        l_ret = s_check_db_ret;
    }
    pthread_mutex_unlock(&s_check_db_mutex);
    return l_ret;
}

/**
 * @brief s_check_db_version_callback_get
 * @details Notify callback on reading GlobalDB version
 * @param a_errno
 * @param a_group
 * @param a_key
 * @param a_value
 * @param a_value_len
 * @param a_arg
 */
static void s_check_db_version_callback_get (int a_errno, const char * a_group, const char * a_key, const void * a_value, const size_t a_value_len, void * a_arg)
{
    int res = 0;

    pthread_mutex_lock(&s_check_db_mutex); //    To be sure thats we're on pthread_cond_wait() line
    pthread_mutex_unlock(&s_check_db_mutex); //  in calling thread

    if(a_errno != 0){
        log_it(L_ERROR, "Can't process request for DB version, error code %d", a_errno);
        res = a_errno;
        goto lb_exit;
    }

    const char * l_value_str = (const char *) a_value;
    if(a_value_len>0 ){
        if(l_value_str[a_value_len-1]=='\0'){
            s_global_db_version = atoi(l_value_str);
        }
    }

    if( s_global_db_version < DAP_GLOBAL_DB_VERSION) {
        log_it(L_NOTICE, "GlobalDB version %u, but %u required. The current database will be recreated",
               s_global_db_version, DAP_GLOBAL_DB_VERSION);
        dap_global_db_deinit();
        // Database path
        const char *l_storage_path = dap_config_get_item_str(g_config, "resources", "dap_global_db_path");
        // Delete database
        if(dap_file_test(l_storage_path) || dap_dir_test(l_storage_path)) {
            // Backup filename: backup_global_db_ver.X_DATE_TIME.zip
            char now[255];
            time_t t = time(NULL);
            strftime(now, 200, "%y.%m.%d-%H_%M_%S", localtime(&t));
#ifdef DAP_BUILD_WITH_ZIP
            char *l_output_file_name = dap_strdup_printf("backup_%s_ver.%d_%s.zip", dap_path_get_basename(l_storage_path), l_gdb_version, now);
            char *l_output_file_path = dap_build_filename(l_storage_path, "../", l_output_file_name, NULL);
            // Create backup as ZIP file
            if(dap_zip_directory(l_storage_path, l_output_file_path)) {
#else
            char *l_output_file_name = dap_strdup_printf("backup_%s_ver.%d_%s.tar", dap_path_get_basename(s_storage_path), s_global_db_version, now);
            char *l_output_file_path = dap_build_filename(l_storage_path, "../", l_output_file_name, NULL);
            // Create backup as TAR file
            if(dap_tar_directory(l_storage_path, l_output_file_path)) {
#endif
                // Delete database file or directory
                dap_rm_rf(l_storage_path);
            }
            else {
                log_it(L_ERROR, "Can't backup GlobalDB version %d", s_global_db_version);
                res = -2;
                goto lb_exit;
            }
            DAP_DELETE(l_output_file_name);
            DAP_DELETE(l_output_file_path);
        }
        // Reinitialize database
        res = dap_global_db_init(NULL, NULL);
        // Save current db version
        if(!res) {
            s_global_db_version = DAP_GLOBAL_DB_VERSION;
            dap_global_db_set(DAP_GLOBAL_DB_LOCAL_GENERAL, "gdb_version", &s_global_db_version, sizeof(uint16_t),false,
                              s_check_db_version_callback_set, NULL);
            return; // In this case the condition broadcast should happens in s_check_db_version_callback_set()
        }
    } else if(s_global_db_version > DAP_GLOBAL_DB_VERSION) {
        log_it(L_ERROR, "GlobalDB version %d is newer than supported version %d", s_global_db_version, DAP_GLOBAL_DB_VERSION);
        res = -1;
        goto lb_exit;
    }
    else {
        log_it(L_NOTICE, "GlobalDB version %d", s_global_db_version);
    }
lb_exit:
    s_check_db_ret = res;
    pthread_cond_broadcast(&s_check_db_cond);
}

/**
 * @brief s_check_db_version_callback_set
 * @details GlobalDB version update callback
 * @param a_errno
 * @param a_group
 * @param a_key
 * @param a_value
 * @param a_value_len
 * @param a_arg
 */
static void s_check_db_version_callback_set (int a_errno, const char * a_group, const char * a_key, const void * a_value, const size_t a_value_len, void * a_arg)
{
    int l_res = 0;
    if(a_errno != 0){
        log_it(L_ERROR, "Can't process request for DB version, error code %d", a_errno);
        l_res = a_errno;
        goto lb_exit;
    }

    log_it(L_NOTICE, "GlobalDB version updated to %d", s_global_db_version);

lb_exit:
    s_check_db_ret = l_res;
    pthread_cond_broadcast(&s_check_db_cond);
}
