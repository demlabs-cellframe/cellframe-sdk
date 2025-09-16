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
#pragma once

#include "dap_common.h"
#include "dap_enc_key.h"
#include "dap_time.h"
#include "dap_global_db_driver.h"

#define DAP_GLOBAL_DB_VERSION               3
#define DAP_GLOBAL_DB_LOCAL_GENERAL         "local.general"
#define DAP_GLOBAL_DB_LOCAL_LAST_HASH       "local.lasthash"
#define DAP_GLOBAL_DB_SYNC_WAIT_TIMEOUT     5 // seconds

typedef struct dap_global_db_cluster dap_global_db_cluster_t;

// Global DB instance with settings data
typedef struct dap_global_db_instance {
    uint32_t version;     // Current GlobalDB version
    char *storage_path;   // GlobalDB storage path
    char *driver_name;    // GlobalDB driver name
    dap_list_t *whitelist;
    dap_list_t *blacklist;
    uint64_t store_time_limit;
    dap_global_db_cluster_t *clusters;
    dap_enc_key_t *signing_key;
    uint32_t sync_idle_time;
} dap_global_db_instance_t;

typedef struct dap_global_db_obj {
    char *key;
    uint8_t *value;
    size_t value_len;
    dap_nanotime_t timestamp;
    bool is_pinned;
} dap_global_db_obj_t;

typedef void (*dap_global_db_callback_t)(dap_global_db_instance_t *a_dbi, void * a_arg);

/**
 *  @brief callback for single result
 *  @arg a_rc DAP_GLOBAL_DB_RC_SUCCESS if success others if not
 */
typedef void (*dap_global_db_callback_result_t)(dap_global_db_instance_t *a_dbi, int a_rc, const char *a_group, const char * a_key, const void * a_value,
                                                 const size_t a_value_size, dap_nanotime_t a_value_ts, bool a_is_pinned, void * a_arg);

/**
 *  @brief callback for single raw result
 *  @arg a_rc DAP_GLOBAL_DB_RC_SUCCESS if success others if not
 *  @return none.
 */
typedef void (*dap_global_db_callback_result_raw_t)(dap_global_db_instance_t *a_dbi, int a_rc, dap_store_obj_t * a_store_obj, void * a_arg);


/**
 *  @brief callback for multiple result, with pagination
 *  @arg a_rc DAP_GLOBAL_DB_RC_SUCCESS if success others if not
 *  @arg a_values_total Total values number
 *  @arg a_values_shift Current shift from beginning of values set
 *  @arg a_values_count Current number of items in a_values
 *  @arg a_values Current items (page of items)
 *  @arg a_arg Custom argument
 *  @return none.
 */
typedef bool (*dap_global_db_callback_results_t)(dap_global_db_instance_t *a_dbi,
                                                  int a_rc, const char *a_group,
                                                  const size_t a_values_total, const size_t a_values_count,
                                                  dap_global_db_obj_t *a_values, void *a_arg);
/**
 *  @brief callback for multiple raw result, with pagination
 *  @arg a_rc DAP_GLOBAL_DB_RC_SUCCESS if success other sif not
 *  @arg a_values_total Total values number
 *  @arg a_values_shift Current shift from beginning of values set
 *  @arg a_values_count Current number of items in a_values
 *  @arg a_values Current items (page of items)
 *  @return none.
 */
typedef bool (*dap_global_db_callback_results_raw_t) (dap_global_db_instance_t *a_dbi,
                                                      int a_rc, const char *a_group,
                                                      const size_t a_values_current, const size_t a_values_count,
                                                      dap_store_obj_t *a_values, void *a_arg);
// Return codes
#define DAP_GLOBAL_DB_RC_SUCCESS     0
#define DAP_GLOBAL_DB_RC_NOT_FOUND   1
#define DAP_GLOBAL_DB_RC_PROGRESS    2
#define DAP_GLOBAL_DB_RC_NO_RESULTS -1
#define DAP_GLOBAL_DB_RC_CRITICAL   -3
#define DAP_GLOBAL_DB_RC_ERROR      -6

extern int g_dap_global_db_debug_more;

int dap_global_db_init();
void dap_global_db_deinit();

void dap_global_db_instance_deinit();
dap_global_db_instance_t *dap_global_db_instance_get_default();

// For context unification sometimes we need to exec inside GlobalDB context
int dap_global_db_context_exec(dap_global_db_callback_t a_callback, void * a_arg);

// Copy global_db_obj array
dap_global_db_obj_t *dap_global_db_objs_copy(const dap_global_db_obj_t *a_objs_src, size_t a_count);

// Clear global_db_obj array
void dap_global_db_objs_delete(dap_global_db_obj_t *a_objs, size_t a_count);

// === Async functions ===
int dap_global_db_get(const char *a_group, const char *a_key,dap_global_db_callback_result_t a_callback, void *a_arg);
int dap_global_db_get_raw(const char *a_group, const char *a_key,dap_global_db_callback_result_raw_t a_callback, void *a_arg);

int dap_global_db_get_del_ts(const char *a_group, const char *a_key,dap_global_db_callback_result_t a_callback, void *a_arg);
int dap_global_db_get_last(const char *a_group, dap_global_db_callback_result_t a_callback, void *a_arg);
int dap_global_db_get_last_raw(const char *a_group, dap_global_db_callback_result_raw_t a_callback, void *a_arg);
int dap_global_db_get_all(const char *a_group, size_t l_results_page_size, dap_global_db_callback_results_t a_callback, void *a_arg);
int dap_global_db_get_all_raw(const char *a_group, size_t l_results_page_size, dap_global_db_callback_results_raw_t a_callback, void *a_arg);

int dap_global_db_set(const char *a_group, const char *a_key, const void * a_value, const size_t a_value_length, bool a_pin_value, dap_global_db_callback_result_t a_callback, void *a_arg);
int dap_global_db_set_raw(dap_store_obj_t *a_store_objs, size_t a_store_objs_count, dap_global_db_callback_results_raw_t a_callback, void *a_arg);

int dap_global_db_pin(const char *a_group, const char *a_key, dap_global_db_callback_result_t a_callback, void *a_arg);
int dap_global_db_unpin(const char *a_group, const char *a_key, dap_global_db_callback_result_t a_callback, void *a_arg);
int dap_global_db_del(const char *a_group, const char *a_key, dap_global_db_callback_result_t a_callback, void *a_arg);
int dap_global_db_flush( dap_global_db_callback_result_t a_callback, void *a_arg);

// Set multiple. In callback writes total processed objects to a_values_total and a_values_count to the a_values_count as well
int dap_global_db_set_multiple_zc(const char *a_group, dap_global_db_obj_t * a_values, size_t a_values_count, dap_global_db_callback_results_t a_callback, void *a_arg);

// === Sync functions ===
byte_t *dap_global_db_get_sync(const char *a_group, const char *a_key, size_t *a_data_size, bool *a_is_pinned, dap_nanotime_t *a_ts);
dap_store_obj_t *dap_global_db_get_raw_sync(const char *a_group, const char *a_key);

dap_nanotime_t dap_global_db_get_del_ts_sync(const char *a_group, const char *a_key);
byte_t *dap_global_db_get_last_sync(const char *a_group, char **a_key, size_t *a_data_size, bool *a_is_pinned, dap_nanotime_t *a_ts);
dap_store_obj_t *dap_global_db_get_last_raw_sync(const char *a_group);
dap_global_db_obj_t *dap_global_db_get_all_sync(const char *a_group, size_t *a_objs_count);
dap_store_obj_t *dap_global_db_get_all_raw_sync(const char *a_group, size_t *a_objs_count);

int dap_global_db_set_sync(const char *a_group, const char *a_key, const void *a_value, const size_t a_value_length, bool a_pin_value);
// set raw with cluster roles and rights checks
int dap_global_db_set_raw_sync(dap_store_obj_t *a_store_objs, size_t a_store_objs_count);

int dap_global_db_pin_sync(const char *a_group, const char *a_key);
int dap_global_db_unpin_sync(const char *a_group, const char *a_key);
int dap_global_db_del_sync(const char *a_group, const char *a_key);
int dap_global_db_flush_sync();

bool dap_global_db_isalnum_group_key(const dap_store_obj_t *a_obj, bool a_not_null_key);
bool dap_global_db_group_match_mask(const char *a_group, const char *a_mask);

int dap_global_db_erase_table_sync(const char *a_group);
int dap_global_db_erase_table(const char *a_group, dap_global_db_callback_result_t a_callback, void *a_arg);