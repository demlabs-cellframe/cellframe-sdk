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
#include <stddef.h>
#include <stdbool.h>
#include "dap_common.h"
#include "dap_time.h"
#include "dap_context.h"
#include "dap_proc_queue.h"
#define DAP_GLOBAL_DB_VERSION                 1
#define DAP_GLOBAL_DB_LOCAL_GENERAL         "local.general"

// GlobalDB own context custom extension
typedef struct dap_global_db_context
{
    dap_events_socket_t * queue_io; // I/O queue for GlobalDB i/o requests

    dap_events_socket_t ** queue_worker_callback_input; // Worker callback queue input
    dap_events_socket_t ** queue_worker_io_input; // Worker io queue input
    dap_events_socket_t ** queue_proc_thread_callback_input; // Worker callback queue input

    dap_context_t * context; // parent pointer
} dap_global_db_context_t;

typedef struct dap_store_obj {
    uint64_t id;
    dap_nanotime_t timestamp;
    uint32_t type;                                                          /* Operation type: ADD/DELETE, see DAP_DB$K_OPTYPE_* constants */
    uint8_t flags;                                                          /* RECORD_FLAGS */

    char *group;
    uint64_t group_len;

    char *key;
    uint64_t key_len;

    uint8_t *value;
    uint64_t value_len;

    dap_proc_queue_callback_t callback_proc_thread;                                           /* (Async mode only!) A call back to be called on request completion */
    void *callback_proc_thread_arg;                                                     /* (Async mode only!) An argument of the callback rotine */
} dap_store_obj_t, *pdap_store_obj_t;

typedef struct dap_global_db_obj {
    uint64_t id;
    char *key;
    uint8_t *value;
    size_t value_len;
    bool is_pinned;
} DAP_ALIGN_PACKED dap_global_db_obj_t;



typedef void (*dap_global_db_callback_result_t) (dap_global_db_context_t * a_global_db_context,int a_rc, const char * a_group, const char * a_key, const void * a_value, const size_t a_value_len, dap_nanotime_t value_ts, bool a_is_pinned, void * a_arg);
typedef void (*dap_global_db_callback_results_t) (dap_global_db_context_t * a_global_db_context,int a_rc, const char * a_group, const char * a_key, const size_t a_values_total,  const size_t a_values_shift,
                                                  const size_t a_value_count, dap_global_db_obj_t * a_values, void * a_arg);
// Return codes
#define DAP_GLOBAL_DB_RC_SUCCESS         0
#define DAP_GLOBAL_DB_RC_NO_RESULTS     -1
#define DAP_GLOBAL_DB_RC_ERROR           -666

extern bool g_dap_global_db_debug_more;

int dap_global_db_init(const char * a_path, const char * a_driver);
void dap_global_db_deinit();

int dap_global_db_get(const char * a_group, const char *a_key,dap_global_db_callback_result_t a_callback, void * a_arg );
int dap_global_db_get_del_ts(const char * a_group, const char *a_key,dap_global_db_callback_result_t a_callback, void * a_arg );
int dap_global_db_get_last(const char * a_group, dap_global_db_callback_result_t a_callback, void * a_arg );
int dap_global_db_get_all(const char * a_group, size_t l_results_page_size, dap_global_db_callback_results_t a_callback, void * a_arg );

int dap_global_db_set(const char * a_group, const char *a_key, const void * a_value, const size_t a_value_length, bool a_pin_value, dap_global_db_callback_result_t a_callback, void * a_arg );
int dap_global_db_set_multiple(const char * a_group, dap_global_db_obj_t * a_values, size_t a_values_count, dap_global_db_callback_results_t a_callback, void * a_arg );
int dap_global_db_pin(const char * a_group, const char *a_key, dap_global_db_callback_result_t a_callback, void * a_arg );
int dap_global_db_unpin(const char * a_group, const char *a_key, dap_global_db_callback_result_t a_callback, void * a_arg );
int dap_global_db_delete(const char * a_group, const char *a_key, dap_global_db_callback_result_t a_callback, void * a_arg );
int dap_global_db_flush( dap_global_db_callback_result_t a_callback, void * a_arg );

void dap_global_db_objs_delete(dap_global_db_obj_t *a_objs, size_t a_count);
