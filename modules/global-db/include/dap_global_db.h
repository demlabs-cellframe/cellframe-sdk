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

#define DAP_GLOBAL_DB_VERSION                 1
#define DAP_GLOBAL_DB_LOCAL_GENERAL         "local.general"

typedef struct dap_global_db_record{
        uint64_t        id;                                                 /* An uniqe-like Id of the record - internaly created and maintained */
        uint32_t        flags;                                              /* Flag of the record  */
        uint32_t        length;
        dap_nanotime_t  ts; /* Timestamp of the record */
        uint64_t        padding;
        byte_t          data[];
} DAP_ALIGN_PACKED dap_global_db_record_t;


typedef void (*dap_global_db_callback_result_t) (int a_errno, const char * a_group, const char * a_key, const void * a_value, const size_t a_value_len, void * a_arg);
typedef void (*dap_global_db_callback_results_t) (int a_errno, const char * a_group, const char * a_key, const size_t a_values_total, const size_t, const size_t a_values_shift, const size_t a_value_count,
                                                 dap_global_db_record_t ** values, void * a_arg);

extern bool g_dap_global_db_debug_more;

int dap_global_db_init(const char * a_path, const char * a_driver);
void dap_global_db_deinit();

int dap_global_db_get(const char * a_group, const char *a_key,dap_global_db_callback_result_t a_callback, void * a_arg );
int dap_global_db_get_last(const char * a_group, dap_global_db_callback_result_t a_callback, void * a_arg );
int dap_global_db_get_all(const char * a_group, dap_global_db_callback_results_t a_callback, void * a_arg );

int dap_global_db_set(const char * a_group, const char *a_key, const void * a_value, const size_t a_value_length, bool a_pin_value, dap_global_db_callback_result_t a_callback, void * a_arg );
int dap_global_db_pin(const char * a_group, const char *a_key, dap_global_db_callback_result_t a_callback, void * a_arg );
int dap_global_db_unpin(const char * a_group, const char *a_key, dap_global_db_callback_result_t a_callback, void * a_arg );
int dap_global_db_delete(const char * a_group, const char *a_key, dap_global_db_callback_result_t a_callback, void * a_arg );
