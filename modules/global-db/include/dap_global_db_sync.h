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
#include <dap_list.h>
typedef void (*dap_global_db_obj_callback_notify_t) (void * a_arg, const char a_op_code, const char * a_group,
                                                     const char * a_key, const void * a_value, const size_t a_value_len);

// Callback table item
typedef struct dap_sync_group_item {
    char *group_mask;
    char *net_name;
    dap_global_db_obj_callback_notify_t callback_notify;
    void * callback_arg;
} dap_sync_group_item_t;

void dap_global_db_sync_init();
void dap_global_db_sync_deinit();

/**
 * Setup callbacks and filters
 */
// Add group name that will be synchronized
void dap_chain_global_db_add_sync_group(const char *a_net_name, const char *a_group_prefix, dap_global_db_obj_callback_notify_t a_callback, void *a_arg);
void dap_chain_global_db_add_sync_extra_group(const char *a_net_name, const char *a_group_mask, dap_global_db_obj_callback_notify_t a_callback, void *a_arg);
dap_list_t *dap_chain_db_get_sync_groups(const char *a_net_name);
dap_list_t *dap_chain_db_get_sync_extra_groups(const char *a_net_name);
dap_list_t * dap_global_db_get_sync_groups_all();
dap_list_t * dap_global_db_get_sync_groups_extra_all();
