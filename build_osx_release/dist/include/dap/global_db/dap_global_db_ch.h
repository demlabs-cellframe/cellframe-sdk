/*
* Authors:
* Roman Khlopkov <roman.khlopkov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2023
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
#include "dap_time.h"
#include "dap_timerfd.h"
#include "dap_global_db_pkt.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_worker.h"

#define DAP_GLOBAL_DB_TASK_PRIORITY DAP_QUEUE_MSG_PRIORITY_LOW
#define DAP_GLOBAL_DB_QUEUE_SIZE_MAX 4096

enum dap_stream_ch_gdb_state {
    DAP_STREAM_CH_GDB_STATE_IDLE,
    DAP_STREAM_CH_GDB_STATE_UPDATE,
    DAP_STREAM_CH_GDB_STATE_SYNC
};

enum dap_global_db_cluster_msg_type {
    DAP_STREAM_CH_GLOBAL_DB_MSG_TYPE_START,
    DAP_STREAM_CH_GLOBAL_DB_MSG_TYPE_GROUP_REQUEST,
    DAP_STREAM_CH_GLOBAL_DB_MSG_TYPE_HASHES,
    DAP_STREAM_CH_GLOBAL_DB_MSG_TYPE_REQUEST,
    DAP_STREAM_CH_GLOBAL_DB_MSG_TYPE_RECORD,
    DAP_STREAM_CH_GLOBAL_DB_MSG_TYPE_RECORD_PACK,
    DAP_STREAM_CH_GLOBAL_DB_MSG_TYPE_DELETE
};

// Under construcion
typedef struct dap_stream_ch_gdb {
    void *_inheritor;
} dap_stream_ch_gdb_t;

#define DAP_STREAM_CH_GDB(a) ((dap_stream_ch_gdb_t *) ((a)->internal) )
#define DAP_STREAM_CH(a) ((dap_stream_ch_t *)((a)->_inheritor))
#define DAP_STREAM_CH_GDB_ID 'D'

int dap_global_db_ch_init();
void dap_global_db_ch_deinit();

bool dap_global_db_ch_check_store_obj(dap_store_obj_t *a_obj, dap_stream_node_addr_t *a_addr);

bool dap_global_db_ch_set_last_hash_remote(dap_stream_node_addr_t a_node_addr, const char *a_group, dap_global_db_driver_hash_t a_hash);
dap_global_db_driver_hash_t dap_glboal_db_ch_get_last_hash_remote(dap_stream_node_addr_t a_node_addr, const char *a_group);
