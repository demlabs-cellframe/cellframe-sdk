/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2020
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
#include "dap_worker.h"
#include "dap_proc_thread.h"
#include "dap_stream_ch.h"

typedef struct dap_stream_worker {
    dap_worker_t * worker;
    dap_events_socket_t *queue_ch_io; // IO queue for channels
    dap_stream_ch_t * channels; // Client channels assigned on worker. Unsafe list, operate only in worker's context
    pthread_rwlock_t channels_rwlock;
} dap_stream_worker_t;

#define DAP_STREAM_WORKER(a) ((dap_stream_worker_t*) (a->_inheritor)  )

typedef struct dap_stream_worker_msg_io {
    dap_stream_ch_uuid_t ch_uuid;
    uint32_t flags_set; // set flags
    uint32_t flags_unset; // unset flags
    uint8_t ch_pkt_type;
    void * data;
    size_t data_size;
} dap_stream_worker_msg_io_t;

int dap_stream_worker_init();

size_t dap_proc_thread_stream_ch_write_inter(dap_proc_thread_t * a_thread,dap_worker_t * a_worker, dap_stream_ch_uuid_t a_ch_uuid,
                                        uint8_t a_type,const void * a_data, size_t a_data_size);
size_t dap_proc_thread_stream_ch_write_f_inter(dap_proc_thread_t * a_thread,dap_worker_t * a_worker,  dap_stream_ch_uuid_t a_ch_uuid,
                                        uint8_t a_type,const char * a_format,...);
