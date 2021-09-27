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
#include "dap_common.h"
#include "dap_events.h"
#include "dap_events_socket.h"
#include "dap_stream_worker.h"
#include "dap_stream_ch_pkt.h"

#define LOG_TAG "dap_stream_worker"

struct proc_thread_stream{
    dap_proc_thread_t * proc_thread;
    dap_events_socket_t ** queue_ch_io_input; // Inputs for ch assign queues
    dap_stream_ch_t * channels; // Client channels assigned on worker. Unsafe list, operate only in worker's context
    pthread_rwlock_t channels_rwlock;
};

static void s_ch_io_callback(dap_events_socket_t * a_es, void * a_msg);

/**
 * @brief dap_stream_worker_init
 * @return
 */
int dap_stream_worker_init()
{
    uint32_t l_worker_count = dap_events_worker_get_count();
    for (uint32_t i = 0; i < l_worker_count; i++){
        dap_worker_t * l_worker = dap_events_worker_get(i);
        if (!l_worker) {
            log_it(L_CRITICAL,"Can't init stream worker,- worker thread don't exist");
            return -2;
        }
        if (l_worker->_inheritor){
            log_it(L_CRITICAL,"Can't init stream worker,- core worker has already inheritor");
            return -1;
        }
        dap_stream_worker_t *l_stream_worker =  DAP_NEW_Z(dap_stream_worker_t);
        if(!l_stream_worker)
            return -5;
        l_worker->_inheritor = l_stream_worker;
        l_stream_worker->worker = l_worker;
        pthread_rwlock_init( &l_stream_worker->channels_rwlock, NULL);

        l_stream_worker->queue_ch_io = dap_events_socket_create_type_queue_ptr_mt( l_worker, s_ch_io_callback);
        if(! l_stream_worker->queue_ch_io)
            return -6;
    }
    for (uint32_t i = 0; i < l_worker_count; i++){
        dap_proc_thread_t * l_proc_thread  = dap_proc_thread_get(i);
        if (!l_proc_thread) {
            log_it(L_CRITICAL,"Can't init stream proc thread,- proc thread don't exist");
            return -3;
        }
        if (l_proc_thread->_inheritor){
            log_it(L_CRITICAL,"Can't init stream worker, core worker has already inheritor");
            return -4;
        }
        struct proc_thread_stream * l_thread_stream = DAP_NEW_Z(struct proc_thread_stream);
        if (!l_thread_stream)
            return -7;
        l_proc_thread->_inheritor = l_thread_stream;
        l_thread_stream->queue_ch_io_input = DAP_NEW_Z_SIZE(dap_events_socket_t *, sizeof (dap_events_socket_t*)*l_worker_count);
        for (uint32_t j = 0; j < l_worker_count; j++){
            dap_worker_t * l_worker = dap_events_worker_get(j);
            dap_stream_worker_t *l_stream_worker = (dap_stream_worker_t*) l_worker->_inheritor;
            l_thread_stream->queue_ch_io_input[i] = dap_events_socket_queue_ptr_create_input(l_stream_worker->queue_ch_io);
        }
    }
    return 0;
}

/**
 * @brief s_ch_io_callback
 * @param a_es
 * @param a_msg
 */
static void s_ch_io_callback(dap_events_socket_t * a_es, void * a_msg)
{
    dap_stream_worker_t * l_stream_worker = DAP_STREAM_WORKER( a_es->worker );
    dap_stream_worker_msg_io_t * l_msg = (dap_stream_worker_msg_io_t*) a_msg;

    assert(l_msg);
    // Check if it was removed from the list
    dap_stream_ch_t *l_msg_ch = NULL;
    pthread_rwlock_rdlock(&l_stream_worker->channels_rwlock);
    HASH_FIND(hh_worker, l_stream_worker->channels , &l_msg->ch_uuid , sizeof (l_msg->ch_uuid ), l_msg_ch );
    pthread_rwlock_unlock(&l_stream_worker->channels_rwlock);
    if ( l_msg_ch == NULL){
        log_it(L_DEBUG, "We got i/o message for client thats now not in list. Lost %u data", l_msg->data_size);
        DAP_DELETE(l_msg);
        return;
    }

    if (l_msg->flags_set & DAP_SOCK_READY_TO_READ)
        dap_stream_ch_set_ready_to_read_unsafe(l_msg_ch, true);
    if (l_msg->flags_unset & DAP_SOCK_READY_TO_READ)
        dap_stream_ch_set_ready_to_read_unsafe(l_msg_ch, false);
    if (l_msg->flags_set & DAP_SOCK_READY_TO_WRITE)
        dap_stream_ch_set_ready_to_write_unsafe(l_msg_ch, true);
    if (l_msg->flags_unset & DAP_SOCK_READY_TO_WRITE)
        dap_stream_ch_set_ready_to_write_unsafe(l_msg_ch, false);
    if (l_msg->data_size && l_msg->data) {
        dap_stream_ch_pkt_write_unsafe(l_msg_ch, l_msg->ch_pkt_type, l_msg->data,l_msg->data_size);
        DAP_DELETE(l_msg->data);
    }
    DAP_DELETE(l_msg);
}

/**
 * @brief dap_proc_thread_stream_ch_write_inter
 * @param a_thread
 * @param a_worker
 * @param a_ch_uuid
 * @param a_type
 * @param a_data
 * @param a_data_size
 * @return
 */
size_t dap_proc_thread_stream_ch_write_inter(dap_proc_thread_t * a_thread,dap_worker_t * a_worker, dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type,
                                        const void * a_data, size_t a_data_size)
{
    struct proc_thread_stream * l_thread_stream = (struct proc_thread_stream *) a_thread->_inheritor;
    dap_events_socket_t* l_es_input = l_thread_stream->queue_ch_io_input[a_worker->id];
    size_t l_ret = dap_stream_ch_pkt_write_inter(l_es_input,a_ch_uuid,a_type,a_data,a_data_size);
// TODO Make this code platform-independent
#ifndef DAP_EVENTS_CAPS_EVENT_KEVENT
    l_es_input->flags |= DAP_SOCK_READY_TO_WRITE;
    dap_proc_thread_esocket_update_poll_flags(a_thread,l_es_input);
#endif

    return l_ret;
}

/**
 * @brief dap_proc_thread_stream_ch_write_f_inter
 * @param a_thread
 * @param a_worker
 * @param a_ch_uuid
 * @param a_type
 * @param a_format
 * @return
 */
size_t dap_proc_thread_stream_ch_write_f_inter(dap_proc_thread_t * a_thread,dap_worker_t * a_worker,  dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type,
                                        const char * a_format,...)
{
    struct proc_thread_stream * l_thread_stream = (struct proc_thread_stream *) a_thread->_inheritor;
    va_list ap, ap_copy;
    va_start(ap,a_format);
    va_copy(ap_copy, ap);
    int l_data_size = dap_vsnprintf(NULL,0,a_format,ap);
    va_end(ap);
    if (l_data_size <0 ){
        log_it(L_ERROR,"Can't write out formatted data '%s' with values",a_format);
        va_end(ap_copy);
        return 0;
    }

    dap_events_socket_t * l_es_io_input = l_thread_stream->queue_ch_io_input[a_worker->id];
    char * l_data = DAP_NEW_SIZE(char,l_data_size+1);
    if (!l_data){
        va_end(ap_copy);
        return -1;
    }
    l_data_size = dap_vsprintf(l_data,a_format,ap_copy);
    va_end(ap_copy);

    size_t l_ret = dap_stream_ch_pkt_write_inter(l_es_io_input,a_ch_uuid,a_type, l_data, l_data_size);

    // TODO Make this code platform-independent
#ifndef DAP_EVENTS_CAPS_EVENT_KEVENT
    l_es_io_input->flags |= DAP_SOCK_READY_TO_WRITE;
    dap_proc_thread_esocket_update_poll_flags(a_thread, l_es_io_input);
#endif
    return l_ret;
}
