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
#include "dap_worker.h"
#include "dap_proc_queue.h"
#include "dap_proc_thread.h"
#define LOG_TAG "dap_proc_queue"


typedef struct dap_proc_queue_msg{
    dap_proc_queue_callback_t callback;
    void * callback_arg;
    bool signal_kill;
} dap_proc_queue_msg_t;

static void s_queue_esocket_callback( dap_events_socket_t * a_es, void * a_msg);

/**
 * @brief dap_proc_queue_create
 * @param a_thread
 * @return
 */
dap_proc_queue_t * dap_proc_queue_create(dap_proc_thread_t * a_thread)
{
    dap_proc_queue_t * l_queue = DAP_NEW_Z(dap_proc_queue_t);
    l_queue->proc_thread = a_thread;
    l_queue->esocket = dap_events_socket_create_type_queue_ptr_unsafe(NULL,s_queue_esocket_callback);
    l_queue->esocket->_inheritor = l_queue;
    return l_queue;
}

/**
 * @brief dap_proc_queue_delete
 * @param a_queue
 */
void dap_proc_queue_delete(dap_proc_queue_t * a_queue)
{
    dap_proc_queue_msg_t * l_msg = DAP_NEW_Z(dap_proc_queue_msg_t);
    l_msg->signal_kill = true;
    dap_events_socket_queue_ptr_send( a_queue->esocket, l_msg );
}

/**
 * @brief s_queue_esocket_callback
 * @param a_es
 * @param a_msg
 */
static void s_queue_esocket_callback( dap_events_socket_t * a_es, void * a_msg)
{
    //log_it(L_DEBUG, "New callback in list accepted");
    dap_proc_queue_t * l_queue = (dap_proc_queue_t*) a_es->_inheritor;
    dap_proc_queue_msg_t * l_msg = (dap_proc_queue_msg_t*) a_msg;

    // We have callback to add in list
    if (l_msg->callback){
        dap_proc_queue_item_t * l_item = DAP_NEW_Z(dap_proc_queue_item_t);
        l_item->callback = l_msg->callback;
        l_item->callback_arg = l_msg->callback_arg;
        l_item->next=l_queue->items;
        l_queue->items = l_item;
        // Add on top so after call this callback will be executed first
        dap_events_socket_queue_ptr_send(l_queue->proc_thread->proc_event,NULL);
        //log_it( L_DEBUG, "Sent signal to proc thread that we have callbacks on board");
    }
    if (l_msg->signal_kill){ // Say to kill this object and delete its inherior dap_proc_queue_t
        a_es->flags |= DAP_ESOCK_SIGNAL_CLOSE;
    }
    DAP_DELETE(l_msg);
}


void dap_proc_queue_add_callback(dap_worker_t * a_worker,dap_proc_queue_callback_t a_callback, void * a_callback_arg)
{
    dap_proc_queue_msg_t * l_msg = DAP_NEW_Z(dap_proc_queue_msg_t);
    l_msg->callback = a_callback;
    l_msg->callback_arg = a_callback_arg;
    dap_events_socket_queue_ptr_send( a_worker->proc_queue->esocket , l_msg );
}
