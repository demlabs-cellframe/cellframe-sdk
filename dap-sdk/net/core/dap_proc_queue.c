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
#include <errno.h>
#include "dap_worker.h"
#include "dap_proc_queue.h"
#include "dap_proc_thread.h"
#define LOG_TAG "dap_proc_queue"


typedef struct dap_proc_queue_msg{
    dap_proc_queue_callback_t callback;
    void * callback_arg;
    int signal_kill,
        pri;                                                                /* Message priority, see DAP_QUE$K_PRI* constants */
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

    if (!l_queue)
        return NULL;

    for (int i = 0; i < DAP_QUE$K_PRIMAX; i++) {
        assert ( !(pthread_mutex_init(&l_queue->list[i].lock, 0 )) );
    }

    l_queue->proc_thread = a_thread;
    l_queue->esocket = dap_events_socket_create_type_queue_ptr_unsafe(NULL,s_queue_esocket_callback);
    l_queue->esocket->proc_thread = a_thread;
    l_queue->esocket->_inheritor = l_queue;

    return l_queue;
}

/**
 * @brief dap_proc_queue_delete
 * @param a_queue
 * @return:  -ENOMEM in case of memory allocation error
 *           other <errno> codes from the internaly called routine
 */
int dap_proc_queue_delete(dap_proc_queue_t * a_queue)
{
    dap_proc_queue_msg_t * l_msg = DAP_NEW_Z(dap_proc_queue_msg_t);

    if (!l_msg)
        return  -ENOMEM;

    l_msg->signal_kill = 1;             /* TRUE */
    l_msg->pri = DAP_QUE$K_PRI_HIGH;    /* Assume that KILL must be delivered ASAP */

    return  dap_events_socket_queue_ptr_send( a_queue->esocket, l_msg );
}

/**
 * @brief s_queue_esocket_callback
 * @param a_es
 * @param a_msg
 */
static void s_queue_esocket_callback( dap_events_socket_t * a_es, void * a_msg)
{
    int l_rc, pri;
    dap_proc_queue_t *l_queue;
    dap_proc_queue_msg_t *l_msg;
    dap_proc_queue_item_t *l_item;

    assert ( a_es );
    if ( !(l_queue = (dap_proc_queue_t*) a_es->_inheritor) ) {
        log_it(L_CRITICAL, "%s: a_es: %p, l_queue is NULL", __PRETTY_FUNCTION__, a_es);
        return;
    }

    if ( !(l_msg = (dap_proc_queue_msg_t*) a_msg) ) {
        log_it(L_CRITICAL, "%s: a_es: %p, a_msg is NULL", __PRETTY_FUNCTION__, a_es);
        return;
    }

    if ( !l_msg->callback ) {
        if ( l_msg->signal_kill )                                           /* Say to kill this object and delete its inherior dap_proc_queue_t */
            a_es->flags |= DAP_SOCK_SIGNAL_CLOSE;

        DAP_DELETE(l_msg);
        return;
    }

    log_it(L_DEBUG, "l_queue: %p, l_msg: %p, callback: %p/%p, pri: %d", l_queue, l_msg, l_msg->callback, l_msg->callback_arg, l_msg->pri);


    if ( !(l_item = DAP_NEW_Z(dap_proc_queue_item_t)) ) {
        log_it(L_CRITICAL,"Can't allocate memory, drop l_msg:%p, callback: %p/%p, pri: %d", l_msg, l_msg->callback, l_msg->callback_arg, l_msg->pri);

        if ( l_msg->signal_kill )                                           /* Say to kill this object and delete its inherior dap_proc_queue_t */
            a_es->flags |= DAP_SOCK_SIGNAL_CLOSE;

        DAP_DELETE(l_msg);
        return;
    }

    /*
     * So, all checks has been finished, now we can prepare new entry
     */
    pri = l_msg->pri;                                                       /* Validate priority */
    pri = MIN(pri, DAP_QUE$K_PRIMAX - 1);
    pri = MAX(pri, 0);

        l_item->callback = l_msg->callback;
        l_item->callback_arg = l_msg->callback_arg;

    pthread_mutex_lock(&l_queue->list[pri].lock);                           /* Protect list from other threads */
    l_rc = s_dap_insqtail (&l_queue->list[pri].items, l_item, 1);
    pthread_mutex_unlock(&l_queue->list[pri].lock);

    if ( l_rc )
        log_it(L_CRITICAL, "Enqueue failed: %d, drop l_msg:%p, callback: %p/%p, pri: %d", l_rc, l_msg, l_msg->callback, l_msg->callback_arg, l_msg->pri);
    else
        log_it(L_DEBUG, "Enqueued l_msg:%p, callback: %p/%p, pri: %d", l_msg, l_msg->callback, l_msg->callback_arg, l_msg->pri);

    dap_events_socket_event_signal(l_queue->proc_thread->proc_event, 1);    /* Add on top so after call this callback will be executed first */

    if (l_msg->signal_kill)                                                 /* Say to kill this object and delete its inherior dap_proc_queue_t */
        a_es->flags |= DAP_SOCK_SIGNAL_CLOSE;

    DAP_DELETE(l_msg);
}

/**
 * @brief dap_proc_queue_add_callback
 * @param a_worker
 * @param a_callback
 * @param a_callback_arg
 * @return:  -ENOMEM in case of memory allocation error
 *           other <errno> codes from the internaly called routine
 */
int dap_proc_queue_add_callback(dap_worker_t * a_worker,dap_proc_queue_callback_t a_callback, void * a_callback_arg)
{
    dap_proc_queue_msg_t * l_msg = DAP_NEW_Z(dap_proc_queue_msg_t);

    if (!l_msg)
        return  -ENOMEM;

    l_msg->callback = a_callback;
    l_msg->callback_arg = a_callback_arg;
    l_msg->pri = DAP_QUE$K_PRI_NORMAL;
    /*
     * Send message to queue with the DEFAULT priority
     */
    return  dap_events_socket_queue_ptr_send( a_worker->proc_queue->esocket , l_msg );
}


/**
 * @brief dap_proc_queue_add_callback
 * @param a_worker
 * @param a_callback
 * @param a_callback_arg
 * @param a_pri - priority, DAP_QUE$K_PRI* constants
 * @return:  -ENOMEM in case of memory allocation error
 *           other <errno> codes from the internaly called routine
 */
int dap_proc_queue_add_callback_ext(dap_worker_t * a_worker,dap_proc_queue_callback_t a_callback, void * a_callback_arg,
                                    int a_pri)
{
dap_proc_queue_msg_t *l_msg;

    if ( !(a_pri < DAP_QUE$K_PRIMAX) )                                      /* Check that priority level is in legal range */
    {
        log_it(L_WARNING, "Priority level %d is incorrect (should be is in range %d-%d)", a_pri, DAP_QUE$K_PRI0 + 1, DAP_QUE$K_PRIMAX - 1);
        a_pri = DAP_QUE$K_PRI_NORMAL;
    }

    if ( !(l_msg = DAP_NEW_Z(dap_proc_queue_msg_t)) )                       /* Allocate memory for a new message */
        return  -ENOMEM;

    l_msg->callback = a_callback;
    l_msg->callback_arg = a_callback_arg;
    l_msg->pri = a_pri;

    /*
     * Send message to queueu with the given priority
     */
    return  dap_events_socket_queue_ptr_send ( a_worker->proc_queue->esocket , l_msg);
}


/**
 * @brief dap_proc_queue_add_callback_inter
 * @param a_es_input
 * @param a_callback
 * @param a_callback_arg
 * @return:  -ENOMEM in case of memory allocation error
 *           other <errno> codes from the internaly called routine
 */
int dap_proc_queue_add_callback_inter( dap_events_socket_t * a_es_input, dap_proc_queue_callback_t a_callback, void * a_callback_arg)
{
    dap_proc_queue_msg_t * l_msg = DAP_NEW_Z(dap_proc_queue_msg_t);

    if (!l_msg)
        return  -ENOMEM;

    l_msg->callback = a_callback;
    l_msg->callback_arg = a_callback_arg;
    l_msg->pri = DAP_QUE$K_PRI_NORMAL;

    return  dap_events_socket_queue_ptr_send_to_input( a_es_input , l_msg );
}


/**
 * @brief dap_proc_queue_add_callback_inter
 * @param a_es_input
 * @param a_callback
 * @param a_callback_arg
 * @return:  -ENOMEM in case of memory allocation error
 *           other <errno> codes from the internaly called routine
 */
int dap_proc_queue_add_callback_inter_ext( dap_events_socket_t * a_es_input, dap_proc_queue_callback_t a_callback, void * a_callback_arg,
                                           int a_pri)
{
dap_proc_queue_msg_t * l_msg;

    if ( !(a_pri < DAP_QUE$K_PRIMAX) )                                      /* Check that priority level is in legal range */
    {
        log_it(L_WARNING, "Priority level %d is incorrect (should be is in range %d-%d)", a_pri, DAP_QUE$K_PRI0 + 1, DAP_QUE$K_PRIMAX - 1);
        a_pri = DAP_QUE$K_PRI_NORMAL;
    }

    if ( !(l_msg = DAP_NEW_Z(dap_proc_queue_msg_t)) )                       /* Allocate memory for a new message */
        return  -ENOMEM;

    l_msg->callback = a_callback;
    l_msg->callback_arg = a_callback_arg;
    l_msg->pri = a_pri;

    return  dap_events_socket_queue_ptr_send_to_input( a_es_input , l_msg );
}
