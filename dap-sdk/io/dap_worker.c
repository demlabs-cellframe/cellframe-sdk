/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2017
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
#include <time.h>
#include <errno.h>
#include <unistd.h>

#include "dap_common.h"
#include "dap_config.h"
#include "dap_context.h"
#include "dap_math_ops.h"
#include "dap_worker.h"
#include "dap_timerfd.h"
#include "dap_events.h"
#include "dap_enc_base64.h"
#include "dap_proc_queue.h"

#ifndef DAP_NET_CLIENT_NO_SSL
#include <wolfssl/options.h>
#include "wolfssl/ssl.h"
#endif

#define LOG_TAG "dap_worker"

pthread_key_t g_pth_key_worker;

static time_t s_connection_timeout = 60;    // seconds

static bool s_socket_all_check_activity( void * a_arg);
static void s_queue_add_es_callback( dap_events_socket_t * a_es, void * a_arg);
static void s_queue_delete_es_callback( dap_events_socket_t * a_es, void * a_arg);
static void s_queue_es_reassign_callback( dap_events_socket_t * a_es, void * a_arg);
static void s_queue_callback_callback( dap_events_socket_t * a_es, void * a_arg);
static void s_queue_es_io_callback( dap_events_socket_t * a_es, void * a_arg);
static void s_event_exit_callback( dap_events_socket_t * a_es, uint64_t a_flags);

/**
 * @brief dap_worker_init
 * @param a_threads_count
 * @param conn_timeout
 * @return
 */
int dap_worker_init( size_t a_conn_timeout )
{
    if ( a_conn_timeout )
      s_connection_timeout = a_conn_timeout;

    pthread_key_create( &g_pth_key_worker, NULL);

    return 0;
}

void dap_worker_deinit( )
{
}

/**
 * @brief dap_worker_context_callback_started
 * @param a_context
 * @param a_arg
 * @return
 */
void dap_worker_context_callback_started( dap_context_t * a_context, void *a_arg)
{
    dap_worker_t *l_worker = (dap_worker_t *) a_arg;
    assert(l_worker);
    pthread_setspecific(g_pth_key_worker, l_worker);
    l_worker->queue_es_new_input      = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof (dap_events_socket_t*)* dap_events_thread_get_count() );
    l_worker->queue_es_delete_input   = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof (dap_events_socket_t*)* dap_events_thread_get_count() );
    l_worker->queue_es_io_input       = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof (dap_events_socket_t*)* dap_events_thread_get_count() );
    l_worker->queue_es_reassign_input = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof (dap_events_socket_t*)* dap_events_thread_get_count() );


    l_worker->queue_es_new      = dap_context_create_esocket_queue(a_context, s_queue_add_es_callback);
    l_worker->queue_es_delete   = dap_context_create_esocket_queue(a_context, s_queue_delete_es_callback);
    l_worker->queue_es_io       = dap_context_create_esocket_queue(a_context, s_queue_es_io_callback);
    l_worker->queue_es_reassign = dap_context_create_esocket_queue(a_context, s_queue_es_reassign_callback );


    for( size_t n = 0; n < dap_events_thread_get_count(); n++) {
        l_worker->queue_es_new_input[n] = dap_events_socket_queue_ptr_create_input(l_worker->queue_es_new);
        l_worker->queue_es_delete_input[n] = dap_events_socket_queue_ptr_create_input(l_worker->queue_es_delete);
        l_worker->queue_es_io_input[n] = dap_events_socket_queue_ptr_create_input(l_worker->queue_es_io);
        l_worker->queue_es_reassign_input[n] = dap_events_socket_queue_ptr_create_input(l_worker->queue_es_reassign);
    }

    l_worker->queue_callback    = dap_context_create_esocket_queue(a_context, s_queue_callback_callback);
    l_worker->event_exit        = dap_context_create_esocket_event(a_context, s_event_exit_callback);

    l_worker->timer_check_activity = dap_timerfd_create(s_connection_timeout * 1000 / 2,
                                                        s_socket_all_check_activity, l_worker);
    dap_worker_add_events_socket_unsafe(  l_worker->timer_check_activity->events_socket, l_worker);

}

/**
 * @brief dap_worker_context_callback_stopped
 * @param a_context
 * @param a_arg
 * @return
 */
void dap_worker_context_callback_stopped( dap_context_t * a_context, void *a_arg)
{
    dap_worker_t *l_worker = (dap_worker_t *) a_arg;
    assert(l_worker);
    log_it(L_NOTICE,"Exiting thread #%u", l_worker->id);
}


/**
 * @brief s_new_es_callback
 * @param a_es
 * @param a_arg
 */
static void s_queue_add_es_callback( dap_events_socket_t * a_es, void * a_arg)
{
    assert(a_es);
    dap_context_t * l_context = a_es->context;
    assert(l_context);
    dap_worker_t * l_worker = l_context->worker;
    assert(l_worker);
    dap_events_socket_t * l_es_new =(dap_events_socket_t *) a_arg;
    if (!l_es_new){
        log_it(L_ERROR,"NULL esocket accepted to add on worker #%u", l_worker->id);
        return;
    }

    if(g_debug_reactor)
        log_it(L_NOTICE, "Received event socket %p (ident %"DAP_FORMAT_SOCKET" type %d) to add on worker", l_es_new, l_es_new->socket, l_es_new->type);

    switch( l_es_new->type){
        case DESCRIPTOR_TYPE_SOCKET_UDP: break;
        case DESCRIPTOR_TYPE_SOCKET_CLIENT: break;
        default:{}
    }

#ifdef DAP_EVENTS_CAPS_KQUEUE
    if(l_es_new->socket!=0 && l_es_new->socket != -1 &&
            l_es_new->type != DESCRIPTOR_TYPE_EVENT &&
        l_es_new->type != DESCRIPTOR_TYPE_QUEUE &&
        l_es_new->type != DESCRIPTOR_TYPE_TIMER
            )
#else
    if(l_es_new->socket!=0 && l_es_new->socket != INVALID_SOCKET)

#endif
    if(dap_context_esocket_find_by_uuid( l_context, l_es_new->uuid)){
        // Socket already present in worker, it's OK
        return;
    }

    switch( l_es_new->type){

        case DESCRIPTOR_TYPE_SOCKET_UDP:
        case DESCRIPTOR_TYPE_SOCKET_CLIENT:
        case DESCRIPTOR_TYPE_SOCKET_LISTENING:{

#ifdef DAP_OS_UNIX
#if defined (SO_INCOMING_CPU)
            int l_cpu = l_worker->id;
            setsockopt(l_es_new->socket , SOL_SOCKET, SO_INCOMING_CPU, &l_cpu, sizeof(l_cpu));
#endif
#endif
        } break;
        default: {}
    }

    l_es_new->last_time_active = time(NULL);
    // We need to differ new and reassigned esockets. If its new - is_initialized is false
    if ( ! l_es_new->is_initalized ){
        if (l_es_new->callbacks.new_callback)
            l_es_new->callbacks.new_callback(l_es_new, NULL);
        l_es_new->is_initalized = true;
    }

    int l_ret =dap_context_add_esocket(l_context,l_es_new);
    if (  l_ret != 0 ){
        log_it(L_CRITICAL,"Can't add event socket's handler to worker i/o poll mechanism with error %d", errno);
    }else{
        // Add in worker
        l_es_new->me = l_es_new;
        if (l_es_new->socket!=0 && l_es_new->socket != INVALID_SOCKET){
            HASH_ADD(hh_worker, l_worker->context->esockets, uuid, sizeof(l_es_new->uuid), l_es_new );
            l_worker->event_sockets_count++;
        }
        //log_it(L_DEBUG, "Added socket %d on worker %u", l_es_new->socket, w->id);
        if (l_es_new->callbacks.worker_assign_callback)
            l_es_new->callbacks.worker_assign_callback(l_es_new, l_worker);

    }
}

/**
 * @brief s_delete_es_callback
 * @param a_es
 * @param a_arg
 */
static void s_queue_delete_es_callback( dap_events_socket_t * a_es, void * a_arg)
{
    assert(a_arg);
    dap_events_socket_uuid_t * l_es_uuid_ptr = (dap_events_socket_uuid_t*) a_arg;
    dap_events_socket_t * l_es;
    if ( (l_es = dap_context_esocket_find_by_uuid(a_es->context,*l_es_uuid_ptr)) != NULL ){
        //l_es->flags |= DAP_SOCK_SIGNAL_CLOSE; // Send signal to socket to kill
        dap_events_socket_remove_and_delete_unsafe(l_es,false);
    }else
        log_it(L_INFO, "While we were sending the delete() message, esocket %"DAP_UINT64_FORMAT_U" has been disconnected ", *l_es_uuid_ptr);
    DAP_DELETE(l_es_uuid_ptr);
}

/**
 * @brief s_reassign_es_callback
 * @param a_es
 * @param a_arg
 */
static void s_queue_es_reassign_callback( dap_events_socket_t * a_es, void * a_arg)
{
    assert(a_es);
    dap_context_t * l_context = a_es->context;
    assert(l_context);
    dap_worker_t * l_worker = l_context->worker;
    assert(l_worker);
    dap_worker_msg_reassign_t * l_msg = (dap_worker_msg_reassign_t*) a_arg;
    assert(l_msg);
    dap_events_socket_t * l_es_reassign;
    if ( ( l_es_reassign = dap_context_esocket_find_by_uuid(l_context, l_msg->esocket_uuid))!= NULL ){
        if( l_es_reassign->was_reassigned && l_es_reassign->flags & DAP_SOCK_REASSIGN_ONCE) {
            log_it(L_INFO, "Reassgment request with DAP_SOCK_REASSIGN_ONCE allowed only once, declined reassigment from %u to %u",
                   l_es_reassign->context->worker->id, l_msg->worker_new->id);

        }else{
            dap_events_socket_reassign_between_workers_unsafe(l_es_reassign,l_msg->worker_new);
        }
    }else{
        log_it(L_INFO, "While we were sending the reassign message, esocket %p has been disconnected", l_msg->esocket);
    }
    DAP_DELETE(l_msg);
}

/**
 * @brief s_queue_callback
 * @param a_es
 * @param a_arg
 */
static void s_queue_callback_callback( dap_events_socket_t * a_es, void * a_arg)
{
    dap_worker_msg_callback_t * l_msg = (dap_worker_msg_callback_t *) a_arg;
    assert(l_msg);
    assert(l_msg->callback);
    l_msg->callback(a_es->context->worker, l_msg->arg);
    DAP_DELETE(l_msg);
}

/**
 * @brief s_event_exit_callback
 * @param a_es
 * @param a_flags
 */
static void s_event_exit_callback( dap_events_socket_t * a_es, uint64_t a_flags)
{
    (void) a_flags;
    a_es->context->signal_exit = true;
    if(g_debug_reactor)
        log_it(L_DEBUG, "Worker :%u signaled to exit", a_es->context->worker->id);
}

/**
 * @brief s_pipe_data_out_read_callback
 * @param a_es
 * @param a_arg
 */
static void s_queue_es_io_callback( dap_events_socket_t * a_es, void * a_arg)
{
    assert(a_es);
    dap_context_t * l_context = a_es->context;
    assert(l_context);
    dap_worker_t * l_worker = a_es->context->worker;
    dap_worker_msg_io_t * l_msg = a_arg;
    assert(l_msg);
    // Check if it was removed from the list
    dap_events_socket_t *l_msg_es = dap_context_esocket_find_by_uuid(l_worker->context, l_msg->esocket_uuid);
    if ( l_msg_es == NULL){
        log_it(L_INFO, "We got i/o message for esocket %"DAP_UINT64_FORMAT_U" thats now not in list. Lost %zu data", l_msg->esocket_uuid, l_msg->data_size);
        DAP_DELETE(l_msg);
        return;
    }

    if (l_msg->flags_set & DAP_SOCK_CONNECTING)
        if (!  (l_msg_es->flags & DAP_SOCK_CONNECTING) ){
            l_msg_es->flags |= DAP_SOCK_CONNECTING;
            dap_context_poll_update(l_msg_es);
        }

    if (l_msg->flags_set & DAP_SOCK_CONNECTING)
        if (!  (l_msg_es->flags & DAP_SOCK_CONNECTING) ){
            l_msg_es->flags ^= DAP_SOCK_CONNECTING;
            dap_context_poll_update(l_msg_es);
        }

    if (l_msg->flags_set & DAP_SOCK_READY_TO_READ)
        dap_events_socket_set_readable_unsafe(l_msg_es, true);
    if (l_msg->flags_unset & DAP_SOCK_READY_TO_READ)
        dap_events_socket_set_readable_unsafe(l_msg_es, false);
    if (l_msg->flags_set & DAP_SOCK_READY_TO_WRITE)
        dap_events_socket_set_writable_unsafe(l_msg_es, true);
    if (l_msg->flags_unset & DAP_SOCK_READY_TO_WRITE)
        dap_events_socket_set_writable_unsafe(l_msg_es, false);
    if (l_msg->data_size && l_msg->data) {
        dap_events_socket_write_unsafe(l_msg_es, l_msg->data,l_msg->data_size);
        DAP_DELETE(l_msg->data);
    }
    DAP_DELETE(l_msg);
}

/**
 * @brief s_socket_all_check_activity
 * @param a_arg
 */
static bool s_socket_all_check_activity( void * a_arg)
{
    dap_worker_t *l_worker = (dap_worker_t*) a_arg;
    assert(l_worker);
    dap_events_socket_t *l_es = NULL, *tmp = NULL;
    char l_curtimebuf[64];
    time_t l_curtime= time(NULL);
    //dap_ctime_r(&l_curtime, l_curtimebuf);
    //log_it(L_DEBUG,"Check sockets activity on worker #%u at %s", l_worker->id, l_curtimebuf);
    HASH_ITER(hh_worker, l_worker->context->esockets, l_es, tmp ) {
        if (l_es->type == DESCRIPTOR_TYPE_SOCKET_CLIENT){
            if ( !(l_es->flags & DAP_SOCK_SIGNAL_CLOSE) &&
                 (  l_curtime >=  (l_es->last_time_active + s_connection_timeout) ) && !l_es->no_close ) {
                log_it( L_INFO, "Socket %"DAP_FORMAT_SOCKET" timeout (diff %"DAP_UINT64_FORMAT_U" ), closing...",
                                l_es->socket, l_curtime -  (time_t)l_es->last_time_active - s_connection_timeout );
                if (l_es->callbacks.error_callback) {
                    l_es->callbacks.error_callback(l_es, ETIMEDOUT);
                }
                dap_events_socket_remove_and_delete_unsafe(l_es,false);
            }
        }
    }
    return true;
}

/**
 * @brief sap_worker_add_events_socket
 * @param a_events_socket
 * @param a_worker
 */
void dap_worker_add_events_socket(dap_events_socket_t * a_events_socket, dap_worker_t * a_worker)
{
/*#ifdef DAP_EVENTS_CAPS_KQUEUE
    a_events_socket->worker = a_worker;
    if(dap_worker_add_events_socket_unsafe(a_events_socket, a_worker)!=0)
        a_events_socket->worker = NULL;

#else*/
    if(g_debug_reactor)
        log_it(L_DEBUG,"Worker add esocket %"DAP_FORMAT_SOCKET, a_events_socket->socket);
    int l_ret = dap_events_socket_queue_ptr_send( a_worker->queue_es_new, a_events_socket );
    if(l_ret != 0 ){
        char l_errbuf[128];
        *l_errbuf = 0;
        strerror_r(l_ret, l_errbuf, sizeof(l_errbuf));
        log_it(L_ERROR, "Can't send pointer in queue: \"%s\"(code %d)", l_errbuf, l_ret);
    }
//#endif
}

/**
 * @brief dap_worker_add_events_socket_inter
 * @param a_es_input
 * @param a_events_socket
 */
void dap_worker_add_events_socket_inter(dap_events_socket_t * a_es_input, dap_events_socket_t * a_events_socket)
{
    if( dap_events_socket_queue_ptr_send_to_input( a_es_input, a_events_socket ) != 0 ){
        int l_errno = errno;
        char l_errbuf[128];
        *l_errbuf = 0;
        strerror_r(l_errno,l_errbuf,sizeof (l_errbuf));
        log_it(L_ERROR, "Cant send pointer to interthread queue input: \"%s\"(code %d)", l_errbuf, l_errno);
    }
}


/**
 * @brief dap_worker_exec_callback_on
 */
void dap_worker_exec_callback_on(dap_worker_t * a_worker, dap_worker_callback_t a_callback, void * a_arg)
{
    dap_worker_msg_callback_t * l_msg = DAP_NEW_Z(dap_worker_msg_callback_t);
    l_msg->callback = a_callback;
    l_msg->arg = a_arg;
    int l_ret=dap_events_socket_queue_ptr_send( a_worker->queue_callback,l_msg );
    if(l_ret != 0 ){
        char l_errbuf[128];
        *l_errbuf = 0;
        strerror_r(l_ret,l_errbuf,sizeof (l_errbuf));
        log_it(L_ERROR, "Cant send pointer in queue: \"%s\"(code %d)", l_errbuf, l_ret);
    }

}


/**
 * @brief dap_worker_add_events_socket
 * @param a_worker
 * @param a_events_socket
 */
dap_worker_t *dap_worker_add_events_socket_auto( dap_events_socket_t *a_es)
{
//  struct epoll_event ev = {0};
  dap_worker_t *l_worker = dap_events_worker_get_auto( );

  dap_worker_add_events_socket( a_es, l_worker);
  return l_worker;
}



