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
#include <stdatomic.h>

#include "dap_config.h"
#include "dap_list.h"
#include "dap_events.h"
#include "dap_events_socket.h"
#include "dap_proc_thread.h"
#include "dap_server.h"

#if defined(DAP_EVENTS_CAPS_EPOLL) && !defined(DAP_OS_WINDOWS)
#include <sys/epoll.h>
#elif defined DAP_OS_WINDOWS
#include "wepoll.h"
#elif defined (DAP_EVENTS_CAPS_POLL)
#include <poll.h>
#elif defined (DAP_EVENTS_CAPS_KQUEUE)

#include <sys/event.h>
#include <err.h>

#ifndef DAP_OS_DARWIN
#include <pthread_np.h>
typedef cpuset_t cpu_set_t; // Adopt BSD CPU setstructure to POSIX variant
#else
#define NOTE_READ NOTE_LOWAT
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL SO_NOSIGPIPE
#endif

#else
#error "Unimplemented poll for this platform"
#endif

#define LOG_TAG "dap_proc_thread"

static size_t s_threads_count = 0;
static dap_proc_thread_t * s_threads = NULL;

static void s_event_exit_callback( dap_events_socket_t * a_es, uint64_t a_flags);

static void s_context_callback_started( dap_context_t * a_context, void *a_arg);
static void s_context_callback_stopped( dap_context_t * a_context, void *a_arg);

/**
 * @brief dap_proc_thread_init
 * @param a_cpu_count 0 means autodetect
 * @return
 */

int dap_proc_thread_init(uint32_t a_threads_count)
{
int l_ret = 0;

    s_threads_count = a_threads_count ? a_threads_count : dap_get_cpu_count( );
    s_threads = DAP_NEW_Z_SIZE(dap_proc_thread_t, sizeof (dap_proc_thread_t)* s_threads_count);

    for (uint32_t i = 0; i < s_threads_count; i++ )
    {
        dap_proc_thread_t * l_thread = s_threads + i;
        l_thread->context = dap_context_new(DAP_CONTEXT_TYPE_PROC_THREAD);
        l_thread->context->proc_thread = l_thread;

        if ( (l_ret = dap_context_run(l_thread->context,i,DAP_CONTEXT_POLICY_TIMESHARING,2,
                                      DAP_CONTEXT_FLAG_WAIT_FOR_STARTED, s_context_callback_started,
                                      s_context_callback_stopped,l_thread)  ) ) {
            log_it(L_CRITICAL, "Create thread failed with code %d", l_ret);
            return l_ret;
        }

    }

    return l_ret;
}


/**
 * @brief dap_proc_thread_deinit
 */
void dap_proc_thread_deinit()
{
    int l_rc = 0;
    size_t l_sz = 0;
    dap_proc_thread_t *l_proc_thread = NULL;

    for (uint32_t i = s_threads_count; i--; ){
        dap_context_stop_n_kill(s_threads[i].context);
    }


    // Signal to cancel working threads and wait for finish
    // TODO: Android realization
//#ifndef DAP_OS_ANDROID
//    for (size_t i = 0; i < s_threads_count; i++ ){
//        pthread_cancel(s_threads[i].thread_id);
//        pthread_join(s_threads[i].thread_id, NULL);
//    }
//#endif

}

/**
 * @brief dap_proc_thread_get
 * @param a_cpu_id
 * @return
 */
dap_proc_thread_t * dap_proc_thread_get(uint32_t a_cpu_id)
{
    return (a_cpu_id < s_threads_count) ? &s_threads[a_cpu_id] : NULL;
}

/**
 * @brief dap_proc_thread_get_auto
 * @return
 */
dap_proc_thread_t * dap_proc_thread_get_auto()
{
unsigned l_id_min = 0, l_size_min = UINT32_MAX, l_queue_size;

    for (size_t i = 0; i < s_threads_count; i++ )
    {
        l_queue_size = atomic_load(&s_threads[i].proc_queue_size);

        if( l_queue_size < l_size_min ){
            l_size_min = l_queue_size;
            l_id_min = i;
        }
    }

    return &s_threads[l_id_min];
}

/**
 * @brief s_proc_event_callback - get from queue next element and execute action routine,
 *  repeat execution depending on status is returned by action routine.
 *
 * @param a_esocket
 * @param a_value
 *
 */
static void s_proc_event_callback(dap_events_socket_t * a_esocket, uint64_t __attribute__((unused))  a_value)
{
    dap_proc_thread_t   *l_thread;
    dap_proc_queue_item_t *l_item;
    int     l_rc, l_is_anybody_in_queue, l_is_finished, l_iter_cnt, l_cur_pri,
            l_is_processed;
    size_t  l_size;
    dap_proc_queue_t    *l_queue;

    debug_if (g_debug_reactor, L_DEBUG, "--> Proc event callback start, a_esocket:%p ", a_esocket);

    if ( !(l_thread = (dap_proc_thread_t *) a_esocket->_inheritor) )
        {
        log_it(L_ERROR, "NULL <dap_proc_thread_t> context is detected");
        return;
        }

    l_iter_cnt = l_is_anybody_in_queue = 0;
    /*@RRL:  l_iter_cnt = DAP_QUE$K_ITER_NR; */
    l_queue = l_thread->proc_queue;

    struct timespec l_time_start, l_time_end;
    clock_gettime(CLOCK_REALTIME, &l_time_start);
    do {
        l_is_processed = 0;
        for (l_cur_pri = (DAP_PROC_PRI_MAX - 1); l_cur_pri; l_iter_cnt++ )                          /* Run from higest to lowest ... */
        {
            if ( !l_queue->list[l_cur_pri].items.nr) {                       /* A lockless quick check */
                l_cur_pri--;
                continue;
            }

            clock_gettime(CLOCK_REALTIME, &l_time_end);
            if (l_time_end.tv_sec > l_time_start.tv_sec)
                break;

//            pthread_mutex_lock(&l_queue->list[l_cur_pri].lock);                 /* Protect list from other threads */
            l_rc = dap_slist_get4head(&l_queue->list[l_cur_pri].items, (void **) &l_item, &l_size);
//            pthread_mutex_unlock(&l_queue->list[l_cur_pri].lock);

            if  ( l_rc == -ENOENT ) {                                           /* Queue is empty ? */
                debug_if (g_debug_reactor, L_DEBUG, "a_esocket:%p - nothing to do at prio: %d ", a_esocket, l_cur_pri);
                continue;
            }

            debug_if (g_debug_reactor, L_INFO, "Proc event callback (l_item: %p) : %p/%p, prio=%d, iteration=%d",
                           l_item, l_item->callback, l_item->callback_arg, l_cur_pri, l_iter_cnt);

            l_is_processed += 1;
            l_is_finished = l_item->callback(l_thread, l_item->callback_arg);

            debug_if (g_debug_reactor, L_INFO, "Proc event callback: %p/%p, prio=%d, iteration=%d - is %sfinished",
                               l_item->callback, l_item->callback_arg, l_cur_pri, l_iter_cnt, l_is_finished ? "" : "not ");

            if ( !(l_is_finished) ) {                                       /* Put entry back to queue to repeat of execution */
                pthread_mutex_lock(&l_queue->list[l_cur_pri].lock);
                l_rc = dap_slist_add2tail(&l_queue->list[l_cur_pri].items, l_item, l_size);
                pthread_mutex_unlock(&l_queue->list[l_cur_pri].lock);
            }
            else    {
                DAP_DEL_Z(l_item);
            }
        }
    } while ( l_is_processed );


    for (l_cur_pri = (DAP_PROC_PRI_MAX - 1); l_cur_pri; l_cur_pri--)
        l_is_anybody_in_queue += l_queue->list[l_cur_pri].items.nr;

    if ( l_is_anybody_in_queue )                                          /* Arm event if we have something to proc again */
        dap_events_socket_event_signal(a_esocket, 1);

    debug_if(g_debug_reactor, L_DEBUG, "<-- Proc event callback end, items rest: %d, iterations: %d", l_is_anybody_in_queue, l_iter_cnt);
}


/**
 * @brief dap_proc_thread_assign_esocket_unsafe
 * @param a_thread
 * @param a_esocket
 * @return
 */
int dap_proc_thread_assign_esocket_unsafe(dap_proc_thread_t * a_thread, dap_events_socket_t * a_esocket)
{
    assert(a_esocket);
    assert(a_thread);
    a_esocket->proc_thread = a_thread;
    int l_ret = dap_context_add(a_thread->context, a_esocket);
    if (l_ret)
        log_it(L_CRITICAL,"Can't add event socket's handler to worker i/o poll mechanism with error %d", errno);
    a_esocket->is_initalized = true;
    return l_ret;
}



/**
 * @brief dap_proc_thread_create_queue_ptr
 * @details Call this function as others only from safe situation, or, thats better, from a_thread's context
 * @param a_thread
 * @param a_callback
 * @return
 */
dap_events_socket_t * dap_proc_thread_create_queue_ptr(dap_proc_thread_t * a_thread, dap_events_socket_callback_queue_ptr_t a_callback)
{
    dap_events_socket_t * l_es = dap_context_create_queue(a_thread->context,a_callback);
    if(l_es == NULL)
        return NULL;
    l_es->proc_thread = a_thread;
    return l_es;
}

/**
 * @brief s_context_callback_started
 * @param a_context
 * @param a_arg
 */
static void s_context_callback_started( dap_context_t * a_context, void *a_arg)
{
    dap_proc_thread_t * l_thread = (dap_proc_thread_t*) a_arg;
    assert(l_thread);
    l_thread->proc_queue = dap_proc_queue_create(l_thread);

    // Init proc_queue for related worker
    dap_worker_t * l_worker_related = dap_events_worker_get(l_thread->context->cpu_id);
    assert(l_worker_related);

    l_worker_related->proc_queue = l_thread->proc_queue;
    l_worker_related->proc_queue_input = dap_events_socket_queue_ptr_create_input(l_worker_related->proc_queue->esocket);

    dap_events_socket_assign_on_worker_mt(l_worker_related->proc_queue_input,l_worker_related);

    l_thread->proc_event = dap_context_create_event( a_context , s_proc_event_callback);
    l_thread->proc_event->proc_thread = l_thread;

    l_thread->proc_event->_inheritor = l_thread; // we pass thread through it

    size_t l_workers_count= dap_events_thread_get_count();
    assert(l_workers_count);
    l_thread->queue_assign_input = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof (dap_events_socket_t*)*l_workers_count  );
    l_thread->queue_io_input = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof (dap_events_socket_t*)*l_workers_count  );
    l_thread->queue_callback_input = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof (dap_events_socket_t*)*l_workers_count  );

    assert(l_thread->queue_assign_input);
    assert(l_thread->queue_io_input);
    for (size_t n = 0; n < l_workers_count; n++) {
        dap_worker_t *l_worker = dap_events_worker_get(n);
        // Queue assign
        l_thread->queue_assign_input[n] = dap_events_socket_queue_ptr_create_input(l_worker->queue_es_new);
        dap_proc_thread_assign_esocket_unsafe(l_thread, l_thread->queue_assign_input[n]);
        // Queue IO
        l_thread->queue_io_input[n] = dap_events_socket_queue_ptr_create_input(l_worker->queue_es_io);
        dap_proc_thread_assign_esocket_unsafe(l_thread, l_thread->queue_io_input[n]);
        // Queue callback
        l_thread->queue_callback_input[n] = dap_events_socket_queue_ptr_create_input(l_worker->queue_callback);
        dap_proc_thread_assign_esocket_unsafe(l_thread, l_thread->queue_callback_input[n]);
    }
}

/**
 * @brief s_context_callback_stopped
 * @param a_context
 * @param a_arg
 */
static void s_context_callback_stopped( dap_context_t * a_context, void *a_arg)
{
    dap_proc_thread_t * l_thread = (dap_proc_thread_t*) a_arg;
    assert(l_thread);
    log_it(L_ATT, "Stop processing thread #%u", l_thread->context->cpu_id);
    // cleanip inputs
    for (size_t n=0; n<dap_events_thread_get_count(); n++){
        dap_events_socket_delete_unsafe(l_thread->queue_assign_input[n], false);
        dap_events_socket_delete_unsafe(l_thread->queue_io_input[n], false);
        dap_events_socket_delete_unsafe(l_thread->queue_callback_input[n], false);
    }
}


/**
 * @brief dap_proc_thread_assign_on_worker_inter
 * @param a_thread
 * @param a_worker
 * @param a_esocket
 * @return
 */
bool dap_proc_thread_assign_on_worker_inter(dap_proc_thread_t * a_thread, dap_worker_t * a_worker, dap_events_socket_t *a_esocket  )
{
    dap_events_socket_t * l_es_assign_input = a_thread->queue_assign_input[a_worker->id];
    if(g_debug_reactor)
        log_it(L_DEBUG,"Remove esocket %p from proc thread and send it to worker #%u",a_esocket, a_worker->id);
    dap_events_socket_assign_on_worker_inter(l_es_assign_input, a_esocket);
    return true;
}

/**
 * @brief dap_proc_thread_esocket_write_inter
 * @param a_thread
 * @param a_worker
 * @param a_es_uuid
 * @param a_data
 * @param a_data_size
 * @return
 */
int dap_proc_thread_esocket_write_inter(dap_proc_thread_t * a_thread,dap_worker_t * a_worker,   dap_events_socket_uuid_t a_es_uuid,
                                        const void * a_data, size_t a_data_size)
{
    dap_events_socket_t * l_es_io_input = a_thread->queue_io_input[a_worker->id];
    dap_events_socket_write_inter(l_es_io_input,a_es_uuid, a_data, a_data_size);
    return 0;
}


/**
 * @brief dap_proc_thread_esocket_write_f_inter
 * @param a_thread
 * @param a_worker
 * @param a_es_uuid,
 * @param a_format
 * @return
 */
int dap_proc_thread_esocket_write_f_inter(dap_proc_thread_t * a_thread,dap_worker_t * a_worker,  dap_events_socket_uuid_t a_es_uuid,
                                        const char * a_format,...)
{
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

    dap_events_socket_t * l_es_io_input = a_thread->queue_io_input[a_worker->id];
    char * l_data = DAP_NEW_SIZE(char,l_data_size+1);
    if (!l_data){
        va_end(ap_copy);
        return -1;
    }
    l_data_size = dap_vsprintf(l_data,a_format,ap_copy);
    va_end(ap_copy);

    dap_events_socket_write_inter(l_es_io_input, a_es_uuid, l_data, l_data_size);
    DAP_DELETE(l_data);
    return 0;
}

/**
 * @brief dap_proc_thread_worker_exec_callback
 * @param a_thread
 * @param a_worker_id
 * @param a_callback
 * @param a_arg
 */
void dap_proc_thread_worker_exec_callback_inter(dap_proc_thread_t * a_thread, size_t a_worker_id, dap_worker_callback_t a_callback, void * a_arg)
{
    dap_worker_msg_callback_t *l_msg = DAP_NEW_Z(dap_worker_msg_callback_t);
    l_msg->callback = a_callback;
    l_msg->arg = a_arg;
    debug_if(g_debug_reactor, L_INFO, "Msg with arg %p -> worker %zu", a_arg, a_worker_id);
    dap_events_socket_queue_ptr_send_to_input(a_thread->queue_callback_input[a_worker_id], l_msg);
}




