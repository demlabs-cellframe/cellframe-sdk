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
static int  s_debug_reactor = 0;
static dap_proc_thread_t * s_threads = NULL;
static void *s_proc_thread_function(void * a_arg);
static void s_event_exit_callback( dap_events_socket_t * a_es, uint64_t a_flags);

/**
 * @brief dap_proc_thread_init
 * @param a_cpu_count 0 means autodetect
 * @return
 */
static pthread_cond_t  s_started_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t s_started_mutex = PTHREAD_MUTEX_INITIALIZER;

int dap_proc_thread_init(uint32_t a_threads_count)
{
int l_ret = 0;

    s_threads_count = a_threads_count ? a_threads_count : dap_get_cpu_count( );
    s_threads = DAP_NEW_Z_SIZE(dap_proc_thread_t, sizeof (dap_proc_thread_t)* s_threads_count);
    s_debug_reactor = g_config ? dap_config_get_item_bool_default(g_config, "general", "debug_reactor", false) : false;

    for (uint32_t i = 0; i < s_threads_count; i++ )
    {
        s_threads[i].cpu_id = i;
        pthread_mutex_lock( &s_started_mutex );

        if ( (l_ret = pthread_create( &s_threads[i].thread_id,NULL, s_proc_thread_function, &s_threads[i] )) ) {
            log_it(L_CRITICAL, "Create thread failed with code %d", l_ret);
            pthread_mutex_unlock( &s_started_mutex );
            return l_ret;
        }

        pthread_cond_wait( &s_started_cond, &s_started_mutex);
        pthread_mutex_unlock( &s_started_mutex);
    }

    return l_ret;
}

/**
 * @brief dap_proc_thread_deinit
 */
void dap_proc_thread_deinit()
{
    for (uint32_t i = 0; i < s_threads_count; i++){
        dap_events_socket_event_signal(s_threads[i].event_exit, 1);
        pthread_join(s_threads[i].thread_id, NULL);
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
int     l_rc, l_is_anybody_for_repeat, l_is_finished, l_iter_cnt, l_cur_pri;
size_t  l_size;
dap_proc_queue_t    *l_queue;

    debug_if (s_debug_reactor, L_DEBUG, "--> Proc event callback start, a_esocket:%p ", a_esocket);

    if ( !(l_thread = (dap_proc_thread_t *) a_esocket->_inheritor) )
        {
        log_it(L_ERROR, "NULL <dap_proc_thread_t> context is detected");
        return;
        }

    l_iter_cnt = l_is_anybody_for_repeat = 0;
    /*@RRL:  l_iter_cnt = DAP_QUE$K_ITER_NR; */
    l_cur_pri = (DAP_QUE$K_PRIMAX - 1);
    l_queue = l_thread->proc_queue;

    for ( ; l_cur_pri; l_cur_pri--, l_iter_cnt++ )                          /* Run from higest to lowest ... */
    {
        if ( !l_queue->list[l_cur_pri].items.nr )                           /* A lockless quick check */
            continue;

        pthread_mutex_lock(&l_queue->list[l_cur_pri].lock);                 /* Protect list from other threads */
        l_rc = s_dap_remqhead (&l_queue->list[l_cur_pri].items, (void **) &l_item, &l_size);
        pthread_mutex_unlock(&l_queue->list[l_cur_pri].lock);

        if  ( l_rc == -ENOENT ) {                                           /* Queue is empty ? */
            debug_if (s_debug_reactor, L_DEBUG, "a_esocket:%p - nothing to do at prio: %d ", a_esocket, l_cur_pri);
            continue;
        }

        debug_if (s_debug_reactor, L_INFO, "Proc event callback: %p/%p, prio=%d, iteration=%d",
                       l_item->callback, l_item->callback_arg, l_cur_pri, l_iter_cnt);

        l_is_finished = l_item->callback(l_thread, l_item->callback_arg);
        l_is_anybody_for_repeat++;

        debug_if (s_debug_reactor, L_INFO, "Proc event callback: %p/%p, prio=%d, iteration=%d - is %sfinished",
                           l_item->callback, l_item->callback_arg, l_cur_pri, l_iter_cnt, l_is_finished ? "" : "not ");

        if ( !(l_is_finished) ) {
                                                                            /* Rearm callback to be executed again */
            pthread_mutex_lock(&l_queue->list[l_cur_pri].lock);
            l_rc = s_dap_insqtail (&l_queue->list[l_cur_pri].items, l_item, 1);
            pthread_mutex_unlock(&l_queue->list[l_cur_pri].lock);
        }
        else    {
                    DAP_DELETE(l_item);
    	}

            l_is_anybody_for_repeat += (!l_is_finished);

        }

    if ( l_is_anybody_for_repeat )                                          /* Arm event if we have something to proc again */
        dap_events_socket_event_signal(a_esocket, 1);

    debug_if(s_debug_reactor, L_DEBUG, "<-- Proc event callback end, repeat flag is: %d, iterations: %d", l_is_anybody_for_repeat, l_iter_cnt);
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

#ifdef DAP_EVENTS_CAPS_EPOLL
        // Init events for EPOLL
        a_esocket->ev.events = a_esocket->ev_base_flags ;
        if(a_esocket->flags & DAP_SOCK_READY_TO_READ )
            a_esocket->ev.events |= EPOLLIN;
        if(a_esocket->flags & DAP_SOCK_READY_TO_WRITE )
            a_esocket->ev.events |= EPOLLOUT;
        a_esocket->ev.data.ptr = a_esocket;
        return epoll_ctl(a_thread->epoll_ctl, EPOLL_CTL_ADD, a_esocket->socket, &a_esocket->ev);
#elif defined (DAP_EVENTS_CAPS_POLL)
    if (  a_thread->poll_count == a_thread->poll_count_max ){ // realloc
        a_thread->poll_count_max *= 2;
        log_it(L_WARNING, "Too many descriptors (%zu), resizing array twice to %zu", a_thread->poll_count, a_thread->poll_count_max);
        a_thread->poll =DAP_REALLOC(a_thread->poll, a_thread->poll_count_max * sizeof(*a_thread->poll));
        a_thread->esockets =DAP_REALLOC(a_thread->esockets, a_thread->poll_count_max * sizeof(*a_thread->esockets));
    }

    a_thread->poll[a_thread->poll_count].fd = a_thread->proc_queue->esocket->fd;
    a_thread->poll[a_thread->poll_count].events = a_thread->proc_queue->esocket->poll_base_flags;
    a_thread->esockets[a_thread->poll_count] = a_thread->proc_queue->esocket;
    a_thread->poll_count++;
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
/*    u_short l_flags = a_esocket->kqueue_base_flags;
    u_int   l_fflags = a_esocket->kqueue_base_fflags;
    short l_filter = a_esocket->kqueue_base_filter;
        if(a_esocket->flags & DAP_SOCK_READY_TO_READ )
            l_fflags |= NOTE_READ;
        if(a_esocket->flags & DAP_SOCK_READY_TO_WRITE )
            l_fflags |= NOTE_WRITE;

        EV_SET(&a_esocket->kqueue_event , a_esocket->socket, l_filter, EV_ADD| l_flags | EV_CLEAR, l_fflags,0, a_esocket);
        return kevent ( a_thread->kqueue_fd,&a_esocket->kqueue_event,1,NULL,0,NULL)==1 ? 0 : -1 ;
*/
    // Nothing to do if its input
    if ( a_esocket->type == DESCRIPTOR_TYPE_QUEUE && a_esocket->pipe_out)
        return 0;
#else
#error "Unimplemented new esocket on worker callback for current platform"
#endif

    return dap_proc_thread_esocket_update_poll_flags(a_thread,a_esocket);
}

/**
 * @brief dap_proc_thread_esocket_update_poll_flags
 * @param a_thread
 * @param a_esocket
 * @return
 */
int dap_proc_thread_esocket_update_poll_flags(dap_proc_thread_t * a_thread, dap_events_socket_t * a_esocket)
{
#ifdef DAP_EVENTS_CAPS_EPOLL
    u_int events = a_esocket->ev_base_flags;
    if( a_esocket->flags & DAP_SOCK_READY_TO_READ) {
        events |= EPOLLIN;
#ifdef DAP_OS_WINDOWS
        events ^= EPOLLONESHOT;
#endif
    }
    if( a_esocket->flags & DAP_SOCK_READY_TO_WRITE) {
        events |= EPOLLOUT;
#ifdef DAP_OS_WINDOWS
        events |= EPOLLONESHOT;
#endif
    }
    a_esocket->ev.events = events;
    if( epoll_ctl(a_thread->epoll_ctl, EPOLL_CTL_MOD, a_esocket->socket, &a_esocket->ev) != 0 ){
#ifdef DAP_OS_WINDOWS
        errno = WSAGetLastError();
#endif
        log_it(L_CRITICAL, "Can't add proc queue on epoll ctl, err: %d", errno);
        return -1;
    }
#elif defined (DAP_EVENTS_CAPS_POLL)
    if (  a_thread->poll_count == a_thread->poll_count_max ){ // realloc
        a_thread->poll_count_max *= 2;
        log_it(L_WARNING, "Too many descriptors (%zu), resizing array twice to %zu", a_thread->poll_count, a_thread->poll_count_max);
        a_thread->poll =DAP_REALLOC(a_thread->poll, a_thread->poll_count_max * sizeof(*a_thread->poll));
        a_thread->esockets =DAP_REALLOC(a_thread->esockets, a_thread->poll_count_max * sizeof(*a_thread->esockets));
    }
    a_thread->poll[a_esocket->poll_index].events= a_esocket->poll_base_flags;
    if( a_esocket->flags & DAP_SOCK_READY_TO_READ)
        a_thread->poll[a_esocket->poll_index].events |= POLLIN;
    if( a_esocket->flags & DAP_SOCK_READY_TO_WRITE)
        a_thread->poll[a_esocket->poll_index].events |= POLLOUT;

#elif defined (DAP_EVENTS_CAPS_KQUEUE)

    u_short l_flags = a_esocket->kqueue_base_flags;
    u_int   l_fflags = a_esocket->kqueue_base_fflags;
    short l_filter = a_esocket->kqueue_base_filter;
    int l_kqueue_fd = a_esocket->proc_thread ? a_esocket->proc_thread->kqueue_fd : -1;
    if ( l_kqueue_fd == -1 ){
        log_it(L_ERROR, "Esocket is not assigned with anything ,exit");
    }
    struct kevent * l_event = &a_esocket->kqueue_event;
    // Check & add
    int l_is_error=false;
    int l_errno=0;
    if (a_esocket->type == DESCRIPTOR_TYPE_EVENT || a_esocket->type == DESCRIPTOR_TYPE_QUEUE){
        EV_SET(l_event, a_esocket->socket, EVFILT_USER,EV_ADD| EV_CLEAR ,0,0, &a_esocket->kqueue_event_catched_data );
        if( kevent( l_kqueue_fd,l_event,1,NULL,0,NULL)!=0){
            l_is_error = true;
            l_errno = errno;
        }
    }else{
        EV_SET(l_event, a_esocket->socket, l_filter,l_flags| EV_ADD,l_fflags,a_esocket->kqueue_data,a_esocket);
        if( a_esocket->flags & DAP_SOCK_READY_TO_READ ){
            EV_SET(l_event, a_esocket->socket, EVFILT_READ,l_flags| EV_ADD,l_fflags,a_esocket->kqueue_data,a_esocket);
            if( kevent( l_kqueue_fd,l_event,1,NULL,0,NULL) != 1 ){
                l_is_error = true;
                l_errno = errno;
            }
        }
        if( !l_is_error){
            if( a_esocket->flags & DAP_SOCK_READY_TO_WRITE || a_esocket->flags &DAP_SOCK_CONNECTING ){
                EV_SET(l_event, a_esocket->socket, EVFILT_WRITE,l_flags| EV_ADD,l_fflags,a_esocket->kqueue_data,a_esocket);
                if(kevent( l_kqueue_fd,l_event,1,NULL,0,NULL) != 1){
                    l_is_error = true;
                    l_errno = errno;
                }
            }
        }
    }

    if ( l_is_error){
        char l_errbuf[128];
        l_errbuf[0]=0;
        strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
        log_it(L_ERROR,"Can't update client socket state on kqueue fd %d: \"%s\" (%d)",
            l_kqueue_fd, l_errbuf, l_errno);
    }

#else
#error "Not defined dap_proc_thread.c::s_update_poll_flags() on your platform"
#endif
    return 0;
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
    dap_events_socket_t * l_es = dap_events_socket_create_type_queue_ptr_unsafe(NULL,a_callback);
    if(l_es == NULL)
        return NULL;
    l_es->proc_thread = a_thread;
    dap_proc_thread_assign_esocket_unsafe (a_thread, l_es);
    return l_es;
}

/**
 * @brief s_proc_thread_function
 * @param a_arg
 * @return
 */
static void * s_proc_thread_function(void * a_arg)
{

    dap_proc_thread_t * l_thread = (dap_proc_thread_t*) a_arg;
    assert(l_thread);
    dap_cpu_assign_thread_on(l_thread->cpu_id);

    struct sched_param l_shed_params;
    l_shed_params.sched_priority = 0;
#if defined(DAP_OS_WINDOWS)
    if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST))
        log_it(L_ERROR, "Couldn't set thread priority, err: %lu", GetLastError());
#elif defined (DAP_OS_LINUX)
    pthread_setschedparam(pthread_self(),SCHED_BATCH ,&l_shed_params);
#elif defined (DAP_OS_BSD)
    pthread_setschedparam(pthread_self(),SCHED_OTHER ,&l_shed_params);
#else
#error "Undefined set sched param"
#endif
    l_thread->proc_queue = dap_proc_queue_create(l_thread);

    // Init proc_queue for related worker
    dap_worker_t * l_worker_related = dap_events_worker_get(l_thread->cpu_id);
    assert(l_worker_related);
    l_worker_related->proc_queue = l_thread->proc_queue;
    l_worker_related->proc_queue_input = dap_events_socket_queue_ptr_create_input(l_worker_related->proc_queue->esocket);

    dap_events_socket_assign_on_worker_mt(l_worker_related->proc_queue_input,l_worker_related);

    l_thread->proc_event = dap_events_socket_create_type_event_unsafe(NULL, s_proc_event_callback);
    l_thread->event_exit = dap_events_socket_create_type_event_unsafe(NULL, s_event_exit_callback);

    l_thread->proc_event->_inheritor = l_thread; // we pass thread through it
    l_thread->event_exit->_inheritor = l_thread;

    size_t l_workers_count= dap_events_worker_get_count();
    assert(l_workers_count);
    l_thread->queue_assign_input = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof (dap_events_socket_t*)*l_workers_count  );
    l_thread->queue_io_input = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof (dap_events_socket_t*)*l_workers_count  );
    l_thread->queue_callback_input = DAP_NEW_Z_SIZE(dap_events_socket_t*, sizeof (dap_events_socket_t*)*l_workers_count  );

    assert(l_thread->queue_assign_input);
    assert(l_thread->queue_io_input);
    for (size_t n=0; n<l_workers_count; n++){
        dap_worker_t * l_worker =dap_events_worker_get(n);
        l_thread->queue_assign_input[n] = dap_events_socket_queue_ptr_create_input(l_worker->queue_es_new );
        l_thread->queue_io_input[n] = dap_events_socket_queue_ptr_create_input(l_worker->queue_es_io );
        l_thread->queue_callback_input[n] = dap_events_socket_queue_ptr_create_input(l_worker->queue_callback );
    }
#ifdef DAP_EVENTS_CAPS_EPOLL
    struct epoll_event l_epoll_events[ DAP_EVENTS_SOCKET_MAX]= { { 0 } };

    // Create epoll ctl
    l_thread->epoll_ctl = epoll_create( DAP_EVENTS_SOCKET_MAX );

    // add proc queue
    l_thread->proc_queue->esocket->ev.events    = l_thread->proc_queue->esocket->ev_base_flags;
    l_thread->proc_queue->esocket->ev.data.ptr  = l_thread->proc_queue->esocket;
    if( epoll_ctl(l_thread->epoll_ctl, EPOLL_CTL_ADD, l_thread->proc_queue->esocket->socket , &l_thread->proc_queue->esocket->ev) != 0 ){
#ifdef DAP_OS_WINDOWS
        errno = WSAGetLastError();
#endif
        log_it(L_CRITICAL, "Can't add proc queue %zu on epoll ctl, error %d", l_thread->proc_queue->esocket->socket, errno);
        return NULL;
    }

    // Add proc event
    l_thread->proc_event->ev.events     = l_thread->proc_event->ev_base_flags ;
    l_thread->proc_event->ev.data.ptr   = l_thread->proc_event;
    if( epoll_ctl(l_thread->epoll_ctl, EPOLL_CTL_ADD, l_thread->proc_event->socket , &l_thread->proc_event->ev) != 0 ){
#ifdef DAP_OS_WINDOWS
        errno = WSAGetLastError();
#endif
        log_it(L_CRITICAL, "Can't add proc event on epoll ctl, err: %d", errno);
        return NULL;
    }

    // Add exit event
    l_thread->event_exit->ev.events     = l_thread->event_exit->ev_base_flags;
    l_thread->event_exit->ev.data.ptr   = l_thread->event_exit;
    if( epoll_ctl(l_thread->epoll_ctl, EPOLL_CTL_ADD, l_thread->event_exit->socket , &l_thread->event_exit->ev) != 0 ){
#ifdef DAP_OS_WINDOWS
        errno = WSAGetLastError();
#endif
        log_it(L_CRITICAL, "Can't add exit event on epoll ctl, err: %d", errno);
        return NULL;
    }

    for (size_t n = 0; n< dap_events_worker_get_count(); n++){
        // Queue asssign
        l_thread->queue_assign_input[n]->ev.events      = l_thread->queue_assign_input[n]->ev_base_flags ;
        l_thread->queue_assign_input[n]->ev.data.ptr    = l_thread->queue_assign_input[n];
        if( epoll_ctl(l_thread->epoll_ctl, EPOLL_CTL_ADD, l_thread->queue_assign_input[n]->socket, &l_thread->queue_assign_input[n]->ev) != 0 ){
#ifdef DAP_OS_WINDOWS
        errno = WSAGetLastError();
#endif
            log_it(L_CRITICAL, "Can't add queue input on epoll ctl, err: %d", errno);
            return NULL;
        }

        // Queue IO
        l_thread->queue_io_input[n]->ev.events      = l_thread->queue_io_input[n]->ev_base_flags ;
        l_thread->queue_io_input[n]->ev.data.ptr    = l_thread->queue_io_input[n];
        if( epoll_ctl(l_thread->epoll_ctl, EPOLL_CTL_ADD, l_thread->queue_io_input[n]->fd , &l_thread->queue_io_input[n]->ev) != 0 ){
#ifdef DAP_OS_WINDOWS
        errno = WSAGetLastError();
#endif
            log_it(L_CRITICAL, "Can't add proc io input on epoll ctl, err: %d", errno);
            return NULL;
        }

        // Queue callback
        l_thread->queue_callback_input[n]->ev.events      = l_thread->queue_callback_input[n]->ev_base_flags ;
        l_thread->queue_callback_input[n]->ev.data.ptr    = l_thread->queue_callback_input[n];
        if( epoll_ctl(l_thread->epoll_ctl, EPOLL_CTL_ADD, l_thread->queue_callback_input[n]->fd , &l_thread->queue_callback_input[n]->ev) != 0 ){
#ifdef DAP_OS_WINDOWS
        errno = WSAGetLastError();
#endif
            log_it(L_CRITICAL, "Can't add proc io input on epoll ctl, err: %d", errno);
            return NULL;
        }
    }
#elif defined(DAP_EVENTS_CAPS_POLL)
    l_thread->poll_count_max = DAP_EVENTS_SOCKET_MAX;
    l_thread->poll_count = 0;
    int l_poll_compress = false;
    l_thread->poll = DAP_NEW_Z_SIZE(struct pollfd,l_thread->poll_count_max *sizeof (*l_thread->poll));
    l_thread->esockets = DAP_NEW_Z_SIZE(dap_events_socket_t*,l_thread->poll_count_max *sizeof (*l_thread->esockets));

    // Add proc queue
    dap_proc_thread_assign_esocket_unsafe(l_thread,l_thread->proc_queue->esocket);

    // Add proc event
    l_thread->poll[l_thread->poll_count].fd = l_thread->proc_event->fd;
    l_thread->poll[l_thread->poll_count].events = l_thread->proc_event->poll_base_flags;
    l_thread->esockets[l_thread->poll_count] = l_thread->proc_event;
    l_thread->poll_count++;

    // Add exit event
    l_thread->poll[l_thread->poll_count].fd = l_thread->event_exit->fd;
    l_thread->poll[l_thread->poll_count].events = l_thread->event_exit->poll_base_flags;
    l_thread->esockets[l_thread->poll_count] = l_thread->event_exit;
    l_thread->poll_count++;

    for (size_t n = 0; n< dap_events_worker_get_count(); n++){
        dap_events_socket_t * l_queue_assign_input =  l_thread->queue_assign_input[n];
        dap_events_socket_t * l_queue_io_input =  l_thread->queue_io_input[n];
        dap_events_socket_t * l_queue_callback_input =  l_thread->queue_callback_input[n];
        if (l_queue_assign_input&&l_queue_io_input){

            // Queue assign input
            l_queue_assign_input->poll_index = l_thread->poll_count;
            l_thread->poll[l_thread->poll_count].fd = l_queue_assign_input->fd;
            l_thread->poll[l_thread->poll_count].events = l_queue_assign_input->poll_base_flags;
            l_thread->esockets[l_thread->poll_count] = l_queue_assign_input;
            l_thread->poll_count++;

            // Queue io input
            l_queue_io_input->poll_index = l_thread->poll_count;
            l_thread->poll[l_thread->poll_count].fd = l_queue_io_input->fd;
            l_thread->poll[l_thread->poll_count].events = l_queue_io_input->poll_base_flags;
            l_thread->esockets[l_thread->poll_count] = l_queue_io_input;
            l_thread->poll_count++;

            // Queue callback input
            l_queue_callback_input->poll_index = l_thread->poll_count;
            l_thread->poll[l_thread->poll_count].fd = l_queue_callback_input->fd;
            l_thread->poll[l_thread->poll_count].events = l_queue_callback_input->poll_base_flags;
            l_thread->esockets[l_thread->poll_count] = l_queue_callback_input;
            l_thread->poll_count++;
        }
    }
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
    // Create kqueue fd
    l_thread->kqueue_fd = kqueue();
    l_thread->kqueue_events_count_max = DAP_EVENTS_SOCKET_MAX;
    l_thread->kqueue_events = DAP_NEW_Z_SIZE(struct kevent, l_thread->kqueue_events_count_max *sizeof(struct kevent));

    dap_proc_thread_assign_esocket_unsafe(l_thread,l_thread->proc_queue->esocket);
    dap_proc_thread_assign_esocket_unsafe(l_thread,l_thread->proc_event);
    dap_proc_thread_assign_esocket_unsafe(l_thread,l_thread->event_exit);

    for (size_t n = 0; n< dap_events_worker_get_count(); n++){
        // Queue asssign
        dap_proc_thread_assign_esocket_unsafe(l_thread, l_thread->queue_assign_input[n]);

        // Queue IO
        dap_proc_thread_assign_esocket_unsafe(l_thread, l_thread->queue_io_input[n]);

        // Queue callback
        dap_proc_thread_assign_esocket_unsafe(l_thread, l_thread->queue_callback_input[n]);
    }

#else
#error "Unimplemented poll events analog for this platform"
#endif

    //We've started!
    pthread_mutex_lock(&s_started_mutex);
    pthread_mutex_unlock(&s_started_mutex);
    pthread_cond_broadcast(&s_started_cond);

    l_thread->signal_exit = false;

    // Main loop
    while (!l_thread->signal_kill && !l_thread->signal_exit){

        int l_selected_sockets;
        size_t l_sockets_max;
#ifdef DAP_EVENTS_CAPS_EPOLL
        //log_it(L_DEBUG, "Epoll_wait call");
        l_selected_sockets = epoll_wait(l_thread->epoll_ctl, l_epoll_events, DAP_EVENTS_SOCKET_MAX, -1);
        l_sockets_max = (size_t)l_selected_sockets;
#elif defined (DAP_EVENTS_CAPS_POLL)
        l_selected_sockets = poll(l_thread->poll,l_thread->poll_count,-1);
        l_sockets_max = l_thread->poll_count;
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
        l_selected_sockets = kevent(l_thread->kqueue_fd,NULL,0,l_thread->kqueue_events,l_thread->kqueue_events_count_max,NULL);
        l_sockets_max = l_selected_sockets;
#else
#error "Unimplemented poll wait analog for this platform"
#endif

        if(l_selected_sockets == -1) {
            if( errno == EINTR)
                continue;
#if defined DAP_OS_UNIX
            int l_errno = errno;
            char l_errbuf[128];
            strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
            log_it(L_ERROR, "Proc thread #%d got errno:\"%s\" (%d)", l_thread->cpu_id , l_errbuf, l_errno);
#elif DAP_OS_WINDOWS
            log_it(L_ERROR, "Error occured on thread #%d, errno: %d", l_thread->cpu_id , errno);
#endif
            break;
        }
        for(size_t n = 0; n < l_sockets_max; n++) {
            dap_events_socket_t * l_cur;
            int l_flag_hup, l_flag_rdhup, l_flag_read, l_flag_write, l_flag_error,
                    l_flag_nval,l_flag_pri,l_flag_msg;
#ifdef DAP_EVENTS_CAPS_EPOLL
            l_cur = (dap_events_socket_t *) l_epoll_events[n].data.ptr;
            uint32_t l_cur_events = l_epoll_events[n].events;
            l_flag_hup = l_cur_events & EPOLLHUP;
            l_flag_rdhup = l_cur_events & EPOLLHUP;
            l_flag_write = l_cur_events & EPOLLOUT;
            l_flag_read = l_cur_events & EPOLLIN;
            l_flag_error = l_cur_events & EPOLLERR;
            l_flag_nval = false;
            l_flag_pri = false;
            l_flag_msg = false;
#elif defined ( DAP_EVENTS_CAPS_POLL)
            if(n>=l_thread->poll_count){
                log_it(L_WARNING,"selected_sockets(%d) is bigger then poll count (%zu)", l_selected_sockets, l_thread->poll_count);
                break;
            }
            short l_cur_events = l_thread->poll[n].revents ;
            if (!l_cur_events)
                continue;
            l_cur = l_thread->esockets[n];
            l_flag_hup =  l_cur_events& POLLHUP;
            l_flag_rdhup = l_cur_events & POLLRDHUP;
            l_flag_write = (l_cur_events & POLLOUT) || (l_cur_events &POLLRDNORM)|| (l_cur_events &POLLRDBAND ) ;
            l_flag_read = l_cur_events & POLLIN || (l_cur_events &POLLWRNORM)|| (l_cur_events &POLLWRBAND );
            l_flag_error = l_cur_events & POLLERR;
            l_flag_nval = l_cur_events & POLLNVAL;
            l_flag_pri = l_cur_events & POLLPRI;
            l_flag_msg = l_cur_events & POLLMSG;
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
            struct kevent * l_kevent = &l_thread->kqueue_events[n];
            l_flag_hup=l_flag_rdhup=l_flag_read=l_flag_write=l_flag_error=l_flag_nval=l_flag_msg =l_flag_pri = false;

            if (l_kevent->filter & EVFILT_USER){
                dap_events_socket_w_data_t * l_es_w_data = (dap_events_socket_w_data_t*) l_kevent->udata;
                assert(l_es_w_data);
                l_cur = l_es_w_data->esocket;
                assert(l_cur);
                memcpy(&l_cur->kqueue_event_catched_data,l_es_w_data,sizeof(*l_es_w_data));
                if(l_es_w_data != &l_cur->kqueue_event_catched_data )
                    DAP_DELETE(l_es_w_data);
                else if (s_debug_reactor)
                    log_it(L_DEBUG,"Own event signal without actual event data");
                if ( l_cur->pipe_out == NULL){ // If we're not the input for pipe or queue
                                               // we must drop write flag and set read flag
                    l_flag_read = true;
                }else{
                    l_flag_write = true;
                }
            }else{
                l_cur = (dap_events_socket_t*) l_kevent->udata;
                assert(l_cur);

                switch (l_kevent->filter) {
                    case EVFILT_TIMER:
                    case EVFILT_READ: l_flag_read = true; break;
                    case EVFILT_WRITE: l_flag_write = true; break;
                    case EVFILT_EXCEPT : l_flag_rdhup = true; break;
                    default: log_it(L_CRITICAL,"Unknown filter type in polling, exit thread"); return NULL;
                }

            }
            l_cur->kqueue_event_catched = l_kevent;
#ifndef DAP_OS_DARWIN
            u_int l_cur_events = l_thread->kqueue_events[n].fflags;
#else
            uint32_t l_cur_events = l_thread->kqueue_events[n].fflags;
#endif

#else
#error "Unimplemented fetch esocket after poll"
#endif
            assert(l_cur);
            if(s_debug_reactor)
                log_it(L_DEBUG, "Proc thread #%u esocket %p fd=%"DAP_FORMAT_SOCKET" type=%d flags=0x%0X (%s:%s:%s:%s:%s:%s:%s:%s)", l_thread->cpu_id, l_cur, l_cur->socket,
                    l_cur->type, l_cur_events, l_flag_read?"read":"", l_flag_write?"write":"", l_flag_error?"error":"",
                    l_flag_hup?"hup":"", l_flag_rdhup?"rdhup":"", l_flag_msg?"msg":"", l_flag_nval?"nval":"", l_flag_pri?"pri":"");

            //log_it(L_DEBUG,"Waked up esocket %p (socket %d) {read:%s,write:%s,error:%s} ", l_cur, l_cur->fd,
            //           l_flag_read?"true":"false", l_flag_write?"true":"false", l_flag_error?"true":"false" );
            time_t l_cur_time = time( NULL);
            l_cur->last_time_active = l_cur_time;
            if (l_flag_error){
#ifdef DAP_OS_WINDOWS
                int l_errno = WSAGetLastError();
#else
                int l_errno = errno;
#endif
                char l_errbuf[128];
                strerror_r(l_errno, l_errbuf,sizeof (l_errbuf));
                log_it(L_ERROR,"Some error on proc thread #%u with %"DAP_FORMAT_SOCKET" socket: %s(%d)",l_thread->cpu_id, l_cur->socket, l_errbuf, l_errno);
                if(l_cur->callbacks.error_callback)
                    l_cur->callbacks.error_callback(l_cur, errno);
            }
            if (l_flag_read ){
                int32_t l_bytes_read = 0;
                switch (l_cur->type) {
                    case DESCRIPTOR_TYPE_QUEUE:
                        dap_events_socket_queue_proc_input_unsafe(l_cur);
#ifdef DAP_OS_WINDOWS
                        l_bytes_read = dap_recvfrom(l_cur->socket, NULL, 0);
#endif
                        break;
                    case DESCRIPTOR_TYPE_EVENT:
                        dap_events_socket_event_proc_input_unsafe (l_cur);
                        break;

                    default:
                        log_it(L_ERROR, "Unprocessed descriptor type accepted in proc thread loop");
#ifdef DAP_OS_WINDOWS
                        l_bytes_read = dap_recvfrom(l_cur->socket, NULL, 0);
#endif
                        break;
                }
            }
            if (l_flag_write ){
                int l_errno=0;
                if (l_cur->buf_out_size){
                    ssize_t l_bytes_sent = -1;
                    switch (l_cur->type) {
                        case DESCRIPTOR_TYPE_QUEUE:
                            if (l_cur->flags & DAP_SOCK_QUEUE_PTR){
                                #if defined(DAP_EVENTS_CAPS_QUEUE_PIPE2)
                                    l_bytes_sent = write(l_cur->socket, l_cur->buf_out, sizeof (void *) ); // We send pointer by pointer
                                #elif defined DAP_EVENTS_CAPS_MSMQ
                                DWORD l_mp_id = 0;
                                MQMSGPROPS    l_mps;
                                MQPROPVARIANT l_mpvar[1];
                                MSGPROPID     l_p_id[1];
                                HRESULT       l_mstatus[1];

                                l_p_id[l_mp_id] = PROPID_M_BODY;
                                l_mpvar[l_mp_id].vt = VT_VECTOR | VT_UI1;
                                l_mpvar[l_mp_id].caub.pElems = l_cur->buf_out;
                                l_mpvar[l_mp_id].caub.cElems = (u_long)l_cur->buf_out_size;
                                l_mp_id++;

                                l_mps.cProp = l_mp_id;
                                l_mps.aPropID = l_p_id;
                                l_mps.aPropVar = l_mpvar;
                                l_mps.aStatus = l_mstatus;
                                HRESULT hr = MQSendMessage(l_cur->mqh, &l_mps, MQ_NO_TRANSACTION);

                                if (hr != MQ_OK) {
                                    log_it(L_ERROR, "An error occured on sending message to queue, errno: %ld", hr);
                                    break;
                                } else {
                                    if(dap_sendto(l_cur->socket, l_cur->port, NULL, 0) == SOCKET_ERROR) {
                                        log_it(L_ERROR, "Write to sock error: %d", WSAGetLastError());
                                    }
                                    l_cur->buf_out_size = 0;
                                    dap_events_socket_set_writable_unsafe(l_cur,false);

                                    break;
                                }
                                #elif defined (DAP_EVENTS_CAPS_QUEUE_MQUEUE)
                                    char * l_ptr = (char *) l_cur->buf_out;
                                    void *l_ptr_in;
                                    memcpy(&l_ptr_in,l_ptr, sizeof (l_ptr_in) );

                                    l_bytes_sent = mq_send(l_cur->mqd, l_ptr, sizeof (l_ptr),0);
                                    if (l_bytes_sent==0){
//                                        log_it(L_DEBUG,"mq_send %p success", l_ptr_in);
                                        l_bytes_sent = sizeof (void *);
                                    }else if (l_bytes_sent == -1 && errno == EINVAL){ // To make compatible with other
                                        l_errno = EAGAIN;                        // non-blocking sockets
//                                        log_it(L_DEBUG,"mq_send %p EAGAIN", l_ptr_in);
                                    }else{
                                        l_errno = errno;
                                        log_it(L_WARNING,"mq_send %p errno: %d", l_ptr_in, l_errno);
                                    }
                                #elif defined (DAP_EVENTS_CAPS_KQUEUE)

                                    // Select socket and kqueue fd to send the event
                                    dap_events_socket_t * l_es_output = l_cur->pipe_out ? l_cur->pipe_out : l_cur;
                                    int l_kqueue_fd = l_es_output->worker ? l_es_output->worker->kqueue_fd : l_es_output->proc_thread ? l_es_output->proc_thread->kqueue_fd : -1;

                                    struct kevent l_event;
                                    dap_events_socket_w_data_t * l_es_w_data = DAP_NEW_Z(dap_events_socket_w_data_t);
                                    l_es_w_data->esocket = l_es_output;

                                    memcpy(&l_es_w_data->ptr,l_cur->buf_out,sizeof(l_es_w_data->ptr) );
                                    EV_SET(&l_event,l_es_output->socket, EVFILT_USER,0,NOTE_TRIGGER ,0, l_es_w_data);


                                    int l_n =  l_kqueue_fd==-1 ? -1 : kevent(l_kqueue_fd,&l_event,1,NULL,0,NULL);
                                    if (l_n != -1)
                                        l_bytes_sent = sizeof(l_es_w_data->ptr);
                                    else{
                                        l_errno = errno;
                                        log_it(L_WARNING,"queue ptr send error: kevent %p errno: %d", l_es_w_data->ptr, l_errno);
                                        DAP_DELETE(l_es_w_data);
                                    }
                                #else
                                    #error "Not implemented dap_events_socket_queue_ptr_send() for this platform"
                                #endif
                                //int l_errno = errno;

                                break;
                            }break;
                        default:
                            log_it(L_ERROR, "Dont process write flags for this socket %d in proc thread", l_cur->fd);

                    }
                    l_errno = errno;

                    if(l_bytes_sent>0){
                        l_cur->buf_out_size -= l_bytes_sent;
                        //log_it(L_DEBUG,"Sent %zd bytes out, left %zd in buf out", l_bytes_sent, l_cur->buf_out);
                        if (l_cur->buf_out_size ){ // Shrink output buffer

                            memmove(l_cur->buf_out, l_cur->buf_out+l_bytes_sent, l_cur->buf_out_size );
                        }else{
#ifndef DAP_EVENTS_CAPS_KQUEUE
                            l_cur->flags ^= DAP_SOCK_READY_TO_WRITE;
                            dap_proc_thread_esocket_update_poll_flags(l_thread, l_cur);
#else
                            log_it(L_WARNING,"(!) Write event receieved but nothing in buffer");
                            sleep(500); // to prevent shitting the log files
#endif
                        }
                    }

                }else{
                    // TODO Make this code platform-independent
#ifndef DAP_EVENTS_CAPS_EVENT_KEVENT
                    log_it(L_DEBUG,"(!) Write event receieved but nothing in buffer, switching off this flag");
                    l_cur->flags ^= DAP_SOCK_READY_TO_WRITE;
                    dap_proc_thread_esocket_update_poll_flags(l_thread, l_cur);
                    // TODO Make this code platform-independent
#else
                    log_it(L_WARNING,"(!) Write event receieved but nothing in buffer");
                    sleep(500); // to prevent shitting the log files
#endif
                }


            }
            if(l_cur->flags & DAP_SOCK_SIGNAL_CLOSE){
#ifdef DAP_EVENTS_CAPS_EPOLL
                log_it(L_WARNING, "Deleting esocket %d from proc thread?...", l_cur->fd);
                if ( epoll_ctl( l_thread->epoll_ctl, EPOLL_CTL_DEL, l_cur->fd, &l_cur->ev) == -1 )
                    log_it( L_ERROR,"Can't remove event socket's handler from the epoll ctl" );
                //else
                //    log_it( L_DEBUG,"Removed epoll's event from proc thread #%u", l_thread->cpu_id );
                if (l_cur->callbacks.delete_callback)
                    l_cur->callbacks.delete_callback(l_cur, l_thread);
                if(l_cur->_inheritor)
                    DAP_DELETE(l_cur->_inheritor);
                DAP_DELETE(l_cur);
#elif defined (DAP_EVENTS_CAPS_POLL)
                l_thread->poll[n].fd = -1;
                l_poll_compress = true;
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
        if (l_cur->socket != -1 ){
            struct kevent * l_event = &l_cur->kqueue_event;
            EV_SET(l_event, l_cur->socket, 0 ,EV_DELETE, 0,0,l_cur);
            if ( kevent( l_thread->kqueue_fd,l_event,1,NULL,0,NULL) != 1 ) {
                int l_errno = errno;
                char l_errbuf[128];
                strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
                log_it( L_ERROR,"Can't remove event socket's handler %d from the epoll_fd %d  \"%s\" (%d)", l_cur->socket,
                l_thread->kqueue_fd, l_errbuf, l_errno);
            }
        }

#else
#error "Unimplemented poll ctl analog for this platform"
#endif
            }

        }
#ifdef DAP_EVENTS_CAPS_POLL
        /***********************************************************/
        /* If the compress_array flag was turned on, we need       */
        /* to squeeze together the array and decrement the number  */
        /* of file descriptors.                                    */
        /***********************************************************/
        if ( l_poll_compress){
           l_poll_compress = false;
           for (size_t i = 0; i < l_thread->poll_count ; i++)  {
               if ( l_thread->poll[i].fd == -1){
                    for(size_t j = i; j +1 < l_thread->poll_count; j++){
                        l_thread->poll[j].fd = l_thread->poll[j+1].fd;
                        l_thread->poll[j].events = l_thread->poll[j+1].events;
                        l_thread->poll[j].revents = l_thread->poll[j+1].revents;
                        l_thread->esockets[j] = l_thread->esockets[j+1];
                        if(l_thread->esockets[j])
                            l_thread->esockets[j]->poll_index = j;
                    }
                   i--;
                   l_thread->poll_count--;
               }
           }
        }
#endif
    }
    log_it(L_ATT, "Stop processing thread #%u", l_thread->cpu_id);
    fflush(stdout);

    // cleanip inputs
    for (size_t n=0; n<dap_events_worker_get_count(); n++){
        dap_events_socket_delete_unsafe(l_thread->queue_assign_input[n], false);
        dap_events_socket_delete_unsafe(l_thread->queue_io_input[n], false);
    }

    return NULL;
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
    if(s_debug_reactor)
        log_it(L_DEBUG,"Remove esocket %p from proc thread and send it to worker #%u",a_esocket, a_worker->id);

    dap_events_socket_assign_on_worker_inter(l_es_assign_input, a_esocket);
    // TODO Make this code platform-independent
#ifndef DAP_EVENTS_CAPS_EVENT_KEVENT
    l_es_assign_input->flags |= DAP_SOCK_READY_TO_WRITE;
    dap_proc_thread_esocket_update_poll_flags(a_thread, l_es_assign_input);
#endif
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
    // TODO Make this code platform-independent
#ifndef DAP_EVENTS_CAPS_EVENT_KEVENT
    l_es_io_input->flags |= DAP_SOCK_READY_TO_WRITE;
    dap_proc_thread_esocket_update_poll_flags(a_thread, l_es_io_input);
#endif
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
    // TODO Make this code platform-independent
#ifndef DAP_EVENTS_CAPS_EVENT_KEVENT
    l_es_io_input->flags |= DAP_SOCK_READY_TO_WRITE;
    dap_proc_thread_esocket_update_poll_flags(a_thread, l_es_io_input);
#endif
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
void dap_proc_thread_worker_exec_callback(dap_proc_thread_t * a_thread, size_t a_worker_id, dap_worker_callback_t a_callback, void * a_arg)
{
    dap_worker_msg_callback_t * l_msg = DAP_NEW_Z(dap_worker_msg_callback_t);
    l_msg->callback = a_callback;
    l_msg->arg = a_arg;
    dap_events_socket_queue_ptr_send_to_input(a_thread->queue_callback_input[a_worker_id],l_msg );

    // TODO Make this code platform-independent
#ifndef DAP_EVENTS_CAPS_EVENT_KEVENT
    a_thread->queue_callback_input[a_worker_id]->flags |= DAP_SOCK_READY_TO_WRITE;
    dap_proc_thread_esocket_update_poll_flags(a_thread, a_thread->queue_callback_input[a_worker_id]);
#endif
}

static void s_event_exit_callback( dap_events_socket_t * a_es, uint64_t a_flags)
{
    (void) a_flags;
    dap_proc_thread_t * l_thread = (dap_proc_thread_t *) a_es->_inheritor;
    l_thread->signal_exit = true;
    if(s_debug_reactor)
        log_it(L_DEBUG, "Proc_thread :%u signaled to exit", l_thread->cpu_id);
}

