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

#include <assert.h>
#include <errno.h>
#include "dap_server.h"

#if defined(DAP_EVENTS_CAPS_EPOLL) && !defined(DAP_OS_WINDOWS)
#include <sys/epoll.h>
#elif defined DAP_OS_WINDOWS
#include "wepoll.h"
#elif defined (DAP_EVENTS_CAPS_POLL)
#include <poll.h>
#else
#error "Unimplemented poll for this platform"
#endif

#include "dap_config.h"
#include "dap_events.h"
#include "dap_events_socket.h"
#include "dap_proc_thread.h"

#define LOG_TAG "dap_proc_thread"

static size_t s_threads_count = 0;
static bool s_debug_reactor = false;
static dap_proc_thread_t * s_threads = NULL;
static void * s_proc_thread_function(void * a_arg);

/**
 * @brief dap_proc_thread_init
 * @param a_cpu_count 0 means autodetect
 * @return
 */
int dap_proc_thread_init(uint32_t a_threads_count){
    s_threads_count = a_threads_count ? a_threads_count : dap_get_cpu_count( );
    s_threads = DAP_NEW_Z_SIZE(dap_proc_thread_t, sizeof (dap_proc_thread_t)* s_threads_count);
    s_debug_reactor = g_config? dap_config_get_item_bool_default(g_config,"general","debug_reactor",false) : false;
    for (size_t i = 0; i < s_threads_count; i++ ){

        s_threads[i].cpu_id = i;
        pthread_cond_init( &s_threads[i].started_cond, NULL );
        pthread_mutex_init( &s_threads[i].started_mutex, NULL );
        pthread_mutex_lock( &s_threads[i].started_mutex );
        int res = pthread_create( &s_threads[i].thread_id,NULL, s_proc_thread_function, &s_threads[i] );
        if (res) {
            log_it(L_CRITICAL, "Create thread failed with code %d", res);
            pthread_mutex_unlock( &s_threads[i].started_mutex );
            return -1;
        }
        pthread_cond_wait( &s_threads[i].started_cond, &s_threads[i].started_mutex );
        pthread_mutex_unlock( &s_threads[i].started_mutex );
    }


    return 0;
}

/**
 * @brief dap_proc_thread_deinit
 */
void dap_proc_thread_deinit()
{
    // Signal to cancel working threads and wait for finish
    // TODO: Android realization
#ifndef DAP_OS_ANDROID
    for (size_t i = 0; i < s_threads_count; i++ ){
        pthread_cancel(s_threads[i].thread_id);
        pthread_join(s_threads[i].thread_id, NULL);
    }
#endif

}

/**
 * @brief dap_proc_thread_get
 * @param a_cpu_id
 * @return
 */
dap_proc_thread_t * dap_proc_thread_get(uint32_t a_cpu_id)
{
    return a_cpu_id<s_threads_count? &s_threads[a_cpu_id] : NULL;
}

/**
 * @brief dap_proc_thread_get_auto
 * @return
 */
dap_proc_thread_t * dap_proc_thread_get_auto()
{
    size_t l_id_min=0;
    size_t l_size_min=UINT32_MAX;
    for (size_t i = 0; i < s_threads_count; i++ ){
        size_t l_queue_size = s_threads[i].proc_queue_size;
        if( l_queue_size < l_size_min ){
            l_size_min = l_queue_size;
            l_id_min = i;
        }
    }
    return &s_threads[l_id_min];

}

/**
 * @brief s_proc_event_callback
 * @param a_esocket
 * @param a_value
 */
static void s_proc_event_callback(dap_events_socket_t * a_esocket, uint64_t a_value)
{
    (void) a_value;
//    log_it(L_DEBUG, "--> Proc event callback start");
    dap_proc_thread_t * l_thread = (dap_proc_thread_t *) a_esocket->_inheritor;
    dap_proc_queue_item_t * l_item = l_thread->proc_queue->item_first;
    dap_proc_queue_item_t * l_item_old = NULL;
    bool l_is_anybody_for_repeat=false;
    while(l_item){
//        log_it(L_INFO, "Proc event callback: %p/%p", l_item->callback, l_item->callback_arg);
        bool l_is_finished = l_item->callback(l_thread, l_item->callback_arg);
        if (l_is_finished){
            if ( l_item->prev ){
                l_item->prev->next = l_item_old;
            }
            if(l_item_old){
                l_item_old->prev = l_item->prev;

                if ( ! l_item->prev ) { // We deleted tail
                    l_thread->proc_queue->item_last = l_item_old;
                }

                DAP_DELETE(l_item);
                l_item = l_item_old->prev;
            }else{
                l_thread->proc_queue->item_first = l_item->prev;
                if ( l_item->prev){
                    l_item->prev->next = NULL; // Prev if it was - now its NULL
                }else
                    l_thread->proc_queue->item_last = NULL; // NULL last item

                DAP_DELETE(l_item);
                l_item = l_thread->proc_queue->item_first;
            }
//            log_it(L_DEBUG, "Proc event finished");
        }else{
//            log_it(L_DEBUG, "Proc event not finished");
            l_item_old = l_item;
            l_item=l_item->prev;
        }
        l_is_anybody_for_repeat = !l_is_finished;
    }
    if(l_is_anybody_for_repeat) // Arm event if we have smth to proc again
        dap_events_socket_event_signal(a_esocket,1);
//    log_it(L_DEBUG, "<-- Proc event callback end");
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
    a_thread->poll[a_esocket->poll_index].events= a_esocket->poll_base_flags;
    if( a_esocket->flags & DAP_SOCK_READY_TO_READ)
        a_thread->poll[a_esocket->poll_index].revents |= POLLIN;
    if( a_esocket->flags & DAP_SOCK_READY_TO_WRITE)
        a_thread->poll[a_esocket->poll_index].revents |= POLLOUT;
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
#ifdef DAP_EVENTS_CAPS_EPOLL
    l_es->ev.events      = l_es->ev_base_flags ;
    l_es->ev.data.ptr    = l_es;
    if( epoll_ctl(a_thread->epoll_ctl, EPOLL_CTL_ADD, l_es->socket, &l_es->ev) != 0 ){
#ifdef DAP_OS_WINDOWS
    errno = WSAGetLastError();
#endif
        log_it(L_CRITICAL, "Can't add queue input on epoll ctl, err: %d", errno);
        return NULL;
    }
#elif defined(DAP_EVENTS_CAPS_POLL)
    l_es->poll_index = a_thread->poll_count;
    a_thread->poll[a_thread->poll_count].fd = l_es->fd;
    a_thread->poll[a_thread->poll_count].events = l_es->poll_base_flags;
    a_thread->esockets[a_thread->poll_count] = l_es;
    a_thread->poll_count++;
#else
#error "Not defined dap_proc_thread_create_queue_ptr() on your platform"
#endif
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
#ifdef DAP_OS_WINDOWS 
	if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST))
        log_it(L_ERROR, "Couldn't set thread priority, err: %d", GetLastError());
#else
    pthread_setschedparam(pthread_self(),SCHED_BATCH ,&l_shed_params);
#endif
    l_thread->proc_queue = dap_proc_queue_create(l_thread);

    // Init proc_queue for related worker
    dap_worker_t * l_worker_related = dap_events_worker_get(l_thread->cpu_id);
    assert(l_worker_related);
    l_worker_related->proc_queue = l_thread->proc_queue;
    l_worker_related->proc_queue_input = dap_events_socket_queue_ptr_create_input(l_worker_related->proc_queue->esocket);

    dap_events_socket_assign_on_worker_mt(l_worker_related->proc_queue_input,l_worker_related);

    l_thread->proc_event = dap_events_socket_create_type_event_unsafe(NULL, s_proc_event_callback);
    l_thread->proc_event->_inheritor = l_thread; // we pass thread through it
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
        log_it(L_CRITICAL, "Can't add proc queue %d on epoll ctl, error", l_thread->proc_queue->esocket->socket, errno);
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
    bool l_poll_compress = false;
    l_thread->poll = DAP_NEW_Z_SIZE(struct pollfd,l_thread->poll_count_max *sizeof (*l_thread->poll));
    l_thread->esockets = DAP_NEW_Z_SIZE(dap_events_socket_t*,l_thread->poll_count_max *sizeof (*l_thread->esockets));

    // Add proc queue
    l_thread->poll[l_thread->poll_count].fd = l_thread->proc_queue->esocket->fd;
    l_thread->poll[l_thread->poll_count].events = l_thread->proc_queue->esocket->poll_base_flags;
    l_thread->esockets[l_thread->poll_count] = l_thread->proc_queue->esocket;
    l_thread->poll_count++;

    // Add proc event
    l_thread->poll[l_thread->poll_count].fd = l_thread->proc_event->fd;
    l_thread->poll[l_thread->poll_count].events = l_thread->proc_event->poll_base_flags;
    l_thread->esockets[l_thread->poll_count] = l_thread->proc_event;
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

#else
#error "Unimplemented poll events analog for this platform"
#endif

    //We've started!
    pthread_mutex_lock(&l_thread->started_mutex);
    pthread_mutex_unlock(&l_thread->started_mutex);
    pthread_cond_broadcast(&l_thread->started_cond);
    // Main loop
    while (! l_thread->signal_kill){

#ifdef DAP_EVENTS_CAPS_EPOLL
        //log_it(L_DEBUG, "Epoll_wait call");
        int l_selected_sockets = epoll_wait(l_thread->epoll_ctl, l_epoll_events, DAP_EVENTS_SOCKET_MAX, -1);
        size_t l_sockets_max = (size_t)l_selected_sockets;
#elif defined (DAP_EVENTS_CAPS_POLL)
        int l_selected_sockets = poll(l_thread->poll,l_thread->poll_count,-1);
        size_t l_sockets_max = l_thread->poll_count;
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
            bool l_flag_hup, l_flag_rdhup, l_flag_read, l_flag_write, l_flag_error,
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
                log_it(L_WARNING,"selected_sockets(%d) is bigger then poll count (%u)", l_selected_sockets, l_thread->poll_count);
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
#else
#error "Unimplemented fetch esocket after poll"
#endif

            if(!l_cur) {
                log_it(L_ERROR, "dap_events_socket NULL");
                continue;
            }
            if(s_debug_reactor)
                log_it(L_DEBUG, "Proc thread #%u esocket %p fd=%d type=%d flags=0x%0X (%s:%s:%s:%s:%s:%s:%s:%s)", l_thread->cpu_id, l_cur, l_cur->socket,
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
                log_it(L_ERROR,"Some error on proc thread #%u with %d socket: %s(%d)",l_thread->cpu_id, l_cur->socket, l_errbuf, l_errno);
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
                                    log_it(L_ERROR, "An error occured on sending message to queue, errno: 0x%x", hr);
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
                                    volatile char * l_ptr = (char *) l_cur->buf_out;
                                    volatile void *l_ptr_in;
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
                            l_cur->flags ^= DAP_SOCK_READY_TO_WRITE;
                            dap_proc_thread_esocket_update_poll_flags(l_thread, l_cur);
                        }
                    }

                }else{
                    log_it(L_DEBUG,"(!) Write event receieved but nothing in buffer, switching off this flag");
                    l_cur->flags ^= DAP_SOCK_READY_TO_WRITE;
                    dap_proc_thread_esocket_update_poll_flags(l_thread, l_cur);
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
#else
#error "Unimplemented poll ctl analog for this platform"
#endif
            }

        }
#ifdef DAP_EVENTS_CAPS_POLL
      /***********************************************************/
       /* If the compress_array flag was turned on, we need       */
       /* to squeeze together the array and decrement the number  */
       /* of file descriptors. We do not need to move back the    */
       /* events and revents fields because the events will always*/
       /* be POLLIN in this case, and revents is output.          */
       /***********************************************************/
       if ( l_poll_compress){
           l_poll_compress = false;
           for (size_t i = 0; i < l_thread->poll_count ; i++)  {
               if ( l_thread->poll[i].fd == -1){
                    for(size_t j = i; j +1 < l_thread->poll_count; j++){
                        l_thread->poll[j].fd = l_thread->poll[j+1].fd;
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
    log_it(L_NOTICE, "Stop processing thread #%u", l_thread->cpu_id);

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
    //log_it(L_DEBUG,"Remove esocket %p from proc thread and send it to worker #%u",a_esocket, a_worker->id);
    dap_events_socket_assign_on_worker_inter(l_es_assign_input, a_esocket);
    l_es_assign_input->flags |= DAP_SOCK_READY_TO_WRITE;
    dap_proc_thread_esocket_update_poll_flags(a_thread, l_es_assign_input);
    return true;
}

/**
 * @brief dap_proc_thread_esocket_write_inter
 * @param a_thread
 * @param a_worker
 * @param a_esocket
 * @param a_data
 * @param a_data_size
 * @return
 */
int dap_proc_thread_esocket_write_inter(dap_proc_thread_t * a_thread,dap_worker_t * a_worker,  dap_events_socket_t *a_esocket,
                                        const void * a_data, size_t a_data_size)
{
    dap_events_socket_t * l_es_io_input = a_thread->queue_io_input[a_worker->id];
    dap_events_socket_write_inter(l_es_io_input,a_esocket, a_data, a_data_size);
    l_es_io_input->flags |= DAP_SOCK_READY_TO_WRITE;
    dap_proc_thread_esocket_update_poll_flags(a_thread, l_es_io_input);
    return 0;
}


/**
 * @brief dap_proc_thread_esocket_write_f_inter
 * @param a_thread
 * @param a_worker
 * @param a_esocket
 * @param a_format
 * @return
 */
int dap_proc_thread_esocket_write_f_inter(dap_proc_thread_t * a_thread,dap_worker_t * a_worker,  dap_events_socket_t *a_esocket,
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
    char * l_data = DAP_NEW_SIZE(char,l_data_size+1); if (!l_data) return -1;
    l_data_size = dap_vsprintf(l_data,a_format,ap_copy);
    va_end(ap_copy);

    dap_events_socket_write_inter(l_es_io_input,a_esocket, l_data, l_data_size);
    l_es_io_input->flags |= DAP_SOCK_READY_TO_WRITE;
    dap_proc_thread_esocket_update_poll_flags(a_thread, l_es_io_input);
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

    a_thread->queue_callback_input[a_worker_id]->flags |= DAP_SOCK_READY_TO_WRITE;
    dap_proc_thread_esocket_update_poll_flags(a_thread, a_thread->queue_callback_input[a_worker_id]);

}
