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
#include "dap_server.h"

#if defined(DAP_EVENTS_CAPS_EPOLL)
#include <sys/epoll.h>
#elif defined (DAP_EVENTS_CAPS_POLL)
#include <poll.h>
#else
#error "Unimplemented poll for this platform"
#endif

#include "dap_events.h"
#include "dap_events_socket.h"
#include "dap_proc_thread.h"

#define LOG_TAG "dap_proc_thread"

static size_t s_threads_count = 0;
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
    for (size_t i = 0; i < s_threads_count; i++ ){
        pthread_cancel(s_threads[i].thread_id);
        pthread_join(s_threads[i].thread_id, NULL);
    }
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
static void s_proc_event_callback(dap_events_socket_t * a_esocket, void * a_value)
{
    (void) a_value;
    //log_it(L_DEBUG, "Proc event callback");
    dap_proc_thread_t * l_thread = (dap_proc_thread_t *) a_esocket->_inheritor;
    dap_proc_queue_item_t * l_item = l_thread->proc_queue->items;
    dap_proc_queue_item_t * l_item_old = NULL;
    bool l_is_anybody_for_repeat=false;
    while(l_item){
        bool l_is_finished = l_item->callback(l_thread, l_item->callback_arg);
        if (l_is_finished){
            if(l_item_old){
                l_item_old->next = l_item->next;
                DAP_DELETE(l_item);
                l_item = l_item_old->next;
            }else{
                l_thread->proc_queue->items = l_item->next;
                DAP_DELETE(l_item);
                l_item = l_thread->proc_queue->items;
            }

        }else{
            l_item_old = l_item;
            l_item=l_item->next;
        }
        l_is_anybody_for_repeat = !l_is_finished;
    }
    if(l_is_anybody_for_repeat) // Arm event if we have smth to proc again
        dap_events_socket_event_signal(a_esocket,1);
}

static void * s_proc_thread_function(void * a_arg)
{

    dap_proc_thread_t * l_thread = (dap_proc_thread_t*) a_arg;
    assert(l_thread);
    dap_cpu_assign_thread_on(l_thread->cpu_id);
    struct sched_param l_shed_params;
    l_shed_params.sched_priority = 0;
    pthread_setschedparam(pthread_self(),SCHED_BATCH ,&l_shed_params);
    l_thread->proc_queue = dap_proc_queue_create(l_thread);


    l_thread->proc_event = dap_events_socket_create_type_queue_ptr_unsafe(NULL, s_proc_event_callback);
    l_thread->proc_event->_inheritor = l_thread; // we pass thread through it

#ifdef DAP_EVENTS_CAPS_EPOLL
    struct epoll_event l_epoll_events[DAP_EVENTS_SOCKET_MAX], l_ev;
    memset(l_epoll_events, 0,sizeof (l_epoll_events));

    // Create epoll ctl
    l_thread->epoll_ctl = epoll_create( DAP_EVENTS_SOCKET_MAX );

    // add proc queue
    l_ev.events = l_thread->proc_queue->esocket->ev_base_flags;
    l_ev.data.ptr = l_thread->proc_queue->esocket;
    if( epoll_ctl(l_thread->epoll_ctl, EPOLL_CTL_ADD, l_thread->proc_queue->esocket->socket , &l_ev) != 0 ){
        log_it(L_CRITICAL, "Can't add proc queue on epoll ctl");
        return NULL;
    }

    // Add proc event
    l_ev.events = l_thread->proc_event->ev_base_flags ;
    l_ev.data.ptr = l_thread->proc_event;
    if( epoll_ctl(l_thread->epoll_ctl, EPOLL_CTL_ADD, l_thread->proc_event->fd , &l_ev) != 0 ){
        log_it(L_CRITICAL, "Can't add proc queue on epoll ctl");
        return NULL;
    }
#elif defined(DAP_EVENTS_CAPS_POLL)
    size_t l_poll_count_max = DAP_EVENTS_SOCKET_MAX;
    size_t l_poll_count = 0;
    bool l_poll_compress = false;
    struct pollfd * l_poll = DAP_NEW_Z_SIZE(struct pollfd,l_poll_count_max *sizeof (*l_poll));
    dap_events_socket_t ** l_esockets = DAP_NEW_Z_SIZE(dap_events_socket_t*,l_poll_count_max *sizeof (*l_esockets));

    // Add proc queue
    l_poll[0].fd = l_thread->proc_queue->esocket->fd;
    l_poll[0].events = l_thread->proc_queue->esocket->poll_base_flags;
    l_esockets[0] = l_thread->proc_queue->esocket;
    l_poll_count++;

    // Add proc event
    l_poll[1].fd = l_thread->proc_event->fd;
    l_poll[1].events = l_thread->proc_event->poll_base_flags;
    l_esockets[1] = l_thread->proc_event;
    l_poll_count++;

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
        size_t l_sockets_max = l_selected_sockets;
#elif defined (DAP_EVENTS_CAPS_POLL)
        int l_selected_sockets = poll(l_poll,l_poll_count,-1);
        size_t l_sockets_max = l_poll_count;
#else
#error "Unimplemented poll wait analog for this platform"
#endif
        //log_it(L_DEBUG,"Proc thread waked up");
        if(l_selected_sockets == -1) {
            if( errno == EINTR)
                continue;
            int l_errno = errno;
            char l_errbuf[128];
            strerror_r(l_errno, l_errbuf, sizeof (l_errbuf));
            log_it(L_ERROR, "Proc thread #%d got errno:\"%s\" (%d)", l_thread->cpu_id , l_errbuf, l_errno);
            break;
        }
        for(size_t n = 0; n < l_sockets_max; n++) {
            dap_events_socket_t * l_cur;
            bool l_flag_hup, l_flag_rdhup, l_flag_read, l_flag_write, l_flag_error;
#ifdef DAP_EVENTS_CAPS_EPOLL
            l_cur = (dap_events_socket_t *) l_epoll_events[n].data.ptr;
            uint32_t l_cur_events = l_epoll_events[n].events;
            l_flag_hup = l_cur_events & EPOLLHUP;
            l_flag_rdhup = l_cur_events & EPOLLHUP;
            l_flag_write = l_cur_events & EPOLLOUT;
            l_flag_read = l_cur_events & EPOLLIN;
            l_flag_error = l_cur_events & EPOLLERR;
#elif defined ( DAP_EVENTS_CAPS_POLL)
            if(n>=(int32_t)l_poll_count){
                log_it(L_WARNING,"selected_sockets(%d) is bigger then poll count (%u)", l_selected_sockets, l_poll_count);
                break;
            }
            short l_cur_events = l_poll[n].revents ;
            if (!l_cur_events)
                continue;
            l_cur = l_esockets[n];
            l_flag_hup = l_cur_events & POLLHUP;
            l_flag_rdhup = l_cur_events & POLLHUP;
            l_flag_write = l_cur_events & POLLOUT;
            l_flag_read = l_cur_events & POLLIN;
            l_flag_error = l_cur_events & POLLERR;
#else
#error "Unimplemented fetch esocket after poll"
#endif

            if(!l_cur) {
                log_it(L_ERROR, "dap_events_socket NULL");
                continue;
            }
            time_t l_cur_time = time( NULL);
            l_cur->last_time_active = l_cur_time;
            if (l_flag_error){
                int l_errno = errno;
                char l_errbuf[128];
                strerror_r(l_errno, l_errbuf,sizeof (l_errbuf));
                log_it(L_ERROR,"Some error on proc thread #%u with %d socket: %s(%d)",l_thread->cpu_id, l_cur->socket, l_errbuf, l_errno);
                if(l_cur->callbacks.error_callback)
                    l_cur->callbacks.error_callback(l_cur,errno);
            }
            if (l_flag_read ){
                switch (l_cur->type) {
                    case DESCRIPTOR_TYPE_QUEUE:
                            dap_events_socket_queue_proc_input_unsafe(l_cur);
                    break;
                    case DESCRIPTOR_TYPE_EVENT:
                            dap_events_socket_event_proc_input_unsafe (l_cur);
                    break;

                    default:{ log_it(L_ERROR, "Unprocessed descriptor type accepted in proc thread loop"); }
                }
            }
            if(l_cur->flags & DAP_SOCK_SIGNAL_CLOSE){
#ifdef DAP_EVENTS_CAPS_EPOLL
                if ( epoll_ctl( l_thread->epoll_ctl, EPOLL_CTL_DEL, l_cur->fd, &l_cur->ev ) == -1 )
                    log_it( L_ERROR,"Can't remove event socket's handler from the epoll ctl" );
                //else
                //    log_it( L_DEBUG,"Removed epoll's event from proc thread #%u", l_thread->cpu_id );
                if (l_cur->callbacks.delete_callback)
                    l_cur->callbacks.delete_callback(l_cur, l_thread);
                if(l_cur->_inheritor)
                    DAP_DELETE(l_cur->_inheritor);
                DAP_DELETE(l_cur);
#elif defined (DAP_EVENTS_CAPS_POLL)
                l_poll[n].fd = -1;
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
           for (size_t i = 0; i < l_poll_count ; i++)  {
               if ( l_poll[i].fd == -1){
                   for(size_t j = i; j < l_poll_count-1; j++){
                       l_poll[j].fd = l_poll[j+1].fd;
                       l_esockets[j] = l_esockets[j+1];
                       l_esockets[j]->poll_index = j;
                   }
                   i--;
                   l_poll_count--;
               }
           }
       }
#endif
    }
    log_it(L_NOTICE, "Stop processing thread #%u", l_thread->cpu_id);
    return NULL;
}


