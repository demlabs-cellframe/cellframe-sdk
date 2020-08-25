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

#if defined(DAP_EVENTS_CAPS_WEPOLL)
#elif defined(DAP_EVENTS_CAPS_EPOLL)
#include <sys/epoll.h>
#else
#error "Unimplemented poll for this platform"
#endif

#include "dap_events.h"
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
        pthread_create( &s_threads[i].thread_id,NULL, s_proc_thread_function, &s_threads[i] );
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

static void * s_proc_thread_function(void * a_arg)
{
    dap_proc_thread_t * l_thread = (dap_proc_thread_t*) a_arg;
    assert(l_thread);
#ifdef DAP_EVENTS_CAPS_EPOLL
    struct epoll_event l_epoll_events[DAP_MAX_EPOLL_EVENTS] = {{0}}, l_ev={0};
    l_thread->epoll_ctl = epoll_create( DAP_MAX_EPOLL_EVENTS );
#else
#error "Unimplemented poll events analog for this platform"
#endif

    //We've started!
    pthread_cond_broadcast(&l_thread->started_cond);
    // Main loop
    while (! l_thread->signal_kill){

#ifdef DAP_EVENTS_CAPS_EPOLL
        int l_selected_sockets = epoll_wait(l_thread->epoll_ctl, l_epoll_events, DAP_MAX_EPOLL_EVENTS, -1);
#else
#error "Unimplemented poll wait analog for this platform"
#endif
    }
}


