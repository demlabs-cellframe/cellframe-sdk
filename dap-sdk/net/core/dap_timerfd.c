/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * Dmitriy Gerasimov <dmitriy.gerasimov@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2021
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

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#ifdef DAP_OS_WINDOWS
#include <winsock2.h>
#endif

#include "dap_common.h"
#include "dap_events.h"
#include "dap_worker.h"
#include "dap_events_socket.h"
#include "dap_timerfd.h"

#define LOG_TAG "dap_timerfd"
static void s_es_callback_timer(struct dap_events_socket *a_event_sock);

#ifdef DAP_OS_WINDOWS
    static HANDLE hTimerQueue = NULL;
#endif

/**
 * @brief dap_events_socket_init Init clients module
 * @return Zero if ok others if no
 */
int dap_timerfd_init()
{
#ifdef DAP_OS_WINDOWS
        hTimerQueue = CreateTimerQueue();
        if (!hTimerQueue) {
            log_it(L_CRITICAL, "Timer queue failed, err %lu", GetLastError());
            return -4;
        }
#endif
    log_it(L_NOTICE, "Initialized timerfd");
    return 0;
}

/**
 * @brief dap_timerfd_start
 * @param a_timeout_ms
 * @param a_callback
 * @return new allocated dap_timerfd_t structure or NULL if error
 */
dap_timerfd_t* dap_timerfd_start(uint64_t a_timeout_ms, dap_timerfd_callback_t a_callback, void *a_callback_arg)
{
     return dap_timerfd_start_on_worker(dap_events_worker_get_auto(), a_timeout_ms, a_callback, a_callback_arg);
}

#ifdef DAP_OS_WINDOWS
void __stdcall TimerAPCb(void* arg, DWORD low, DWORD high) {  // Timer high value.
    UNREFERENCED_PARAMETER(low)
    UNREFERENCED_PARAMETER(high)
    dap_timerfd_t *l_timerfd = (dap_timerfd_t *)arg;
    if (dap_sendto(l_timerfd->tfd, l_timerfd->port, NULL, 0) == SOCKET_ERROR) {
        log_it(L_CRITICAL, "Error occured on writing into socket from APC, errno: %d", WSAGetLastError());
    }
}

void __stdcall TimerRoutine(void* arg, BOOLEAN flag) {
    UNREFERENCED_PARAMETER(flag)
    dap_timerfd_t *l_timerfd = (dap_timerfd_t *)arg;
    if (dap_sendto(l_timerfd->tfd, l_timerfd->port, NULL, 0) == SOCKET_ERROR) {
        log_it(L_CRITICAL, "Error occured on writing into socket from timer routine, errno: %d", WSAGetLastError());
     }
}
#endif


/**
 * @brief dap_timerfd_start_on_worker
 * @param a_worker
 * @param a_timeout_ms
 * @param a_callback
 * @param a_callback_arg
 * @return
 */
dap_timerfd_t* dap_timerfd_start_on_worker(dap_worker_t * a_worker, uint64_t a_timeout_ms, dap_timerfd_callback_t a_callback, void *a_callback_arg)
{
    dap_timerfd_t* l_timerfd = dap_timerfd_create( a_timeout_ms, a_callback, a_callback_arg);
    if(l_timerfd){
        dap_worker_add_events_socket(l_timerfd->events_socket, a_worker);
        l_timerfd->worker = a_worker;
        return l_timerfd;
    }else{
        log_it(L_CRITICAL,"Can't create timer");
        return NULL;
    }
}

/**
 * @brief dap_timerfd_start_on_proc_thread
 * @param a_proc_thread
 * @param a_timeout_ms
 * @param a_callback
 * @param a_callback_arg
 * @return
 */
dap_timerfd_t* dap_timerfd_start_on_proc_thread(dap_proc_thread_t * a_proc_thread, uint64_t a_timeout_ms, dap_timerfd_callback_t a_callback, void *a_callback_arg)
{
    dap_timerfd_t* l_timerfd = dap_timerfd_create( a_timeout_ms, a_callback, a_callback_arg);
    return l_timerfd;
}

/**
 * @brief dap_timerfd_create
 * @param a_timeout_ms
 * @param a_callback
 * @param a_callback_arg
 * @return
 */
dap_timerfd_t* dap_timerfd_create(uint64_t a_timeout_ms, dap_timerfd_callback_t a_callback, void *a_callback_arg)
{
    dap_timerfd_t *l_timerfd = DAP_NEW(dap_timerfd_t);
    if(!l_timerfd)
        return NULL;
    // create events_socket for timer file descriptor
    dap_events_socket_callbacks_t l_s_callbacks;
    memset(&l_s_callbacks,0,sizeof (l_s_callbacks));
    l_s_callbacks.timer_callback = s_es_callback_timer;

    dap_events_socket_t * l_events_socket = dap_events_socket_wrap_no_add(dap_events_get_default(), -1, &l_s_callbacks);
    l_events_socket->type = DESCRIPTOR_TYPE_TIMER;

    // pass l_timerfd to events_socket
    l_events_socket->_inheritor = l_timerfd;

    // fill out dap_timerfd_t structure
    l_timerfd->timeout_ms       = a_timeout_ms;
    l_timerfd->callback         = a_callback;
    l_timerfd->callback_arg     = a_callback_arg;
    l_timerfd->events_socket    = l_events_socket;
    l_timerfd->esocket_uuid = l_events_socket->uuid;
    
#if defined DAP_OS_LINUX
    struct itimerspec l_ts;
    int l_tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if(l_tfd == -1) {
        log_it(L_WARNING, "dap_timerfd_start() failed: timerfd_create() errno=%d\n", errno);
        DAP_DELETE(l_timerfd);
        return NULL;
    }
    // repeat never
    l_ts.it_interval.tv_sec = 0;
    l_ts.it_interval.tv_nsec = 0;
    // timeout for timer
    l_ts.it_value.tv_sec = a_timeout_ms / 1000;
    l_ts.it_value.tv_nsec = (a_timeout_ms % 1000) * 1000000;
    if(timerfd_settime(l_tfd, 0, &l_ts, NULL) < 0) {
        log_it(L_WARNING, "dap_timerfd_start() failed: timerfd_settime() errno=%d\n", errno);
        close(l_tfd);
        DAP_DELETE(l_timerfd);
        return NULL;
    }
    l_events_socket->socket = l_tfd;
#elif defined (DAP_OS_BSD)
    l_events_socket->kqueue_base_flags = EV_ONESHOT;
    l_events_socket->kqueue_base_filter = EVFILT_TIMER;
    l_events_socket->socket = arc4random();
#ifdef DAP_OS_DARWIN
    // We have all timers not accurate but more power safe
    // Usualy we don't need exactly 1-5-10 seconds so let it be so
    // TODO make absolute timer without power-saving flags
    l_events_socket->kqueue_base_fflags = NOTE_BACKGROUND;
    l_events_socket->kqueue_data =(int64_t) a_timeout_ms;
#else
    l_events_socket->kqueue_base_fflags = NOTE_MSECONDS;
    l_events_socket->kqueue_data =(int64_t) a_timeout_ms;
#endif


#elif defined (DAP_OS_WINDOWS)
    /*HANDLE l_th = CreateWaitableTimer(NULL, true, NULL);
    if (!l_th) {
        log_it(L_CRITICAL, "Waitable timer not created, error %d", GetLastError());
        DAP_DELETE(l_timerfd);
        return NULL;
    }*/
    l_timerfd->th = NULL;
    SOCKET l_tfd = socket(AF_INET, SOCK_DGRAM, 0);
    int buffsize = 1024;

    setsockopt(l_tfd, SOL_SOCKET, SO_RCVBUF, (char *)&buffsize, sizeof(int));

    unsigned long l_mode = 1;
    ioctlsocket(l_tfd, FIONBIO, &l_mode);

    int l_addr_len;
    struct sockaddr_in l_addr;
    l_addr.sin_family = AF_INET;
    IN_ADDR _in_addr = { { .S_addr = htonl(INADDR_LOOPBACK) } };
    l_addr.sin_addr = _in_addr;
    l_addr.sin_port = 0; //l_tfd + 32768;
    l_addr_len = sizeof(struct sockaddr_in);
    if (bind(l_tfd, (struct sockaddr*)&l_addr, sizeof(l_addr)) < 0) {
        log_it(L_ERROR, "Bind error: %d", WSAGetLastError());
    } else {
        int dummy = 100;
        getsockname(l_tfd, (struct sockaddr*)&l_addr, &dummy);
        l_timerfd->port = l_addr.sin_port;
        //log_it(L_DEBUG, "Bound to port %d", l_addr.sin_port);
    }

    /*LARGE_INTEGER l_due_time;
    l_due_time.QuadPart = (long long)a_timeout_ms * _MSEC;
    if (!SetWaitableTimer(l_th, &l_due_time, 0, TimerAPCb, l_timerfd, false)) {
        log_it(L_CRITICAL, "Waitable timer not set, error %d", GetLastError());
        CloseHandle(l_th);
        DAP_DELETE(l_timerfd);
        return NULL;
    } */
    if (!CreateTimerQueueTimer(&l_timerfd->th, hTimerQueue,
                               (WAITORTIMERCALLBACK)TimerRoutine, l_timerfd, (unsigned long)a_timeout_ms, 0, 0)) {
        log_it(L_CRITICAL, "Timer not set, error %lu", GetLastError());
        DAP_DELETE(l_timerfd);
        return NULL;
    }
    l_events_socket->socket = l_tfd;
#endif
    
#if defined (DAP_OS_LINUX) || defined (DAP_OS_WINDOWS)    
    l_timerfd->tfd              = l_tfd;
#endif
//#ifdef DAP_OS_WINDOWS
    //l_timerfd->th               = l_th;
//#endif
    return l_timerfd;
}

static void s_timerfd_reset(dap_timerfd_t *a_timerfd, dap_events_socket_t *a_event_sock)
{
#if defined DAP_OS_LINUX
    struct itimerspec l_ts;
    // repeat never
    l_ts.it_interval.tv_sec = 0;
    l_ts.it_interval.tv_nsec = 0;
    // timeout for timer
    l_ts.it_value.tv_sec = a_timerfd->timeout_ms / 1000;
    l_ts.it_value.tv_nsec = (a_timerfd->timeout_ms % 1000) * 1000000;
    if(timerfd_settime(a_timerfd->tfd, 0, &l_ts, NULL) < 0) {
        log_it(L_WARNING, "Reset timerfd failed: timerfd_settime() errno=%d\n", errno);
    }
#elif defined (DAP_OS_BSD)
    dap_worker_add_events_socket_unsafe(a_event_sock,a_event_sock->worker);
//struct kevent * l_event = &a_event_sock->kqueue_event;
//EV_SET(l_event, 0, a_event_sock->kqueue_base_filter, a_event_sock->kqueue_base_flags,a_event_sock->kqueue_base_fflags,a_event_sock->kqueue_data,a_event_sock);
//kevent(a_event_sock->worker->kqueue_fd,l_event,1,NULL,0,NULL);
#elif defined (DAP_OS_WINDOWS)
    /*LARGE_INTEGER l_due_time;
    l_due_time.QuadPart = (long long)a_timerfd->timeout_ms * _MSEC;
    if (!SetWaitableTimer(a_timerfd->th, &l_due_time, 0, TimerAPCb, a_timerfd, false)) {
        log_it(L_CRITICAL, "Waitable timer not reset, error %d", GetLastError());
        CloseHandle(a_timerfd->th);
    }*/ // Wtf is this entire thing for?...
#else
#error "No timer reset realization for your platform"
#endif

#ifndef DAP_OS_BSD
    dap_events_socket_set_readable_unsafe(a_event_sock, true);
#endif
}

/**
 * @brief s_es_callback_timer
 * @param a_event_sock
 */
static void s_es_callback_timer(struct dap_events_socket *a_event_sock)
{
    dap_timerfd_t *l_timerfd = a_event_sock->_inheritor;
    // run user's callback
    if(l_timerfd->callback && l_timerfd->callback(l_timerfd->callback_arg)) {
        s_timerfd_reset(l_timerfd, a_event_sock);
    } else {
        l_timerfd->events_socket->flags |= DAP_SOCK_SIGNAL_CLOSE;
    }
}

/**
 * @brief dap_timerfd_reset
 * @param a_tfd
 */
void dap_timerfd_reset(dap_timerfd_t *a_timerfd)
{
    if (!a_timerfd)
        return;
    dap_events_socket_t *l_sock = NULL;
    if (a_timerfd->worker)
        l_sock = dap_worker_esocket_find_uuid(a_timerfd->worker, a_timerfd->esocket_uuid);
    else if (a_timerfd->proc_thread)
        l_sock = a_timerfd->events_socket;
    if (l_sock)
        s_timerfd_reset(a_timerfd, l_sock);
}

/**
 * @brief dap_timerfd_stop
 * @param a_tfd
 */
void dap_timerfd_delete(dap_timerfd_t *a_timerfd)
{
    if (a_timerfd->events_socket->worker)
        dap_events_socket_remove_and_delete_mt(a_timerfd->events_socket->worker, a_timerfd->esocket_uuid);
}
