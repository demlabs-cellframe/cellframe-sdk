/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
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
#ifdef DAP_OS_UNIX
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <inttypes.h>

#include "dap_common.h"
#include "dap_events.h"
#include "dap_worker.h"
#include "dap_events_socket.h"
#include "dap_timerfd.h"

#define LOG_TAG "dap_timerfd"
static void s_es_callback_timer(struct dap_events_socket *a_event_sock);


/**
 * @brief dap_events_socket_init Init clients module
 * @return Zero if ok others if no
 */
int dap_timerfd_init()
{
    log_it(L_NOTICE, "Initialized timerfd");
    return 0;
}

/**
 * @brief dap_timerfd_start
 * @param a_timeout_ms
 * @param a_callback
 * @return new allocated dap_timerfd_t structure or NULL if error
 */
dap_timerfd_t* dap_timerfd_start(uint64_t a_timeout_ms, dap_timerfd_callback_t a_callback, void *a_callback_arg, bool a_repeated)
{
     return dap_timerfd_start_on_worker(dap_events_worker_get_auto(), a_timeout_ms, a_callback, a_callback_arg, a_repeated);
}

/**
 * @brief dap_timerfd_start_on_worker
 * @param a_worker
 * @param a_timeout_ms
 * @param a_callback
 * @param a_callback_arg
 * @return
 */
dap_timerfd_t* dap_timerfd_start_on_worker(dap_worker_t * a_worker, uint64_t a_timeout_ms, dap_timerfd_callback_t a_callback, void *a_callback_arg, bool a_repeated)

{
    struct itimerspec l_ts;
    int l_tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if(l_tfd == -1) {
        log_it(L_WARNING, "dap_timerfd_start() failed: timerfd_create() errno=%d\n", errno);
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
        return NULL;
    }

    // create dap_timerfd_t structure
    dap_timerfd_t *l_timerfd = DAP_NEW(dap_timerfd_t);

    // create events_socket for timer file descriptor
    dap_events_socket_callbacks_t l_s_callbacks;
    memset(&l_s_callbacks,0,sizeof (l_s_callbacks));
    l_s_callbacks.timer_callback = s_es_callback_timer;

    dap_events_socket_t * l_events_socket = dap_events_socket_wrap_no_add(a_worker->events, l_tfd, &l_s_callbacks);
    l_events_socket->type = DESCRIPTOR_TYPE_TIMER;
    // pass l_timerfd to events_socket
    l_events_socket->_inheritor = l_timerfd;

    // fill out dap_timerfd_t structure
    l_timerfd->timeout_ms = a_timeout_ms;
    l_timerfd->tfd = l_tfd;
    l_timerfd->events_socket = l_events_socket;
    l_timerfd->callback = a_callback;
    l_timerfd->callback_arg = a_callback_arg;
    l_timerfd->repeated = a_repeated;
    dap_worker_add_events_socket(l_events_socket, a_worker);

    return l_timerfd;
}

/**
 * @brief s_es_callback_timer
 * @param a_event_sock
 */
static void s_es_callback_timer(struct dap_events_socket *a_event_sock)
{
    uint64_t l_ptiu64;
    dap_timerfd_t *l_timerfd = a_event_sock->_inheritor;
    // run user's callback
    if(l_timerfd->callback)
        l_timerfd->callback(l_timerfd->callback_arg);
    if (l_timerfd->repeated) {
        //printf("\nread() returned %d, %d\n", l_ptiu64, l_read_ret);
        struct itimerspec l_ts;
        // repeat never
        l_ts.it_interval.tv_sec = 0;
        l_ts.it_interval.tv_nsec = 0;
        // timeout for timer
        l_ts.it_value.tv_sec = l_timerfd->timeout_ms / 1000;
        l_ts.it_value.tv_nsec = (l_timerfd->timeout_ms % 1000) * 1000000;
        if(timerfd_settime(l_timerfd->tfd, 0, &l_ts, NULL) < 0) {
            log_it(L_WARNING, "callback_timerfd_read() failed: timerfd_settime() errno=%d\n", errno);
        }
        dap_events_socket_set_readable_unsafe(a_event_sock, true);
    } else {
        dap_events_socket_remove_and_delete_unsafe(l_timerfd->events_socket, false);
    }
}

/**
 * @brief dap_timerfd_stop
 * @param a_tfd
 * @param a_callback
 */
void dap_timerfd_delete(dap_timerfd_t *l_timerfd)
{
    dap_events_socket_remove_and_delete_mt(l_timerfd->events_socket->worker, l_timerfd->events_socket);
}
#else
#error "No dap_timerfd realization for your platform"
#endif
