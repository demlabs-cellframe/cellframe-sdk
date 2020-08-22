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
#ifndef WIN32
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
#include "dap_events_socket.h"
#include "dap_timerfd.h"

#define LOG_TAG "dap_timerfd"

void callback_timerfd_read(struct dap_events_socket *a_event_sock, void * arg)
{
    uint64_t l_ptiu64;
    size_t l_read_ret;
    do {
        l_read_ret = dap_events_socket_pop_from_buf_in(a_event_sock, &l_ptiu64, sizeof(l_ptiu64));

        if(l_read_ret > 0) {
            dap_timerfd_t *l_timerfd = a_event_sock->_inheritor;
            //printf("\nread() returned %d, %d\n", l_ptiu64, l_read_ret);
            struct itimerspec l_ts;
            // first expiration in 0 seconds after times start
            l_ts.it_interval.tv_sec = 0;
            l_ts.it_interval.tv_nsec = 0;
            // timeout for timer
            l_ts.it_value.tv_sec = l_timerfd->timeout_ms / 1000;
            l_ts.it_value.tv_nsec = (l_timerfd->timeout_ms % 1000) * 1000000;
            if(timerfd_settime(l_timerfd->tfd, 0, &l_ts, NULL) < 0) {
                log_it(L_WARNING, "callback_timerfd_read() failed: timerfd_settime() errno=%d\n", errno);
            }
            // run user's callback
            if(l_timerfd->callback)
                l_timerfd->callback(l_timerfd->callback_arg);
        }
    } while(l_read_ret > 0);
    dap_events_socket_set_readable_unsafe(a_event_sock, true);
}

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
dap_timerfd_t* dap_timerfd_start(uint64_t a_timeout_ms, dap_timerfd_callback_t *a_callback, void *a_callback_arg)
{
    struct itimerspec l_ts;
    int l_tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if(l_tfd == -1) {
        log_it(L_WARNING, "dap_timerfd_start() failed: timerfd_create() errno=%d\n", errno);
        return NULL;
    }
    // first expiration in 0 seconds after times start
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
    static dap_events_socket_callbacks_t l_s_callbacks = {
        .read_callback = callback_timerfd_read,
        .write_callback = NULL,
        .error_callback = NULL,
        .delete_callback = NULL
    };
    dap_events_socket_t * l_events_socket = dap_events_socket_wrap_no_add(NULL, l_tfd, &l_s_callbacks);
    l_events_socket->type = DESCRIPTOR_TYPE_FILE;
    dap_events_socket_create_after(l_events_socket);
    // pass l_timerfd to events_socket
    l_events_socket->_inheritor = l_timerfd;

    // fill out dap_timerfd_t structure
    l_timerfd->timeout_ms = a_timeout_ms;
    l_timerfd->tfd = l_tfd;
    l_timerfd->events_socket = l_events_socket;
    l_timerfd->callback = a_callback;
    l_timerfd->callback_arg = a_callback_arg;
    return l_timerfd;
}

/**
 * @brief dap_timerfd_stop
 * @param a_tfd
 * @param a_callback
 * @return 0 or <0 if error
 */
int dap_timerfd_delete(dap_timerfd_t *l_timerfd)
{
    if(!l_timerfd || l_timerfd->tfd < 1 || !l_timerfd->events_socket) {
        return -1;
    }

    if(close(l_timerfd->tfd) == -1) {
        log_it(L_WARNING, "dap_timerfd_stop() failed to close timerfd: errno=%d\n", errno);
        return -2;
    }

    dap_events_socket_queue_remove_and_delete(l_timerfd->events_socket);
    l_timerfd->events_socket = NULL;
    DAP_DELETE(l_timerfd);
    return 0;
}
#endif
