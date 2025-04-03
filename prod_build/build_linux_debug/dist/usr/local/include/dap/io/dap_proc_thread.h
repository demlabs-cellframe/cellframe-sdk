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

#pragma once

#include <pthread.h>
#include "dap_common.h"

typedef struct dap_proc_thread dap_proc_thread_t;
typedef struct dap_context dap_context_t;
/// Callback for processor. Returns TRUE for repeat
typedef bool (*dap_proc_queue_callback_t)(void *a_arg);
typedef void (*dap_thread_timer_callback_t)(void *a_arg);

typedef enum dap_queue_msg_priority {
    DAP_QUEUE_MSG_PRIORITY_IDLE = 0,                                        /* Lowest priority (Idle). Don't use Idle until you sure what you do */
    DAP_QUEUE_MSG_PRIORITY_LOW,                                             /* Low priority */
    DAP_QUEUE_MSG_PRIORITY_NORMAL,                                          /* Default priority for any queue's entry, has assigned implicitly */
    DAP_QUEUE_MSG_PRIORITY_HIGH,                                            /* High priority */
    DAP_QUEUE_MSG_PRIORITY_CRITICAL,                                        /* Highest priority, critical for reaction time*/
    DAP_QUEUE_MSG_PRIORITY_COUNT                                            /* End-of-list marker */
} dap_queue_msg_priority_t;

#define DAP_QUEUE_MSG_PRIORITY_MIN DAP_QUEUE_MSG_PRIORITY_IDLE
#define DAP_QUEUE_MSG_PRIORITY_MAX DAP_QUEUE_MSG_PRIORITY_CRITICAL

typedef struct dap_proc_queue_item {
     dap_proc_queue_callback_t  callback;                                   /* An address of the action routine */
                          void *callback_arg;                               /* Address of the action routine argument */
    struct dap_proc_queue_item *prev;
    struct dap_proc_queue_item *next;
} dap_proc_queue_item_t;

typedef struct dap_proc_thread {
    pthread_mutex_t queue_lock;                                             /* To coordinate access to the queuee's entries */
    pthread_cond_t queue_event;                                             /* Conditional variable for waiting thread event queue */
    dap_proc_queue_item_t *queue[DAP_QUEUE_MSG_PRIORITY_COUNT];             /* List of the queue' entries in array of list according of priority numbers */
    uint64_t proc_queue_size;                                               /* Thread's load factor */
    dap_context_t *context;
} dap_proc_thread_t;

#define DAP_PROC_THREAD(a) (dap_proc_thread_t *)((a)->_inheritor);

int dap_proc_thread_create(dap_proc_thread_t *a_thread, int a_cpu_id);
int dap_proc_thread_init(uint32_t a_threads_count);
void dap_proc_thread_deinit();
int dap_proc_thread_loop(dap_context_t *a_context);

dap_proc_thread_t *dap_proc_thread_get(uint32_t a_thread_number);
dap_proc_thread_t *dap_proc_thread_get_auto();
int dap_proc_thread_callback_add_pri(dap_proc_thread_t *a_thread, dap_proc_queue_callback_t a_callback, void *a_callback_arg, dap_queue_msg_priority_t a_priority);
DAP_STATIC_INLINE int dap_proc_thread_callback_add(dap_proc_thread_t *a_thread, dap_proc_queue_callback_t a_callback, void *a_callback_arg)
{
    return dap_proc_thread_callback_add_pri(a_thread, a_callback, a_callback_arg, DAP_QUEUE_MSG_PRIORITY_NORMAL);
}
int dap_proc_thread_timer_add_pri(dap_proc_thread_t *a_thread, dap_thread_timer_callback_t a_callback, void *a_callback_arg, uint64_t a_timeout_ms, bool a_oneshot, dap_queue_msg_priority_t a_priority);
DAP_STATIC_INLINE int dap_proc_thread_timer_add(dap_proc_thread_t *a_thread, dap_thread_timer_callback_t a_callback, void *a_callback_arg, uint64_t a_timeout_ms)
{
    return dap_proc_thread_timer_add_pri(a_thread, a_callback, a_callback_arg, a_timeout_ms, false, DAP_QUEUE_MSG_PRIORITY_NORMAL);
}
size_t dap_proc_thread_get_avg_queue_size();
uint32_t dap_proc_thread_get_count();
