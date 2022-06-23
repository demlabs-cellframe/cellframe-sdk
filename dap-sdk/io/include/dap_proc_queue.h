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

#include "dap_events_socket.h"
#include "dap_list.h"                                                       /* Simple List routines */

typedef struct dap_proc_thread dap_proc_thread_t;

typedef bool (*dap_proc_queue_callback_t)(dap_proc_thread_t *, void *);     // Callback for processor. Returns true if
                                                                            // we want to stop callback execution and
                                                                            // not to go on next loop
enum    {
        DAP_PROC_PRI_0 = 0,                                                 /* Lowest priority (Idle)  */
        DAP_PROC_PRI_IDLE = DAP_PROC_PRI_0,                                /* Don't use Idle if u are not sure that understand how it works */

        DAP_PROC_PRI_1 = 1,                                                 /* Low priority */
        DAP_PROC_PRI_LOW = DAP_PROC_PRI_1,


        DAP_PROC_PRI_2 = 2,
        DAP_PROC_PRI_NORMAL = DAP_PROC_PRI_2,                              /* Default priority for any queue's entry;
                                                                            has assigned implicitly */

        DAP_PROC_PRI_3 = 3,                                                 /* Higest priority */
        DAP_PROC_PRI_HIGH = DAP_PROC_PRI_3,

        DAP_PROC_PRI_MAX = 4                                                /* End-of-list marker */
};

#define DAP_QUE$K_ITER_NR   7

typedef struct dap_proc_queue_item{
    dap_proc_queue_callback_t callback;                                     /* An address of the action routine */
                        void *callback_arg;                                 /* Address of the action routine argument */

    struct dap_proc_queue_item *prev;                                       /* Links to back and forward entries */
    struct dap_proc_queue_item *next;
} dap_proc_queue_item_t;

typedef struct dap_proc_queue{
        dap_proc_thread_t   *proc_thread;                                   /* An assigned processor threads for the queue's entries */
        dap_events_socket_t *esocket;

        struct {
            pthread_mutex_t     lock;                                           /* To coordinate access to the queuee's entries */
            dap_slist_t         items;                                          /* List of the queue' entries */
        } list [DAP_PROC_PRI_MAX];                                          /* An array of list according of priority numbers */
} dap_proc_queue_t;

dap_proc_queue_t *dap_proc_queue_create(dap_proc_thread_t * a_thread);
dap_proc_queue_t *dap_proc_queue_create_ext(dap_proc_thread_t * a_thread);

int dap_proc_queue_delete(dap_proc_queue_t * a_queue);

int dap_proc_queue_add_callback_ext(dap_worker_t * a_worker, dap_proc_queue_callback_t a_callback, void * a_callback_arg, int a_pri);
int dap_proc_queue_add_callback_inter_ext(dap_events_socket_t * a_es_input, dap_proc_queue_callback_t a_callback, void * a_callback_arg, int );
DAP_STATIC_INLINE int dap_proc_queue_add_callback(dap_worker_t *a_worker, dap_proc_queue_callback_t a_callback, void *a_callback_arg)
{
    return dap_proc_queue_add_callback_ext(a_worker, a_callback, a_callback_arg, DAP_PROC_PRI_NORMAL);
}
DAP_STATIC_INLINE int dap_proc_queue_add_callback_inter(dap_events_socket_t *a_es_input, dap_proc_queue_callback_t a_callback, void *a_callback_arg)
{
    return dap_proc_queue_add_callback_inter_ext(a_es_input, a_callback, a_callback_arg, DAP_PROC_PRI_NORMAL);
}
int dap_proc_thread_add_callback_mt(dap_proc_thread_t * a_thread, dap_proc_queue_callback_t a_callback, void * a_callback_arg, int a_pri);

