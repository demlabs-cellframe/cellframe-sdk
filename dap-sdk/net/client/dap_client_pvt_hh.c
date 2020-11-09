/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2020
 *
 This file is part of DAP (Deus Applications Prototypes) the open source project

 DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 DAP is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <pthread.h>
#include <uthash.h>

#include "dap_common.h"
#include "dap_client_pvt.h"

typedef struct dap_client_pvt_hh {
    dap_client_pvt_t *client_pvt;
    UT_hash_handle hh;
} dap_client_pvt_hh_t;

// List of active connections
static dap_client_pvt_hh_t *s_client_pvt_list = NULL;
// for separate access to s_conn_list
static pthread_mutex_t s_client_pvt_list_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * dap_client_pvt_hh_lock
 */
int dap_client_pvt_hh_lock(void)
{
    return pthread_mutex_lock(&s_client_pvt_list_mutex);
}

/**
 * dap_client_pvt_hh_unlock
 */
int dap_client_pvt_hh_unlock(void)
{
    return pthread_mutex_unlock(&s_client_pvt_list_mutex);
}

/**
 * find active connection in the list
 *
 * return 0 OK, -1 error, -2 connection not found
 */
void* dap_client_pvt_hh_get(dap_client_pvt_t* a_client_pvt)
{
    if(!a_client_pvt)
        return NULL;
    dap_client_pvt_hh_t *l_cur_item;
    HASH_FIND_PTR(s_client_pvt_list, &a_client_pvt, l_cur_item);
    return (void*) l_cur_item;
}

/**
 * @brief dap_client_pvt_check
 * @param a_client_pvt
 * @return
 */
bool dap_client_pvt_check(dap_client_pvt_t* a_client_pvt)
{
    bool l_ret = false;
    pthread_mutex_lock(&s_client_pvt_list_mutex);
    dap_client_pvt_hh_t *l_cur_item = NULL;
    HASH_FIND_PTR(s_client_pvt_list, &a_client_pvt, l_cur_item);
    l_ret = (l_cur_item != NULL);
    pthread_mutex_unlock(&s_client_pvt_list_mutex);
    return l_ret;
}

/**
 * Add new active connection to the list
 *
 * return 0 OK, -1 error, -2 connection present
 */
int dap_client_pvt_hh_add(dap_client_pvt_t* a_client_pvt)
{
    int l_ret = 0;
    if(!a_client_pvt)
        return -1;
    pthread_mutex_lock(&s_client_pvt_list_mutex);
    dap_client_pvt_hh_t *l_cur_item;
    HASH_FIND_PTR(s_client_pvt_list, &a_client_pvt, l_cur_item);
    if(l_cur_item == NULL) {
        l_cur_item = DAP_NEW(dap_client_pvt_hh_t);
        l_cur_item->client_pvt = a_client_pvt;
        HASH_ADD_PTR(s_client_pvt_list, client_pvt, l_cur_item);
        l_ret = 0;
    }
    // connection already present
    else
        l_ret = -2;
    //connect_list = g_list_append(connect_list, client);
    pthread_mutex_unlock(&s_client_pvt_list_mutex);
    return l_ret;
}

/**
 * Delete active connection from the list
 *
 * return 0 OK, -1 error, -2 connection not found
 */
int dap_client_pvt_hh_del(dap_client_pvt_t *a_client_pvt)
{
    int ret = -1;
    if(!a_client_pvt)
        return -1;
    pthread_mutex_lock(&s_client_pvt_list_mutex);
    dap_client_pvt_hh_t *l_cur_item;
    HASH_FIND_PTR(s_client_pvt_list, &a_client_pvt, l_cur_item);
    if(l_cur_item != NULL) {
        HASH_DEL(s_client_pvt_list, l_cur_item);
        DAP_DELETE(l_cur_item);
        ret = 0;
    }
    // connection not found in the hash
    else {
        ret = -2;
    }
    pthread_mutex_unlock(&s_client_pvt_list_mutex);
    return ret;
}
