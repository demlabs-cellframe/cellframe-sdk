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

#include "dap_client_pvt.h"
#include "dap_common.h"

typedef struct dap_client_pvt_hh {
    uint64_t client_pvt_uuid;
    dap_client_pvt_t *client_pvt;
    UT_hash_handle hh;
} dap_client_pvt_hh_t;

// List of active connections
static dap_client_pvt_hh_t *s_client_pvt_list = NULL;
// for separate access to s_conn_list
static pthread_mutex_t s_client_pvt_list_mutex = PTHREAD_MUTEX_INITIALIZER;


/**
 * @brief dap_client_pvt_check
 * @param a_client_pvt
 * @return
 */
dap_client_pvt_t *dap_client_pvt_find(uint64_t a_client_pvt_uuid)
{
    bool l_ret = false;
    pthread_mutex_lock(&s_client_pvt_list_mutex);
    dap_client_pvt_hh_t *l_cur_item = NULL;
    HASH_FIND_PTR(s_client_pvt_list, &a_client_pvt_uuid, l_cur_item);
    pthread_mutex_unlock(&s_client_pvt_list_mutex);
    return l_cur_item? l_cur_item->client_pvt : NULL;
}

/**
 * Add new active connection to the list
 *
 * return 0 OK, -1 error, -2 connection present
 */
int dap_client_pvt_hh_add_unsafe(dap_client_pvt_t* a_client_pvt)
{
    int l_ret = 0;
    assert(a_client_pvt);
    pthread_mutex_lock(&s_client_pvt_list_mutex);
    dap_client_pvt_hh_t *l_cur_item = NULL;
    HASH_FIND_PTR(s_client_pvt_list, &a_client_pvt->uuid, l_cur_item);
    if(l_cur_item == NULL) {
        l_cur_item = DAP_NEW_Z(dap_client_pvt_hh_t);
        l_cur_item->client_pvt = a_client_pvt;
        l_cur_item->client_pvt_uuid = a_client_pvt->uuid;
        HASH_ADD_PTR(s_client_pvt_list, client_pvt_uuid, l_cur_item);
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
int dap_client_pvt_hh_del_unsafe(dap_client_pvt_t *a_client_pvt)
{
    int ret = -1;
    assert(a_client_pvt);
    pthread_mutex_lock(&s_client_pvt_list_mutex);
    dap_client_pvt_hh_t *l_cur_item = NULL;
    HASH_FIND_PTR(s_client_pvt_list, &a_client_pvt->uuid, l_cur_item);
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
