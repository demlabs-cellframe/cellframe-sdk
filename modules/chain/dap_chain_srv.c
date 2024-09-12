/*
* Authors:
* Roman Khlopkov <roman.khlopkov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2024
* All rights reserved.

This file is part of CellFrame SDK the open source project

CellFrame SDK is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CellFrame SDK is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/


#include "dap_guuid.h"
#include "dap_chain_srv.h"

#define LOG_TAG "chain_srv"

struct service_list {
    dap_guuid_t net_uuid; // Unique ID for service with network
    dap_chain_static_srv_callbacks_t callbacks;
    void *_inheritor;
    char name[32];
    UT_hash_handle hh;
};

// list of active services
static struct service_list *s_srv_list = NULL;
// for separate access to s_srv_list
static pthread_mutex_t s_srv_list_mutex = PTHREAD_MUTEX_INITIALIZER;


int dap_chain_srv_add(dap_chain_net_id_t a_net_id, dap_chain_net_srv_uid_t a_uid, const char *a_name,
                      dap_chain_static_srv_callbacks_t *a_static_callbacks, void *a_highlevel_service)
{
    struct service_list *l_service_item = NULL;

    dap_guuid_t l_uid = dap_guuid_compose(a_net_id.uint64, a_uid.uint64);
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_FIND(hh, s_srv_list, &l_uid, sizeof(l_uid), l_service_item);
    if (l_service_item) {
        log_it(L_ERROR, "Already present service with 0x%016"DAP_UINT64_FORMAT_X, a_uid.uint64);
        pthread_mutex_unlock(&s_srv_list_mutex);
        return -1;
    }
    l_service_item = DAP_NEW_Z(struct service_list);
    if (!l_service_item) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        pthread_mutex_unlock(&s_srv_list_mutex);
        return -2;
    }
    l_service_item->net_uuid = l_uid;
    if (a_name)
        dap_strncpy(l_service_item->name, a_name, sizeof(l_service_item->name));
    if (a_static_callbacks)
        l_service_item->callbacks = *a_static_callbacks;
    l_service_item->_inheritor = a_highlevel_service;
    HASH_ADD(hh, s_srv_list, net_uuid, sizeof(l_uid), l_service_item);
    return 0;
}
/**
 * @brief dap_chain_net_srv_call_write_all
 * @param a_client
 */
void dap_chain_net_srv_purge_all(dap_chain_net_id_t *a_net_id)
{
    pthread_mutex_lock(&s_srv_list_mutex);
    for (struct service_list *it = s_srv_list; it; it = it->hh.next) {
        if (it->callbacks.purge)
            it->callbacks.purge();
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
}

/**
 * @brief dap_chain_net_srv_call_opened_all
 * @param a_client
 */
void dap_chain_net_srv_call_opened_all(dap_stream_ch_t * a_client)
{
    struct service_list *l_service_item, *l_service_item_tmp;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_ITER(hh, s_srv_list , l_service_item, l_service_item_tmp)
    {
        if (l_service_item->srv->callbacks.stream_ch_opened)
            l_service_item->srv->callbacks.stream_ch_opened(l_service_item->srv, a_client);
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
}

void dap_chain_net_srv_call_closed_all(dap_stream_ch_t * a_client)
{
    struct service_list *l_service_item, *l_service_item_tmp;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_ITER(hh, s_srv_list , l_service_item, l_service_item_tmp)
    {
        if (l_service_item->srv->callbacks.stream_ch_closed)
            l_service_item->srv->callbacks.stream_ch_closed(l_service_item->srv, a_client);
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
}



/**
 * @brief dap_chain_net_srv_del_all
 * @param a_srv
 */
void dap_chain_net_srv_del_all(void)
{
    struct service_list *l_service_item, *l_service_item_tmp;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_ITER(hh, s_srv_list , l_service_item, l_service_item_tmp)
    {
        // Clang bug at this, l_service_item should change at every loop cycle
        HASH_DEL(s_srv_list, l_service_item);
        DAP_DELETE(l_service_item->srv);
        DAP_DELETE(l_service_item);
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
}

/**
 * @brief dap_chain_net_srv_get
 * @param a_uid
 * @return
 */
dap_chain_net_srv_t *dap_chain_net_srv_get(dap_chain_net_id_t a_net_id, dap_chain_net_srv_uid_t a_srv_id)
{
    dap_guuid_t l_uuid = dap_guuid_compose(a_net_id.uint64, a_srv_id.uint64);
    struct service_list *l_service_item = NULL;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_FIND(hh, s_srv_list, &l_uuid, sizeof(dap_guuid_t), l_service_item);
    pthread_mutex_unlock(&s_srv_list_mutex);
    return (l_service_item) ? l_service_item->srv : NULL;
}

/**
 * @brief dap_chain_net_srv_get_by_name
 * @param a_client
 */
dap_chain_net_srv_t* dap_chain_net_srv_get_by_name(dap_chain_net_id_t a_net_id, const char *a_name)
{
    dap_return_val_if_fail(a_name, NULL);
    struct service_list *l_service_item, *l_service_item_tmp;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_ITER(hh, s_srv_list , l_service_item, l_service_item_tmp) {
        if (!dap_strcmp(l_service_item->name, a_name) &&
                a_net_id.uint64 == l_service_item->net_uuid.net_id) {
            pthread_mutex_unlock(&s_srv_list_mutex);
            return l_service_item->srv;
        }
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
    return NULL;
}

/**
 * @brief dap_chain_net_srv_count
 * @return
 */
size_t dap_chain_srv_count(void)
{
    pthread_mutex_lock(&s_srv_list_mutex);
    size_t l_count = HASH_COUNT(s_srv_list);
    pthread_mutex_unlock(&s_srv_list_mutex);
    return l_count;
}

/**
 * @brief dap_chain_net_srv_list
 * @return
 */
const dap_chain_net_srv_uid_t * dap_chain_net_srv_list(void)
{
    static dap_chain_net_srv_uid_t *l_srv_uids = NULL;
    static size_t l_count_last = 0;
    size_t l_count_cur = 0;
    dap_list_t *l_list = NULL;
    struct service_list *l_service_item, *l_service_item_tmp;
    pthread_mutex_lock(&s_srv_list_mutex);
    // count the number of services and save them in list
    HASH_ITER(hh, s_srv_list , l_service_item, l_service_item_tmp)
    {
        l_list = dap_list_append(l_list, l_service_item);
        l_count_cur++;
    }
    // fill the output array
    if(l_count_cur > 0) {
        if(l_count_cur != l_count_last) {
            DAP_DELETE(l_srv_uids);
            l_srv_uids = DAP_NEW_SIZE(dap_chain_net_srv_uid_t, sizeof(dap_chain_net_srv_uid_t) * l_count_cur);
        }
        for(size_t i = 0; i < l_count_cur; i++) {
            struct service_list *l_service_item = l_list->data;
            memcpy(l_srv_uids + i, &l_service_item->uid, sizeof(dap_chain_net_srv_uid_t));
        }
    }
    // save new number of services
    l_count_last = l_count_cur;
    pthread_mutex_unlock(&s_srv_list_mutex);
    dap_list_free(l_list);
    return l_srv_uids;
}
