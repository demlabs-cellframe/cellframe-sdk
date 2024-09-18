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
    void *_internal;
    char name[32];
    UT_hash_handle hh;
};

// list of active services
static struct service_list *s_srv_list = NULL;
// for separate access to s_srv_list
static pthread_mutex_t s_srv_list_mutex = PTHREAD_MUTEX_INITIALIZER;

void dap_chain_srv_deinit()
{
    struct service_list *it, *tmp;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_ITER(hh, s_srv_list, it, tmp) {
        // Clang bug at this, l_service_item should change at every loop cycle
        HASH_DEL(s_srv_list, it);
        if (it->callbacks.delete)
            it->callbacks.delete(it->_internal);
        DAP_DELETE(it);
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
}


int dap_chain_srv_add(dap_chain_net_id_t a_net_id, dap_chain_net_srv_uid_t a_uid, const char *a_name,
                      dap_chain_static_srv_callbacks_t *a_static_callbacks, void *a_service_internal)
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
    l_service_item->_internal = a_service_internal;
    HASH_ADD(hh, s_srv_list, net_uuid, sizeof(l_uid), l_service_item);
    return 0;
}

static struct service_list *s_service_find(dap_chain_net_id_t a_net_id, dap_chain_net_srv_uid_t a_srv_uid)
{
    dap_guuid_t l_uuid = dap_guuid_compose(a_net_id.uint64, a_srv_uid.uint64);
    struct service_list *l_service_item = NULL;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_FIND(hh, s_srv_list, &l_uuid, sizeof(dap_guuid_t), l_service_item);
    pthread_mutex_unlock(&s_srv_list_mutex);
    return l_service_item;
}

int dap_chain_srv_delete(dap_chain_net_id_t a_net_id, dap_chain_net_srv_uid_t a_srv_uid)
{
    dap_guuid_t l_uuid = dap_guuid_compose(a_net_id.uint64, a_srv_uid.uint64);
    struct service_list *l_service_item = NULL;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_FIND(hh, s_srv_list, &l_uuid, sizeof(dap_guuid_t), l_service_item);
    if (!l_service_item) {
        pthread_mutex_unlock(&s_srv_list_mutex);
        return -1;
    }
    HASH_DEL(s_srv_list, l_service_item);
    pthread_mutex_unlock(&s_srv_list_mutex);
    if (l_service_item->callbacks.delete)
        l_service_item->callbacks.delete(l_service_item->_internal);
    DAP_DELETE(l_service_item);
    return 0;
}

int dap_chain_srv_purge(dap_chain_net_id_t a_net_id, dap_chain_net_srv_uid_t a_srv_uid)
{
    struct service_list *l_service_item = s_service_find(a_net_id, a_srv_uid);
    if (l_service_item && l_service_item->callbacks.purge)
        return l_service_item->callbacks.purge();
    return 0;
}

/**
 * @brief dap_chain_srv_purge_all
 * @param a_net_id
 */
int dap_chain_srv_purge_all(dap_chain_net_id_t a_net_id)
{
    int ret = 0;
    pthread_mutex_lock(&s_srv_list_mutex);
    for (struct service_list *it = s_srv_list; it; it = it->hh.next) {
        if (it->net_uuid.net_id == a_net_id.uint64 && it->callbacks.purge)
            ret += it->callbacks.purge();
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
    return ret;
}

/**
 * @brief dap_chain_srv_hardfork_all
 * @param a_net_id
 */
void dap_chain_srv_hardfork_all(dap_chain_net_id_t a_net_id)
{
    pthread_mutex_lock(&s_srv_list_mutex);
    for (struct service_list *it = s_srv_list; it; it = it->hh.next) {
        if (it->net_uuid.net_id == a_net_id.uint64 && it->callbacks.hardfork)
            it->callbacks.hardfork();
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
}

/**
 * @brief dap_chain_srv_get_fees
 * @param a_net_id
 * @return JSON object with array of fees for services having ones
 */
json_object *dap_chain_srv_get_fees(dap_chain_net_id_t a_net_id)
{
    json_object *ret = json_object_new_array();
    pthread_mutex_lock(&s_srv_list_mutex);
    for (struct service_list *it = s_srv_list; it; it = it->hh.next) {
        if (it->net_uuid.net_id == a_net_id.uint64 && it->callbacks.get_fee_descr)
            json_object_array_add(ret, it->callbacks.get_fee_descr());
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
    return ret;
}

/**
 * @brief dap_chain_srv_get
 * @param a_uid
 * @return
 */
void *dap_chain_srv_get_internal(dap_chain_net_id_t a_net_id, dap_chain_net_srv_uid_t a_srv_uid)
{
    struct service_list *l_service_item = s_service_find(a_net_id, a_srv_uid);
    return (l_service_item) ? l_service_item->_internal : NULL;
}

/**
 * @brief dap_chain_srv_get_uid_by_name
 * @param a_client
 */
uint64_t dap_chain_srv_get_uid_by_name(const char *a_name)
{
    dap_return_val_if_fail(a_name, 0);
    pthread_mutex_lock(&s_srv_list_mutex);
    for (struct service_list *it = s_srv_list; it; it = it->hh.next) {
        if (!dap_strcmp(it->name, a_name)) {
            pthread_mutex_unlock(&s_srv_list_mutex);
            return it->net_uuid.srv_id;
        }
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
    return 0;
}

/**
 * @brief dap_chain_srv_count
 * @return
 */
size_t dap_chain_srv_count(dap_chain_net_id_t a_net_id)
{
    size_t l_count = 0;
    pthread_mutex_lock(&s_srv_list_mutex);
    for (struct service_list *it = s_srv_list; it; it = it->hh.next)
        if (it->net_uuid.net_id == a_net_id.uint64)
            l_count++;
    pthread_mutex_unlock(&s_srv_list_mutex);
    return l_count;
}

/**
 * @brief dap_chain_srv_list
 * @return
 */
dap_list_t *dap_chain_srv_list(dap_chain_net_id_t a_net_id)
{
    dap_list_t *l_list = NULL;
    pthread_mutex_lock(&s_srv_list_mutex);
    // Iterate services and save them to list
    for (struct service_list *it = s_srv_list; it; it = it->hh.next)
        if (it->net_uuid.net_id == a_net_id.uint64)
            l_list = dap_list_append(l_list, DAP_DUP(&it->net_uuid));
    pthread_mutex_unlock(&s_srv_list_mutex);
    return l_list;
}
