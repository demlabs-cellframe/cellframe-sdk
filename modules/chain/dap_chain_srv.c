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

struct network_service {
    dap_chain_net_id_t net_id;
    void *service;
};

struct service_list {
    dap_chain_srv_uid_t uuid; // Unique ID for service
    dap_list_t *networks;   // List of networks with service enabled
    dap_chain_static_srv_callbacks_t callbacks;
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
        dap_list_t *itl, *tmpl;
        DL_FOREACH_SAFE(it->networks, itl, tmpl) {
            struct network_service *l_service = itl->data;
            if (it->callbacks.delete)
                it->callbacks.delete(l_service->service);
            else
                DAP_DEL_Z(l_service->service);
            DAP_DELETE(l_service);
            DAP_DELETE(itl);
        }
        DAP_DELETE(it);
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
}


int dap_chain_srv_add(dap_chain_srv_uid_t a_uid, const char *a_name, dap_chain_static_srv_callbacks_t *a_static_callbacks)
{
    struct service_list *l_service_item = NULL;

    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_FIND(hh, s_srv_list, &a_uid, sizeof(a_uid), l_service_item);
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
    l_service_item->uuid = a_uid;
    if (a_name)
        dap_strncpy(l_service_item->name, a_name, sizeof(l_service_item->name));
    if (a_static_callbacks)
        l_service_item->callbacks = *a_static_callbacks;
    HASH_ADD(hh, s_srv_list, uuid, sizeof(a_uid), l_service_item);
    pthread_mutex_unlock(&s_srv_list_mutex);
    return 0;
}

static struct network_service *s_net_service_find(struct service_list *a_service_item, dap_chain_net_id_t a_net_id)
{
    for (dap_list_t *it = a_service_item->networks; it; it = it->next) {
        struct network_service *l_service = it->data;
        if (l_service->net_id.uint64 == a_net_id.uint64)
            return l_service;
    }
    return NULL;
}

static struct service_list *s_service_find(dap_chain_srv_uid_t a_srv_uid)
{
    struct service_list *l_service_item = NULL;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_FIND(hh, s_srv_list, &a_srv_uid, sizeof(dap_chain_srv_uid_t), l_service_item);
    pthread_mutex_unlock(&s_srv_list_mutex);
    return l_service_item;
}

static struct service_list *s_find_by_name(const char *a_name)
{
    dap_return_val_if_fail(a_name, NULL);
    pthread_mutex_lock(&s_srv_list_mutex);
    for (struct service_list *it = s_srv_list; it; it = it->hh.next) {
        if (!dap_strcmp(it->name, a_name)) {
            pthread_mutex_unlock(&s_srv_list_mutex);
            return it;
        }
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
    return NULL;
}

int dap_chain_srv_start(dap_chain_net_id_t a_net_id, const char *a_name, dap_config_t *a_config)
{
    struct service_list *l_service = s_find_by_name(a_name);
    if (!l_service)
        return -1;
    void *l_internal_service = NULL;
    if (l_service->callbacks.start)
        l_internal_service = l_service->callbacks.start(a_net_id, a_config);
    struct network_service *l_net_service = DAP_NEW_Z_RET_VAL_IF_FAIL(struct network_service, -2);
    *l_net_service = (struct network_service) { .service = l_internal_service, .net_id = a_net_id };
    l_service->networks = dap_list_append(l_service->networks, l_net_service);
    return 0;
}

int dap_chain_srv_delete(dap_chain_srv_uid_t a_srv_uid)
{
    struct service_list *l_service_item = NULL;
    pthread_mutex_lock(&s_srv_list_mutex);
    HASH_FIND(hh, s_srv_list, &a_srv_uid, sizeof(a_srv_uid), l_service_item);
    if (!l_service_item) {
        pthread_mutex_unlock(&s_srv_list_mutex);
        return -1;
    }
    HASH_DEL(s_srv_list, l_service_item);
    pthread_mutex_unlock(&s_srv_list_mutex);
    dap_list_t *it, *tmp;
    DL_FOREACH_SAFE(l_service_item->networks, it, tmp) {
        struct network_service *l_service = it->data;
        if (l_service_item->callbacks.delete)
            l_service_item->callbacks.delete(l_service->service);
        else
            DAP_DEL_Z(l_service->service);
        DAP_DELETE(l_service);
        DAP_DELETE(it);
    }
    DAP_DELETE(l_service_item);
    return 0;
}

int dap_chain_srv_purge(dap_chain_net_id_t a_net_id, dap_chain_srv_uid_t a_srv_uid)
{
    struct service_list *l_service_item = s_service_find(a_srv_uid);
    if (l_service_item && s_net_service_find(l_service_item, a_net_id) &&
            l_service_item->callbacks.purge)
        return l_service_item->callbacks.purge(a_net_id);
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
        if (s_net_service_find(it, a_net_id) && it->callbacks.purge)
            ret += it->callbacks.purge(a_net_id);
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
    return ret;
}

/**
 * @brief dap_chain_srv_hardfork_all
 * @param a_net_id
 */
dap_chain_srv_hardfork_state_t *dap_chain_srv_hardfork_all(dap_chain_net_id_t a_net_id)
{
    dap_chain_srv_hardfork_state_t *ret = NULL;
    pthread_mutex_lock(&s_srv_list_mutex);
    for (struct service_list *it = s_srv_list; it; it = it->hh.next) {
        if (s_net_service_find(it, a_net_id) && it->callbacks.hardfork_prepare) {
            dap_chain_srv_hardfork_state_t *l_state = DAP_NEW_Z(dap_chain_srv_hardfork_state_t), *cur, *tmp;
            if (!l_state)
                DL_FOREACH_SAFE(ret, cur, tmp)
                    DAP_DELETE(cur);
            l_state->uid = it->uuid;
            l_state->data = it->callbacks.hardfork_prepare(a_net_id, &l_state->size, &l_state->count);
            DL_APPEND(ret, l_state);
        }
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
    return ret;
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
        if (s_net_service_find(it, a_net_id) && it->callbacks.get_fee_descr)
            json_object_array_add(ret, it->callbacks.get_fee_descr(a_net_id));
    }
    pthread_mutex_unlock(&s_srv_list_mutex);
    return ret;
}

/**
 * @brief dap_chain_srv_get
 * @param a_uid
 * @return
 */
void *dap_chain_srv_get_internal(dap_chain_net_id_t a_net_id, dap_chain_srv_uid_t a_srv_uid)
{
    struct service_list *l_service_item = s_service_find(a_srv_uid);
    if (!l_service_item)
        return NULL;
    struct network_service *l_service = s_net_service_find(l_service_item, a_net_id);
    return l_service ? l_service->service : NULL;
}


/**
 * @brief dap_chain_srv_get_uid_by_name
 * @param a_client
 */
dap_chain_srv_uid_t dap_chain_srv_get_uid_by_name(const char *a_name)
{
    struct service_list *l_service = s_find_by_name(a_name);
    return l_service ? l_service->uuid : c_dap_chain_srv_uid_null;
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
        if (s_net_service_find(it, a_net_id))
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
        if (s_net_service_find(it, a_net_id))
            l_list = dap_list_append(l_list, DAP_DUP(&it->uuid));
    pthread_mutex_unlock(&s_srv_list_mutex);
    return l_list;
}
