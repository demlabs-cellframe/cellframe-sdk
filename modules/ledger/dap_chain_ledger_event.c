/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025, All rights reserved.

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

#include <pthread.h>
#include "dap_chain_ledger_pvt.h"
#include "dap_hash.h"

#define LOG_TAG "dap_ledger_event"

typedef struct dap_ledger_event_notifier {
    dap_ledger_event_notify_t callback;
    void *arg;
} dap_ledger_event_notifier_t;

static int s_ledger_event_verify_add(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash, dap_chain_datum_tx_t *a_tx, bool a_apply);
static int s_ledger_event_remove(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash);

/**
 * @brief Add notification callback for event transactions
 * @param a_ledger Ledger instance
 * @param a_callback Callback function to be called when a new event is added
 * @param a_arg User data to be passed to the callback
 */
void dap_ledger_event_notify_add(dap_ledger_t *a_ledger, dap_ledger_event_notify_t a_callback, void *a_arg)
{
    if (!a_ledger || !a_callback)
        return;
    
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    
    dap_ledger_event_notifier_t *l_notifier = DAP_NEW_Z(dap_ledger_event_notifier_t);
    if (!l_notifier) {
        log_it(L_CRITICAL, "Memory allocation error in dap_ledger_event_notify_add()");
        return;
    }
    
    l_notifier->callback = a_callback;
    l_notifier->arg = a_arg;
    
    l_ledger_pvt->event_notifiers = dap_list_append(l_ledger_pvt->event_notifiers, l_notifier);
}
 
static dap_chain_tx_event_t *s_ledger_event_to_tx_event(dap_ledger_event_t *a_event)
{
    dap_chain_tx_event_t *l_tx_event = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_tx_event_t, NULL);
    *l_tx_event = (dap_chain_tx_event_t) {
        .group_name = dap_strdup(a_event->group_name),
        .tx_hash = a_event->tx_hash,
        .pkey_hash = a_event->pkey_hash,
        .event_type = a_event->event_type,
        .event_data_size = a_event->event_data_size,
        .timestamp = a_event->timestamp
    };
    if (a_event->event_data_size)
        l_tx_event->event_data = DAP_DUP_SIZE_RET_VAL_IF_FAIL(a_event->event_data, a_event->event_data_size, NULL);
    return l_tx_event;
}
 
dap_chain_tx_event_t *dap_ledger_event_find(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_rdlock(&l_ledger_pvt->events_rwlock);
    dap_ledger_event_t *l_event = NULL;
    HASH_FIND(hh, l_ledger_pvt->events, a_tx_hash, sizeof(dap_hash_fast_t), l_event);
    pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
    if (!l_event)
        return NULL;
    return s_ledger_event_to_tx_event(l_event);
}

dap_list_t *dap_ledger_event_get_list(dap_ledger_t *a_ledger, const char *a_group_name)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_rdlock(&l_ledger_pvt->events_rwlock);
    dap_list_t *l_list = NULL;
    for (dap_ledger_event_t *it = l_ledger_pvt->events; it; it = it->hh.next) {
        if (a_group_name && dap_strcmp(it->group_name, a_group_name))
            continue;
        dap_chain_tx_event_t *l_tx_event = s_ledger_event_to_tx_event(it);
        if (!l_tx_event) {
            log_it(L_ERROR, "Can't allocate memory for tx event in dap_ledger_event_get_list()");
            pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
            dap_list_free_full(l_list, dap_chain_datum_tx_event_delete);
            return NULL;
        }
        l_list = dap_list_append(l_list, l_tx_event);
    }
    pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
    return l_list;
}

int dap_ledger_pvt_event_remove(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_wrlock(&l_ledger_pvt->events_rwlock);
    dap_ledger_event_t *l_event = NULL;
    HASH_FIND(hh, l_ledger_pvt->events, a_tx_hash, sizeof(dap_hash_fast_t), l_event);
    if (!l_event) {
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        return -1;
    }
    
    // Create a copy of the event for notifiers
    dap_chain_tx_event_t *l_tx_event = s_ledger_event_to_tx_event(l_event);
    
    // Remove the event from hash table
    HASH_DEL(l_ledger_pvt->events, l_event);
    DAP_DEL_MULTY(l_event->event_data, l_event->group_name, l_event);
    pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
    
    // Call event notifiers
    if (l_tx_event) {
        for (dap_list_t *it = l_ledger_pvt->event_notifiers; it; it = it->next) {
            dap_ledger_event_notifier_t *l_notifier = (dap_ledger_event_notifier_t *)it->data;
            if (l_notifier && l_notifier->callback) {
                l_notifier->callback(l_notifier->arg, a_ledger, l_tx_event, a_tx_hash, DAP_LEDGER_NOTIFY_OPCODE_DELETED);
            }
        }
        dap_chain_datum_tx_event_delete(l_tx_event);
    }
    
    return 0;
 }
 
int dap_ledger_pvt_event_verify_add(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash, dap_chain_datum_tx_t *a_tx, bool a_apply)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    if (a_apply)
        pthread_rwlock_wrlock(&l_ledger_pvt->events_rwlock);
    else
        pthread_rwlock_rdlock(&l_ledger_pvt->events_rwlock);
    dap_ledger_event_t *l_event = NULL;
    unsigned int l_hash_value = 0;
    HASH_VALUE(a_tx_hash, sizeof(dap_hash_fast_t), l_hash_value);
    HASH_FIND_BYHASHVALUE(hh, l_ledger_pvt->events, a_tx_hash, sizeof(dap_hash_fast_t), l_hash_value, l_event);
    if (l_event) {
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        return -1;
    }
    dap_chain_tx_item_event_t *l_event_item = NULL;
    dap_tsd_t *l_event_tsd = NULL;
    dap_sign_t *l_event_sign = NULL;
    byte_t *l_item; size_t l_tx_item_size;
    int l_event_count = 0, l_tsd_count = 0, l_sign_count = 0;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx) {
        switch (*l_item) {
        case TX_ITEM_TYPE_EVENT:
            if (l_event_count++) {
                log_it(L_WARNING, "Multiple event items in tx %s", dap_hash_fast_to_str_static(a_tx_hash));
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                return -2;
            }
            l_event_item = (dap_chain_tx_item_event_t *)l_item;
            if (l_event_item->version != DAP_CHAIN_TX_EVENT_VERSION) {
                log_it(L_WARNING, "Event version is not supported in tx %s", dap_hash_fast_to_str_static(a_tx_hash));
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                return -3;
            }
            if (!l_event_item->group_name_size) {
                log_it(L_WARNING, "Event group size is 0 in tx %s", dap_hash_fast_to_str_static(a_tx_hash));
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                return -4;
            }
            break;
        case TX_ITEM_TYPE_TSD: {
            dap_chain_tx_tsd_t *l_tsd = (dap_chain_tx_tsd_t *)l_item;
            if (l_tsd->header.size < sizeof(dap_tsd_t)) {
                log_it(L_WARNING, "TSD size is less than expected in tx %s", dap_hash_fast_to_str_static(a_tx_hash));
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                return -5;
            }
            dap_tsd_t *l_tsd_data = (dap_tsd_t *)(l_item + sizeof(dap_chain_tx_tsd_t));
            if (l_tsd_data->type != DAP_CHAIN_TX_TSD_TYPE_CUSTOM_DATA)
                continue;
            if (l_tsd_count++) {
                log_it(L_WARNING, "Multiple TSD items in tx %s", dap_hash_fast_to_str_static(a_tx_hash));
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                return -6;
            }
            l_event_tsd = l_tsd_data;
        } break;
        case TX_ITEM_TYPE_SIG:
            if (++l_sign_count == 2)
                l_event_sign = dap_chain_datum_tx_item_sig_get_sign((dap_chain_tx_sig_t *)l_item);
            break;
        default:
            break;
    }
    }
    if (!l_event_item || !l_event_sign) {
        log_it(L_WARNING, "Event item or sign not found in tx %s", dap_hash_fast_to_str_static(a_tx_hash));
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        return -7;
    }
    if (dap_chain_datum_tx_verify_sign(a_tx, 1)) {
        log_it(L_WARNING, "Sign verification failed in tx %s", dap_hash_fast_to_str_static(a_tx_hash));
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        return -8;
    }
    dap_hash_t l_event_pkey_hash = {};
    dap_sign_get_pkey_hash(l_event_sign, &l_event_pkey_hash);
    if (dap_ledger_event_pkey_check(a_ledger, &l_event_pkey_hash)) {
        log_it(L_WARNING, "Event pkey %s is not allowed in tx %s", dap_hash_fast_to_str_static(&l_event_pkey_hash),
                                                                dap_hash_fast_to_str_static(a_tx_hash));
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        return -9;
    }
    for (dap_ledger_event_t *it = l_ledger_pvt->events; it; it = it->hh.next) {
        if (!memcmp(it->group_name, l_event_item->group_name, l_event_item->group_name_size)) {
            if (!dap_hash_fast_compare(&it->pkey_hash, &l_event_pkey_hash)) {
                log_it(L_WARNING, "Group %s already exists with pkey_hash %s not matching event sign pkey hash %s",
                        it->group_name, dap_hash_fast_to_str_static(&it->pkey_hash), dap_hash_fast_to_str_static(&l_event_pkey_hash));
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                return -11;
            }
            break;
        }
    }
    if (!a_apply) {
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        return 0;
    }

    l_event = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_ledger_event_t, -8);
    *l_event = (dap_ledger_event_t) {
        .tx_hash = *a_tx_hash,
        .event_type = l_event_item->event_type,
        .event_data_size = l_event_tsd ? l_event_tsd->size : 0,
        .pkey_hash = l_event_pkey_hash,
        .timestamp = l_event_item->timestamp
    };
    l_event->group_name = DAP_NEW_SIZE(char, l_event_item->group_name_size + 1);
    if (!l_event->group_name) {
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        DAP_DEL_Z(l_event);
        return -9;
    }
    dap_strncpy((char *)l_event->group_name, (char *)l_event_item->group_name, l_event_item->group_name_size);
    if (l_event_tsd) {
        l_event->event_data = DAP_DUP_SIZE((byte_t *)l_event_tsd->data, l_event_tsd->size);
        if (!l_event->event_data) {
            pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
            DAP_DEL_Z(l_event);
            return -10;
        }
    }
    HASH_ADD_BYHASHVALUE(hh, l_ledger_pvt->events, tx_hash, sizeof(dap_hash_fast_t), l_hash_value, l_event);
    // Call event notifiers
    dap_chain_tx_event_t *l_tx_event = s_ledger_event_to_tx_event(l_event);
    pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
    
    if (l_tx_event) {
        for (dap_list_t *it = l_ledger_pvt->event_notifiers; it; it = it->next) {
            dap_ledger_event_notifier_t *l_notifier = (dap_ledger_event_notifier_t *)it->data;
            if (l_notifier && l_notifier->callback) {
                l_notifier->callback(l_notifier->arg, a_ledger, l_tx_event, a_tx_hash, DAP_LEDGER_NOTIFY_OPCODE_ADDED);
            }
        }
        dap_chain_datum_tx_event_delete(l_tx_event);
    }

    return 0;
}

/**
* @brief dap_ledger_check_event_pkey
* @param a_ledger The ledger instance
* @param a_pkey_hash Hash of the public key to check
* @return 0 if the key is allowed, -1 if not allowed
*/
int dap_ledger_event_pkey_check(dap_ledger_t *a_ledger, dap_hash_fast_t *a_pkey_hash)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_rdlock(&l_ledger_pvt->event_pkeys_rwlock);
    dap_ledger_event_pkey_item_t *l_item = NULL;
    
    // If no keys are in the allowed list, all keys are allowed by default
    if (!l_ledger_pvt->event_pkeys_allowed) {
        pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
        return 0;
    }
    
    HASH_FIND(hh, l_ledger_pvt->event_pkeys_allowed, a_pkey_hash, sizeof(dap_hash_fast_t), l_item);
    pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
    
    // If key found in allowed list - it's allowed
    return l_item ? 0 : -1;
}

/**
* @brief dap_ledger_event_pkey_add
* @param a_ledger The ledger instance
* @param a_pkey_hash Hash of the public key to add to allowed list
* @return 0 on success, -1 on error
*/
int dap_ledger_event_pkey_add(dap_ledger_t *a_ledger, dap_hash_fast_t *a_pkey_hash)
{
    if (!a_ledger || !a_pkey_hash)
        return -1;
    
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_wrlock(&l_ledger_pvt->event_pkeys_rwlock);
    
    dap_ledger_event_pkey_item_t *l_item = NULL;
    HASH_FIND(hh, l_ledger_pvt->event_pkeys_allowed, a_pkey_hash, sizeof(dap_hash_fast_t), l_item);
    if (l_item) {
        // Already exists
        pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
        return -1;
    }
    
    l_item = DAP_NEW_Z(dap_ledger_event_pkey_item_t);
    if (!l_item) {
        pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
        log_it(L_CRITICAL, "Memory allocation error");
        return -1;
    }
    
    memcpy(&l_item->pkey_hash, a_pkey_hash, sizeof(dap_hash_fast_t));
    HASH_ADD(hh, l_ledger_pvt->event_pkeys_allowed, pkey_hash, sizeof(dap_hash_fast_t), l_item);
    
    pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
    return 0;
}

/**
* @brief dap_ledger_event_pkey_rm
* @param a_ledger The ledger instance
* @param a_pkey_hash Hash of the public key to remove from allowed list
* @return 0 on success, -1 on error or if not found
*/
int dap_ledger_event_pkey_rm(dap_ledger_t *a_ledger, dap_hash_fast_t *a_pkey_hash)
{
    if (!a_ledger || !a_pkey_hash)
        return -1;
    
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_wrlock(&l_ledger_pvt->event_pkeys_rwlock);
    
    dap_ledger_event_pkey_item_t *l_item = NULL;
    HASH_FIND(hh, l_ledger_pvt->event_pkeys_allowed, a_pkey_hash, sizeof(dap_hash_fast_t), l_item);
    if (!l_item) {
        // Not found
        pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
        return -1;
    }
    
    HASH_DEL(l_ledger_pvt->event_pkeys_allowed, l_item);
    DAP_DELETE(l_item);
    
    pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
    return 0;
}

/**
* @brief dap_ledger_event_pkey_list
* @param a_ledger The ledger instance
* @return dap_list_t* List of dap_hash_fast_t* pointers to allowed public key hashes, NULL if empty or on error
*/
dap_list_t *dap_ledger_event_pkey_list(dap_ledger_t *a_ledger)
{
    if (!a_ledger)
        return NULL;
    
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_rdlock(&l_ledger_pvt->event_pkeys_rwlock);
    
    dap_list_t *l_list = NULL;
    dap_ledger_event_pkey_item_t *l_item = NULL, *l_tmp = NULL;
    
    HASH_ITER(hh, l_ledger_pvt->event_pkeys_allowed, l_item, l_tmp) {
        dap_hash_fast_t *l_hash_copy = DAP_NEW_Z(dap_hash_fast_t);
        if (!l_hash_copy) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            break;
        }
        memcpy(l_hash_copy, &l_item->pkey_hash, sizeof(dap_hash_fast_t));
        l_list = dap_list_append(l_list, l_hash_copy);
    }
    
    pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
    return l_list;
}
  