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
#include "dap_chain_srv.h"
#include "dap_hash.h"

#define LOG_TAG "dap_ledger_event"

typedef struct dap_ledger_event_notifier {
    dap_ledger_event_notify_t callback;
    void *arg;
} dap_ledger_event_notifier_t;

static int s_ledger_event_verify_add(dap_ledger_t *a_ledger, dap_hash_sha3_256_t *a_tx_hash, dap_chain_datum_tx_t *a_tx, bool a_apply);
static int s_ledger_event_remove(dap_ledger_t *a_ledger, dap_hash_sha3_256_t *a_tx_hash);

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
        .timestamp = a_event->timestamp,
        .srv_uid = a_event->srv_uid
    };
    if (!l_tx_event->group_name) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DELETE(l_tx_event);
        return NULL;
    }
    if (a_event->event_data_size && a_event->event_data) {
        l_tx_event->event_data = DAP_DUP_SIZE(a_event->event_data, a_event->event_data_size);
        if (!l_tx_event->event_data) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            DAP_DEL_MULTY(l_tx_event->group_name, l_tx_event);
            return NULL;
        }
    }
    return l_tx_event;
}

dap_chain_tx_event_t *dap_ledger_event_find(dap_ledger_t *a_ledger, dap_hash_sha3_256_t *a_tx_hash)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_rdlock(&l_ledger_pvt->events_rwlock);
    dap_ledger_event_t *l_event = NULL;
    dap_ht_find_hh(hh, l_ledger_pvt->events, a_tx_hash, sizeof(dap_hash_sha3_256_t), l_event);
    pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
    if (!l_event)
        return NULL;
    return s_ledger_event_to_tx_event(l_event);
}

dap_list_t *dap_ledger_event_get_list_ex(dap_ledger_t *a_ledger, const char *a_group_name, bool a_need_lock)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    if (a_need_lock)
        pthread_rwlock_rdlock(&l_ledger_pvt->events_rwlock);
    dap_list_t *l_list = NULL;
    dap_ledger_event_t *it = NULL, *tmp = NULL;
    dap_ht_foreach_hh(hh, l_ledger_pvt->events, it, tmp) {
        if (a_group_name && dap_strcmp(it->group_name, a_group_name))
            continue;
        dap_chain_tx_event_t *l_tx_event = s_ledger_event_to_tx_event(it);
        if (!l_tx_event) {
            log_it(L_ERROR, "Can't allocate memory for tx event in dap_ledger_event_get_list()");
            if (a_need_lock)
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
            dap_list_free_full(l_list, dap_chain_tx_event_delete);
            return NULL;
        }
        l_list = dap_list_append(l_list, l_tx_event);
    }
    if (a_need_lock)
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
    return l_list;
}

int dap_ledger_pvt_event_remove(dap_ledger_t *a_ledger, dap_hash_sha3_256_t *a_tx_hash)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_wrlock(&l_ledger_pvt->events_rwlock);
    dap_ledger_event_t *l_event = NULL;
    dap_ht_find_hh(hh, l_ledger_pvt->events, a_tx_hash, sizeof(dap_hash_sha3_256_t), l_event);
    if (!l_event) {
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        return -1;
    }

    // Create a copy of the event for notifiers
    dap_chain_tx_event_t *l_tx_event = s_ledger_event_to_tx_event(l_event);

    // Remove the event from hash table
    dap_ht_del(l_ledger_pvt->events, l_event);
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
        dap_chain_tx_event_delete(l_tx_event);
    }

    return 0;
 }

int dap_ledger_pvt_event_verify_add(dap_ledger_t *a_ledger, dap_hash_sha3_256_t *a_tx_hash, dap_chain_datum_tx_t *a_tx, bool a_apply, bool a_from_mempool)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    if (a_apply)
        pthread_rwlock_wrlock(&l_ledger_pvt->events_rwlock);
    else
        pthread_rwlock_rdlock(&l_ledger_pvt->events_rwlock);
    dap_ledger_event_t *l_event = NULL;
    unsigned int l_hash_value = 0;
    if (!a_ledger->is_hardfork_state) {
        l_hash_value = dap_ht_hash_value(a_tx_hash, sizeof(dap_hash_sha3_256_t));;
        dap_ht_find_by_hashvalue_hh(hh, l_ledger_pvt->events, a_tx_hash, sizeof(dap_hash_sha3_256_t), l_hash_value, l_event);
        if (l_event) {
            pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
            return -1;
        }
    }
    dap_chain_tx_item_event_t *l_event_item = NULL;
    dap_tsd_t *l_event_tsd = NULL;
    dap_sign_t *l_event_sign = NULL;
    dap_hash_sha3_256_t l_event_pkey_hash = {};
    dap_hash_sha3_256_t l_tx_hash = *a_tx_hash;
    byte_t *l_item; size_t l_tx_item_size;
    int l_event_count = 0, l_tsd_count = 0, l_sign_count = 0;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx) {
        switch (*l_item) {
        case TX_ITEM_TYPE_EVENT:
            if (l_event_count++) {
                log_it(L_WARNING, "Multiple event items in tx %s", dap_hash_sha3_256_to_str_static(a_tx_hash));
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                return -2;
            }
            l_event_item = (dap_chain_tx_item_event_t *)l_item;
            if (l_event_item->version != DAP_CHAIN_TX_EVENT_VERSION) {
                log_it(L_WARNING, "Event version is not supported in tx %s", dap_hash_sha3_256_to_str_static(a_tx_hash));
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                return -3;
            }
            if (!l_event_item->group_name_size) {
                log_it(L_WARNING, "Event group size is 0 in tx %s", dap_hash_sha3_256_to_str_static(a_tx_hash));
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                return -4;
            }
            break;
        case TX_ITEM_TYPE_TSD: {
            dap_chain_tx_tsd_t *l_tsd = (dap_chain_tx_tsd_t *)l_item;
            if (l_tsd->header.size < sizeof(dap_tsd_t)) {
                log_it(L_WARNING, "TSD size is less than expected in tx %s", dap_hash_sha3_256_to_str_static(a_tx_hash));
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                return -5;
            }
            dap_tsd_t *l_tsd_data = (dap_tsd_t *)(l_item + sizeof(dap_chain_tx_tsd_t));
            if (l_tsd_data->size + sizeof(dap_tsd_t) != l_tsd->header.size) {
                log_it(L_WARNING, "TSD size is not equal to expected in tx %s", dap_hash_sha3_256_to_str_static(a_tx_hash));
                pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                return -5;
            }
            if (!a_ledger->is_hardfork_state) {
                if (l_tsd_data->type != DAP_CHAIN_TX_TSD_TYPE_EVENT_DATA) {
                    log_it(L_WARNING, "TSD type %d is not supported in tx %s", l_tsd_data->type, dap_hash_sha3_256_to_str_static(a_tx_hash));
                    pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                    return -6;
                }
                l_event_tsd = l_tsd_data;
            } else {
                switch (l_tsd_data->type) {
                case DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_EVENT_DATA:
                    l_event_tsd = l_tsd_data;
                    if (l_tsd_count++) {
                        log_it(L_WARNING, "Multiple TSD items in tx %s", dap_hash_sha3_256_to_str_static(a_tx_hash));
                        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                        return -6;
                    }
                    break;
                case DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_TX_HASH:
                    l_tx_hash = *(dap_hash_sha3_256_t *)l_tsd_data->data;
                    break;
                case DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_PKEY_HASH:
                    l_event_pkey_hash = *(dap_hash_sha3_256_t *)l_tsd_data->data;
                    break;
                default:
                    log_it(L_WARNING, "TSD type %d is not supported in tx %s", l_tsd_data->type, dap_hash_sha3_256_to_str_static(a_tx_hash));
                    pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
                    return -6;
                }
            }
        } break;
        case TX_ITEM_TYPE_SIG:
            if (++l_sign_count == 2)
                l_event_sign = dap_chain_datum_tx_item_sig_get_sign((dap_chain_tx_sig_t *)l_item);
            break;
        default:
            break;
        }
    }
    if (!l_event_item) {
        log_it(L_WARNING, "Event item is not found in tx %s", dap_hash_sha3_256_to_str_static(a_tx_hash));
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        return -17;
    }
    if (!a_ledger->is_hardfork_state) {
        if (!l_event_sign) {
            log_it(L_WARNING, "Event sign is not found in tx %s", dap_hash_sha3_256_to_str_static(a_tx_hash));
            pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
            return -7;
        }
        if (dap_chain_datum_tx_verify_sign(a_tx, 1)) {
            log_it(L_WARNING, "Sign verification failed in tx %s", dap_hash_sha3_256_to_str_static(a_tx_hash));
            pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
            return -8;
        }
        dap_sign_get_pkey_hash(l_event_sign, &l_event_pkey_hash);
    }
    // If no keys are in the allowed list, all keys are allowed by default, change comparision to != 0 to block keys with empty list
    if (dap_ledger_event_pkey_check(a_ledger, &l_event_pkey_hash) == -1) {
        log_it(L_WARNING, "Event pkey %s is not allowed in tx %s", dap_hash_sha3_256_to_str_static(&l_event_pkey_hash),
                                                                dap_hash_sha3_256_to_str_static(a_tx_hash));
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        return -9;
    }
    char *l_event_group_name = DAP_NEW_SIZE(char, l_event_item->group_name_size + 1);
    if (!l_event_group_name) {
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        return -11;
    }
    dap_strncpy(l_event_group_name, (char *)l_event_item->group_name, l_event_item->group_name_size + 1);
    if (l_event_item->event_type == DAP_CHAIN_TX_EVENT_TYPE_SERVICE_DECREE) {
        DAP_DELETE(l_event_group_name);
        int ret = dap_chain_srv_decree(a_ledger->net_id, l_event_item->srv_uid, a_apply,
                                       (dap_tsd_t *)l_event_tsd->data, l_event_tsd->size);
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        if (ret)
            log_it(L_WARNING, "Decree event %s rejected by service verificator with code %d", dap_hash_sha3_256_to_str_static(a_tx_hash), ret);
        return a_from_mempool ? ret : 0;
    }
    int l_ret = dap_chain_srv_event_verify(a_ledger->net_id, l_event_item->srv_uid, l_event_group_name,
                                           l_event_item->event_type, l_event_tsd ? (dap_tsd_t *)l_event_tsd->data : NULL,
                                           l_event_tsd ? l_event_tsd->size : 0, a_tx_hash);
    if (l_ret || !a_apply) {
        pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
        DAP_DELETE(l_event_group_name);
        if (l_ret)
            log_it(L_WARNING, "Event %s rejected by service verificator with code %d", dap_hash_sha3_256_to_str_static(a_tx_hash), l_ret);
        return a_from_mempool ? l_ret : 0;
    }

    l_event = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_ledger_event_t, -8);
    *l_event = (dap_ledger_event_t) {
        .group_name = l_event_group_name,
        .tx_hash = l_tx_hash,
        .event_type = l_event_item->event_type,
        .event_data_size = l_event_tsd ? l_event_tsd->size : 0,
        .pkey_hash = l_event_pkey_hash,
        .timestamp = l_event_item->timestamp,
        .srv_uid = l_event_item->srv_uid
    };


    if (l_event_tsd) {
        l_event->event_data = DAP_DUP_SIZE((byte_t *)l_event_tsd->data, l_event_tsd->size);
        if (!l_event->event_data) {
            pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
            DAP_DEL_Z(l_event);
            return -10;
        }
    }
    if (a_ledger->is_hardfork_state) {
        dap_ledger_event_t *l_found = NULL;
        l_hash_value = dap_ht_hash_value(&l_tx_hash, sizeof(dap_hash_sha3_256_t));;
        dap_ht_find_by_hashvalue_hh(hh, l_ledger_pvt->events, a_tx_hash, sizeof(dap_hash_sha3_256_t), l_hash_value, l_found);
        if (l_found) {
            pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
            return -1;
        }
    }
    dap_ht_add_by_hashvalue_hh(hh, l_ledger_pvt->events, tx_hash, sizeof(dap_hash_sha3_256_t), l_hash_value, l_event);
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
        dap_chain_tx_event_delete(l_tx_event);
    }

    return 0;
}

/**
* @brief dap_ledger_check_event_pkey
* @param a_ledger The ledger instance
* @param a_pkey_hash Hash of the public key to check
* @return 1 if no keys set, 0 if the key is allowed, -1 if not allowed
*/
int dap_ledger_event_pkey_check(dap_ledger_t *a_ledger, dap_hash_sha3_256_t *a_pkey_hash)
{
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_rdlock(&l_ledger_pvt->event_pkeys_rwlock);
    dap_ledger_event_pkey_item_t *l_item = NULL;

    if (!l_ledger_pvt->event_pkeys_allowed) {
        pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
        return 1;
    }

    dap_ht_find_hh(hh, l_ledger_pvt->event_pkeys_allowed, a_pkey_hash, sizeof(dap_hash_sha3_256_t), l_item);
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
int dap_ledger_event_pkey_add(dap_ledger_t *a_ledger, dap_hash_sha3_256_t *a_pkey_hash)
{
    if (!a_ledger || !a_pkey_hash)
        return -1;

    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_wrlock(&l_ledger_pvt->event_pkeys_rwlock);

    dap_ledger_event_pkey_item_t *l_item = NULL;
    dap_ht_find_hh(hh, l_ledger_pvt->event_pkeys_allowed, a_pkey_hash, sizeof(dap_hash_sha3_256_t), l_item);
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

    memcpy(&l_item->pkey_hash, a_pkey_hash, sizeof(dap_hash_sha3_256_t));
    dap_ht_add_hh(hh, l_ledger_pvt->event_pkeys_allowed, pkey_hash, l_item);

    pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
    return 0;
}

/**
* @brief dap_ledger_event_pkey_rm
* @param a_ledger The ledger instance
* @param a_pkey_hash Hash of the public key to remove from allowed list
* @return 0 on success, -1 on error or if not found
*/
int dap_ledger_event_pkey_rm(dap_ledger_t *a_ledger, dap_hash_sha3_256_t *a_pkey_hash)
{
    if (!a_ledger || !a_pkey_hash)
        return -1;

    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_wrlock(&l_ledger_pvt->event_pkeys_rwlock);

    dap_ledger_event_pkey_item_t *l_item = NULL;
    dap_ht_find_hh(hh, l_ledger_pvt->event_pkeys_allowed, a_pkey_hash, sizeof(dap_hash_sha3_256_t), l_item);
    if (!l_item) {
        // Not found
        pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
        return -1;
    }

    dap_ht_del(l_ledger_pvt->event_pkeys_allowed, l_item);
    DAP_DELETE(l_item);

    pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
    return 0;
}

/**
* @brief dap_ledger_event_pkey_list
* @param a_ledger The ledger instance
* @return dap_list_t* List of dap_hash_sha3_256_t* pointers to allowed public key hashes, NULL if empty or on error
*/
dap_list_t *dap_ledger_event_pkey_list(dap_ledger_t *a_ledger)
{
    if (!a_ledger)
        return NULL;

    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    pthread_rwlock_rdlock(&l_ledger_pvt->event_pkeys_rwlock);

    dap_list_t *l_list = NULL;
    dap_ledger_event_pkey_item_t *l_item = NULL, *l_tmp = NULL;

    dap_ht_foreach_hh(hh, l_ledger_pvt->event_pkeys_allowed, l_item, l_tmp) {
        dap_hash_sha3_256_t *l_hash_copy = DAP_NEW_Z(dap_hash_sha3_256_t);
        if (!l_hash_copy) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            break;
        }
        memcpy(l_hash_copy, &l_item->pkey_hash, sizeof(dap_hash_sha3_256_t));
        l_list = dap_list_append(l_list, l_hash_copy);
    }

    pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);
    return l_list;
}

dap_ledger_hardfork_events_t *dap_ledger_events_aggregate(dap_ledger_t *a_ledger, dap_chain_id_t a_chain_id)
{
    dap_ledger_hardfork_events_t *ret = NULL;
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);
    size_t l_events_count = 0;
    pthread_rwlock_rdlock(&l_ledger_pvt->events_rwlock);
    dap_ledger_event_t *it = NULL, *tmp = NULL;
    dap_ht_foreach_hh(hh, l_ledger_pvt->events, it, tmp) {
        dap_ledger_hardfork_events_t *l_add = DAP_NEW_Z(dap_ledger_hardfork_events_t);
        if (!l_add) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            break;
        }
        l_add->event = s_ledger_event_to_tx_event(it);
        if (!l_add->event) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            DAP_DELETE(l_add);
            break;
        }
        debug_if(g_debug_ledger, L_NOTICE, "Aggregate event %s from group '%s' with type %u for srv_uid 0x%016" DAP_UINT64_FORMAT_x,
                 dap_hash_sha3_256_to_str_static(&it->tx_hash), it->group_name,
                 it->event_type, it->srv_uid.uint64);
        dap_dl_append(ret, l_add);
        l_events_count++;
    }
    pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);
    debug_if(g_debug_ledger, L_NOTICE, "Aggregated %zu events total", l_events_count);
    return ret;
}

/**
 * @brief Purge all events from the ledger
 * @param a_ledger The ledger instance
 * @details Removes all events and allowed public keys from ledger memory.
 *          Does not affect event notifiers list.
 */
void dap_ledger_event_purge(dap_ledger_t *a_ledger)
{
    dap_return_if_fail(a_ledger);
    dap_ledger_private_t *l_ledger_pvt = PVT(a_ledger);

    // Purge events hash table
    pthread_rwlock_wrlock(&l_ledger_pvt->events_rwlock);
    dap_ledger_event_t *l_event_current, *l_event_tmp;
    size_t l_events_count = 0;
    dap_ht_foreach_hh(hh, l_ledger_pvt->events, l_event_current, l_event_tmp) {
        dap_ht_del(l_ledger_pvt->events, l_event_current);
        DAP_DEL_MULTY(l_event_current->event_data, l_event_current->group_name, l_event_current);
        l_events_count++;
    }
    l_ledger_pvt->events = NULL;
    pthread_rwlock_unlock(&l_ledger_pvt->events_rwlock);

    // Purge allowed public keys hash table
    pthread_rwlock_wrlock(&l_ledger_pvt->event_pkeys_rwlock);
    dap_ledger_event_pkey_item_t *l_pkey_current, *l_pkey_tmp;
    size_t l_pkeys_count = 0;
    dap_ht_foreach_hh(hh, l_ledger_pvt->event_pkeys_allowed, l_pkey_current, l_pkey_tmp) {
        dap_ht_del(l_ledger_pvt->event_pkeys_allowed, l_pkey_current);
        DAP_DELETE(l_pkey_current);
        l_pkeys_count++;
    }
    l_ledger_pvt->event_pkeys_allowed = NULL;
    pthread_rwlock_unlock(&l_ledger_pvt->event_pkeys_rwlock);

    debug_if(g_debug_ledger, L_NOTICE, "Purged %zu events and %zu allowed event pkeys from ledger",
             l_events_count, l_pkeys_count);
}