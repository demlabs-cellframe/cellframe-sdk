/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
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

#include "dap_ht_utils.h"
#include "dap_chain_policy.h"
#include "dap_chain_ledger.h"
#include "dap_chain_datum_decree.h"
#include "dap_common.h"

#define LOG_TAG "dap_chain_policy"

// Policy-level handler storage
typedef struct dap_policy_decree_handler {
    uint16_t decree_subtype;
    dap_chain_policy_decree_callback_t callback;
    void *arg;
    dap_ht_handle_t hh;
} dap_policy_decree_handler_t;

typedef struct dap_policy_anchor_handler {
    uint16_t anchor_subtype;
    dap_chain_policy_anchor_callback_t callback;
    void *arg;
    dap_ht_handle_t hh;
} dap_policy_anchor_handler_t;

static dap_policy_decree_handler_t *s_policy_decree_handlers = NULL;
static dap_policy_anchor_handler_t *s_policy_anchor_handlers = NULL;
static pthread_rwlock_t s_policy_decree_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_rwlock_t s_policy_anchor_rwlock = PTHREAD_RWLOCK_INITIALIZER;

/**
 * @brief Generic decree dispatcher - called by ledger
 */
static int s_policy_decree_dispatcher(dap_chain_datum_decree_t *a_decree, dap_chain_t *a_chain, bool a_apply, void *a_arg)
{
    uint16_t l_subtype = a_decree->header.sub_type;
    dap_policy_decree_handler_t *l_handler = NULL;

    pthread_rwlock_rdlock(&s_policy_decree_rwlock);
    dap_ht_find_hh(hh, s_policy_decree_handlers, &l_subtype, sizeof(uint16_t), l_handler);
    pthread_rwlock_unlock(&s_policy_decree_rwlock);

    if (l_handler && l_handler->callback) {
        return l_handler->callback(a_decree, a_chain, a_apply, l_handler->arg);
    }

    log_it(L_DEBUG, "No policy handler registered for decree subtype %u", l_subtype);
    return 0;  // Not an error - just no handler
}

/**
 * @brief Generic anchor dispatcher - called by ledger
 */
static int s_policy_anchor_dispatcher(dap_chain_datum_anchor_t *a_anchor, dap_chain_t *a_chain, dap_hash_sha3_256_t *a_anchor_hash, void *a_arg)
{
    uint16_t l_subtype = a_anchor->header.sub_type;
    dap_policy_anchor_handler_t *l_handler = NULL;

    pthread_rwlock_rdlock(&s_policy_anchor_rwlock);
    dap_ht_find_hh(hh, s_policy_anchor_handlers, &l_subtype, sizeof(uint16_t), l_handler);
    pthread_rwlock_unlock(&s_policy_anchor_rwlock);

    if (l_handler && l_handler->callback) {
        return l_handler->callback(a_anchor, a_chain, a_anchor_hash, l_handler->arg);
    }

    log_it(L_DEBUG, "No policy handler registered for anchor subtype %u", l_subtype);
    return 0;  // Not an error - just no handler
}

/**
 * @brief Register policy-level decree handler
 */
int dap_chain_policy_decree_callback_register(
    uint16_t a_decree_subtype,
    dap_chain_policy_decree_callback_t a_callback,
    void *a_arg)
{
    if (!a_callback) {
        log_it(L_ERROR, "Cannot register NULL policy decree callback");
        return -1;
    }

    dap_policy_decree_handler_t *l_handler = DAP_NEW_Z(dap_policy_decree_handler_t);
    if (!l_handler) {
        log_it(L_CRITICAL, "Memory allocation failed");
        return -2;
    }

    l_handler->decree_subtype = a_decree_subtype;
    l_handler->callback = a_callback;
    l_handler->arg = a_arg;

    pthread_rwlock_wrlock(&s_policy_decree_rwlock);
    dap_ht_add_hh(hh, s_policy_decree_handlers, decree_subtype, l_handler);
    pthread_rwlock_unlock(&s_policy_decree_rwlock);

    log_it(L_INFO, "Registered policy decree callback for subtype %u", a_decree_subtype);
    return 0;
}

/**
 * @brief Register policy-level anchor handler
 */
int dap_chain_policy_anchor_callback_register(
    uint16_t a_anchor_subtype,
    dap_chain_policy_anchor_callback_t a_callback,
    void *a_arg)
{
    if (!a_callback) {
        log_it(L_ERROR, "Cannot register NULL policy anchor callback");
        return -1;
    }

    dap_policy_anchor_handler_t *l_handler = DAP_NEW_Z(dap_policy_anchor_handler_t);
    if (!l_handler) {
        log_it(L_CRITICAL, "Memory allocation failed");
        return -2;
    }

    l_handler->anchor_subtype = a_anchor_subtype;
    l_handler->callback = a_callback;
    l_handler->arg = a_arg;

    pthread_rwlock_wrlock(&s_policy_anchor_rwlock);
    dap_ht_add_hh(hh, s_policy_anchor_handlers, anchor_subtype, l_handler);
    pthread_rwlock_unlock(&s_policy_anchor_rwlock);

    log_it(L_INFO, "Registered policy anchor callback for subtype %u", a_anchor_subtype);
    return 0;
}

/**
 * @brief Initialize chain policy module
 * Registers policy dispatcher with ledger
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_policy_init(void)
{
    log_it(L_NOTICE, "Initializing chain policy module");

    // Register generic dispatcher with ledger for all decree types
    // Net/consensus/services will register specific handlers in policy
    dap_ledger_decree_handler_register(
        0,  // Will handle all subtypes
        s_policy_decree_dispatcher,
        NULL
    );

    dap_ledger_anchor_handler_register(
        0,  // Will handle all subtypes
        s_policy_anchor_dispatcher,
        NULL
    );

    log_it(L_NOTICE, "Chain policy module initialized successfully");
    return 0;
}

/**
 * @brief Deinitialize chain policy module
 */
void dap_chain_policy_deinit(void)
{
    log_it(L_NOTICE, "Deinitializing chain policy module");

    // Free decree handlers
    dap_policy_decree_handler_t *l_handler, *l_tmp;
    dap_ht_foreach_hh(hh, s_policy_decree_handlers, l_handler, l_tmp) {
        dap_ht_del(s_policy_decree_handlers, l_handler);
        DAP_DELETE(l_handler);
    }

    // Free anchor handlers
    dap_policy_anchor_handler_t *l_anchor_handler, *l_anchor_tmp;
    dap_ht_foreach_hh(hh, s_policy_anchor_handlers, l_anchor_handler, l_anchor_tmp) {
        dap_ht_del(s_policy_anchor_handlers, l_anchor_handler);
        DAP_DELETE(l_anchor_handler);
    }

    pthread_rwlock_destroy(&s_policy_decree_rwlock);
    pthread_rwlock_destroy(&s_policy_anchor_rwlock);
}

