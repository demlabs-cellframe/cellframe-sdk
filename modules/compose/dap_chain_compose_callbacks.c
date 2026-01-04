/**
 * @file dap_chain_tx_compose_callbacks.c
 * @brief Implementation of universal compose callback system
 */

#include "dap_chain_tx_compose_callbacks.h"
#include "dap_common.h"
#include "uthash.h"

#define LOG_TAG "dap_tx_compose_callbacks"

// Callback registry item
typedef struct dap_tx_compose_callback_item {
    uint64_t srv_uid;
    dap_chain_tx_compose_callback_t callback;
    UT_hash_handle hh;
} dap_tx_compose_callback_item_t;

static dap_tx_compose_callback_item_t *s_compose_callbacks = NULL;

void dap_chain_tx_compose_service_callback_register(uint64_t a_srv_uid, dap_chain_tx_compose_callback_t a_callback)
{
    if (!a_callback) {
        log_it(L_WARNING, "Attempting to register NULL callback for service %"DAP_UINT64_FORMAT_X, a_srv_uid);
        return;
    }
    
    dap_tx_compose_callback_item_t *l_item = NULL;
    HASH_FIND(hh, s_compose_callbacks, &a_srv_uid, sizeof(uint64_t), l_item);
    
    if (l_item) {
        log_it(L_WARNING, "Compose callback for service %"DAP_UINT64_FORMAT_X" already registered, replacing", a_srv_uid);
        l_item->callback = a_callback;
    } else {
        l_item = DAP_NEW_Z(dap_tx_compose_callback_item_t);
        if (!l_item) {
            log_it(L_CRITICAL, "Memory allocation failed");
            return;
        }
        l_item->srv_uid = a_srv_uid;
        l_item->callback = a_callback;
        HASH_ADD(hh, s_compose_callbacks, srv_uid, sizeof(uint64_t), l_item);
        log_it(L_NOTICE, "Compose callback registered for service %"DAP_UINT64_FORMAT_X, a_srv_uid);
    }
}

dap_chain_tx_compose_callback_t dap_chain_tx_compose_service_callback_get(uint64_t a_srv_uid)
{
    dap_tx_compose_callback_item_t *l_item = NULL;
    HASH_FIND(hh, s_compose_callbacks, &a_srv_uid, sizeof(uint64_t), l_item);
    return l_item ? l_item->callback : NULL;
}

void dap_chain_tx_compose_service_callback_unregister(uint64_t a_srv_uid)
{
    dap_tx_compose_callback_item_t *l_item = NULL;
    HASH_FIND(hh, s_compose_callbacks, &a_srv_uid, sizeof(uint64_t), l_item);
    if (l_item) {
        HASH_DEL(s_compose_callbacks, l_item);
        DAP_DELETE(l_item);
        log_it(L_NOTICE, "Compose callback unregistered for service %"DAP_UINT64_FORMAT_X, a_srv_uid);
    }
}

int dap_chain_tx_compose_callbacks_init(void)
{
    log_it(L_NOTICE, "Initializing compose callbacks system");
    s_compose_callbacks = NULL;
    return 0;
}

void dap_chain_tx_compose_callbacks_deinit(void)
{
    log_it(L_NOTICE, "Deinitializing compose callbacks system");
    
    dap_tx_compose_callback_item_t *l_item, *l_tmp;
    HASH_ITER(hh, s_compose_callbacks, l_item, l_tmp) {
        HASH_DEL(s_compose_callbacks, l_item);
        log_it(L_INFO, "Unregistering compose callback for service %"DAP_UINT64_FORMAT_X, l_item->srv_uid);
        DAP_DELETE(l_item);
    }
    
    s_compose_callbacks = NULL;
}
