/*
 * Authors:
 * Dmitriy Gerasimov <naeper@demlabs.net>
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 */

#include "dap_chain_decree_callbacks.h"
#include "dap_common.h"
#include "uthash.h"

#define LOG_TAG "dap_chain_decree_callbacks"

// Decree handler registry entry
typedef struct dap_chain_decree_handler_item {
    uint32_t key;  // Combined type+subtype as key
    dap_chain_decree_handler_t handler;
    UT_hash_handle hh;
} dap_chain_decree_handler_item_t;

// Global handler registry
static dap_chain_decree_handler_item_t *s_handlers = NULL;

// Helper: create combined key from type+subtype
static inline uint32_t s_make_key(uint16_t a_type, uint16_t a_subtype) {
    return ((uint32_t)a_type << 16) | a_subtype;
}

// Register decree handler
int dap_chain_decree_handler_register(uint16_t a_decree_type, 
                                      uint16_t a_decree_subtype,
                                      dap_chain_decree_handler_t a_handler) {
    if (!a_handler) {
        log_it(L_ERROR, "NULL handler provided");
        return -1;
    }
    
    uint32_t l_key = s_make_key(a_decree_type, a_decree_subtype);
    
    // Check if already registered
    dap_chain_decree_handler_item_t *l_item = NULL;
    HASH_FIND_INT(s_handlers, &l_key, l_item);
    
    if (l_item) {
        log_it(L_WARNING, "Handler for decree type=%u subtype=%u already registered, replacing",
               a_decree_type, a_decree_subtype);
        l_item->handler = a_handler;
        return 0;
    }
    
    // Create new entry
    l_item = DAP_NEW_Z(dap_chain_decree_handler_item_t);
    if (!l_item) {
        log_it(L_CRITICAL, "Memory allocation failed");
        return -2;
    }
    
    l_item->key = l_key;
    l_item->handler = a_handler;
    
    HASH_ADD_INT(s_handlers, key, l_item);
    
    log_it(L_INFO, "Registered decree handler for type=%u subtype=%u", a_decree_type, a_decree_subtype);
    return 0;
}

// Call registered handler
int dap_chain_decree_handler_call(uint16_t a_decree_type,
                                  uint16_t a_decree_subtype,
                                  dap_chain_datum_decree_t *a_decree,
                                  dap_ledger_t *a_ledger,
                                  dap_chain_t *a_chain,
                                  bool a_apply) {
    uint32_t l_key = s_make_key(a_decree_type, a_decree_subtype);
    
    dap_chain_decree_handler_item_t *l_item = NULL;
    HASH_FIND_INT(s_handlers, &l_key, l_item);
    
    if (!l_item || !l_item->handler) {
        log_it(L_WARNING, "No handler registered for decree type=%u subtype=%u", 
               a_decree_type, a_decree_subtype);
        return -1;
    }
    
    return l_item->handler(a_decree, a_ledger, a_chain, a_apply);
}
