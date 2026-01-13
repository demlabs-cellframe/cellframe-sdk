/*
 * Authors:
 * Dmitriy Gerasimov <naeper@demlabs.net>
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 */

#include "dap_chain_ledger_decree.h"
#include "dap_chain_decree_callbacks.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_ledger.h"
#include "dap_chain_ledger_pvt.h"
#include "dap_common.h"

#define LOG_TAG "dap_chain_ledger_decree"

// Handler for OWNERS decree - updates PoA keys list
static int s_decree_owners_handler(dap_chain_datum_decree_t *a_decree,
                                   dap_ledger_t *a_ledger,
                                   dap_chain_t *a_chain,
                                   bool a_apply) {
    UNUSED(a_chain);
    
    if (!a_decree || !a_ledger) {
        return -1;
    }
    
    uint16_t l_owners_num = 0;
    dap_list_t *l_owners_list = dap_chain_datum_decree_get_owners(a_decree, &l_owners_num);
    if (!l_owners_list) {
        log_it(L_WARNING, "Can't get owners from decree");
        return -104;
    }
    
    if (!a_apply) {
        // Verification only - owners list is valid
        dap_list_free_full(l_owners_list, NULL);
        return 0;
    }
    
    // Apply: update ledger's PoA keys
    dap_list_free_full(a_ledger->poa_keys, NULL);
    a_ledger->poa_keys = l_owners_list;
    
    log_it(L_NOTICE, "Updated PoA owners list: %u keys", l_owners_num);
    return 0;
}

// Handler for OWNERS_MIN decree - updates minimum PoA signers count
static int s_decree_owners_min_handler(dap_chain_datum_decree_t *a_decree,
                                       dap_ledger_t *a_ledger,
                                       dap_chain_t *a_chain,
                                       bool a_apply) {
    UNUSED(a_chain);
    
    if (!a_decree || !a_ledger) {
        return -1;
    }
    
    uint256_t l_value;
    if (dap_chain_datum_decree_get_min_owners(a_decree, &l_value)) {
        log_it(L_WARNING, "Can't get min number of owners from decree");
        return -105;
    }
    
    if (IS_ZERO_256(l_value) || compare256(l_value, GET_256_FROM_64(UINT16_MAX)) == 1) {
        log_it(L_WARNING, "Illegal min number of owners %s", dap_uint256_to_char(l_value, NULL));
        return -116;
    }
    
    if (!a_apply) {
        // Verification only
        return 0;
    }
    
    // Apply: update minimum signers count
    a_ledger->poa_keys_min_count = dap_uint256_to_uint64(l_value);
    
    log_it(L_NOTICE, "Updated PoA minimum signers count: %u", a_ledger->poa_keys_min_count);
    return 0;
}

// Handler for EVENT_PKEY_ADD decree
static int s_decree_event_pkey_add_handler(dap_chain_datum_decree_t *a_decree,
                                           dap_ledger_t *a_ledger,
                                           dap_chain_t *a_chain,
                                           bool a_apply) {
    UNUSED(a_decree); UNUSED(a_ledger); UNUSED(a_chain); UNUSED(a_apply);
    log_it(L_DEBUG, "EVENT_PKEY_ADD handler not yet implemented");
    return 0;
}
static int s_decree_event_pkey_remove_handler(dap_chain_datum_decree_t *a_decree,
                                              dap_ledger_t *a_ledger,
                                              dap_chain_t *a_chain,
                                              bool a_apply) {
    UNUSED(a_decree); UNUSED(a_ledger); UNUSED(a_chain); UNUSED(a_apply);
    log_it(L_DEBUG, "EVENT_PKEY_REMOVE handler not yet implemented");
    return 0;
}
