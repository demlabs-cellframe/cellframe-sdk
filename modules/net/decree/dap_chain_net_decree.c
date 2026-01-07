/*
 * Authors:
 * Dmitriy Gerasimov <naeper@demlabs.net>
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 */

#include "dap_chain_net_decree.h"
#include "dap_chain_decree_callbacks.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_ledger.h"
#include "dap_tsd.h"
#include "dap_common.h"

#define LOG_TAG "dap_chain_net_decree"

// Forward declarations for handlers
static int s_net_decree_fee_handler(dap_chain_datum_decree_t *a_decree, 
                                    dap_ledger_t *a_ledger,
                                    dap_chain_t *a_chain,
                                    bool a_apply);

static int s_net_decree_poa_handler(dap_chain_datum_decree_t *a_decree,
                                    dap_ledger_t *a_ledger, 
                                    dap_chain_t *a_chain,
                                    bool a_apply);

// Initialize and register handlers
int dap_chain_net_decree_init(void) {
    // Register handler for FEE decree
    int l_ret = dap_chain_decree_handler_register(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_FEE,
        s_net_decree_fee_handler
    );
    
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to register FEE decree handler");
        return l_ret;
    }
    
    // Register handler for PoA decree
    l_ret = dap_chain_decree_handler_register(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS,
        s_net_decree_poa_handler
    );
    
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to register PoA decree handler");
        return l_ret;
    }
    
    log_it(L_NOTICE, "Network decree handlers initialized");
    return 0;
}

void dap_chain_net_decree_deinit(void) {
    // Handlers are stored globally, no need to explicitly unregister
    log_it(L_INFO, "Network decree handlers deinitialized");
}

// FEE decree handler implementation
static int s_net_decree_fee_handler(dap_chain_datum_decree_t *a_decree,
                                    dap_ledger_t *a_ledger,
                                    dap_chain_t *a_chain,
                                    bool a_apply) {
    UNUSED(a_chain);
    
    if (!a_decree || !a_ledger) {
        log_it(L_ERROR, "Invalid parameters");
        return -1;
    }
    
    // Extract fee parameters from decree
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE);
    if (!l_tsd || l_tsd->size != sizeof(uint256_t)) {
        log_it(L_ERROR, "Invalid FEE decree: missing or invalid fee TSD");
        return -3;
    }
    
    uint256_t l_fee = *(uint256_t *)l_tsd->data;
    
    // Get fee address
    dap_tsd_t *l_addr_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE_WALLET);
    dap_chain_addr_t l_fee_addr;
    
    if (l_addr_tsd && l_addr_tsd->size == sizeof(dap_chain_addr_t)) {
        l_fee_addr = *(dap_chain_addr_t *)l_addr_tsd->data;
    } else {
        // Use current fee address
        l_fee_addr = a_ledger->fee_addr;
    }
    
    if (!a_apply) {
        // Verification only
        log_it(L_INFO, "FEE decree verification passed");
        return 0;
    }
    
    // Apply fee change via ledger callback
    if (a_ledger->decree_set_fee_callback) {
        int l_ret = a_ledger->decree_set_fee_callback(a_ledger, l_fee, l_fee_addr);
        if (l_ret != 0) {
            log_it(L_ERROR, "Failed to set fee via callback");
            return l_ret;
        }
    } else {
        // Fallback: update ledger directly
        a_ledger->fee_value = l_fee;
        a_ledger->fee_addr = l_fee_addr;
    }
    
    const char *l_fee_str = dap_uint256_to_char(l_fee, NULL);
    const char *l_addr_str = dap_chain_addr_to_str(&l_fee_addr);
    log_it(L_NOTICE, "Network fee updated: %s, address: %s", l_fee_str, l_addr_str);
    
    return 0;
}

// PoA decree handler implementation  
static int s_net_decree_poa_handler(dap_chain_datum_decree_t *a_decree,
                                    dap_ledger_t *a_ledger,
                                    dap_chain_t *a_chain,
                                    bool a_apply) {
    UNUSED(a_chain);
    
    if (!a_decree || !a_ledger) {
        log_it(L_ERROR, "Invalid parameters");
        return -1;
    }
    
    // Extract PoA configuration from decree
    dap_tsd_t *l_min_count_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_SIGNERS_COUNT);
    
    if (!l_min_count_tsd || l_min_count_tsd->size != sizeof(uint16_t)) {
        log_it(L_ERROR, "Invalid PoA decree: missing or invalid min signs count");
        return -3;
    }
    
    uint16_t l_min_count = *(uint16_t *)l_min_count_tsd->data;
    
    if (!a_apply) {
        // Verification only
        log_it(L_INFO, "PoA decree verification passed");
        return 0;
    }
    
    // Apply PoA configuration change directly to ledger
    a_ledger->poa_keys_min_count = l_min_count;
    
    log_it(L_NOTICE, "PoA configuration updated: min_signs=%u", l_min_count);
    
    return 0;
}
