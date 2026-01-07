/*
 * Authors:
 * Daniil Frolov <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright (c) 2025, All rights reserved.
 *
 * This file is part of CellFrame SDK the open source project
 */

#include "dap_chain_cs_esbocs.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_decree_registry.h"
#include "dap_chain.h"  // For dap_chain_find_by_id, dap_chain_get_cs_type
#include "dap_chain_net.h"
#include "dap_chain_srv.h"
#include "dap_chain_ledger.h"
#include "dap_common.h"
#include "dap_hash.h"
#include "dap_tsd.h"

#define LOG_TAG "esbocs_decree"

// Handler for HARDFORK decree
static int s_decree_hardfork_handler(
    dap_chain_datum_decree_t *a_decree,
    dap_chain_net_t *a_net,
    bool a_apply,
    bool a_anchored)
{
    UNUSED(a_anchored);
    uint64_t l_block_num = 0;
    if (dap_chain_datum_decree_get_atom_num(a_decree, &l_block_num)) {
        log_it(L_WARNING, "Can't get atom number from hardfork prepare decree");
        return -105;
    }
    dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
    if (!l_chain) {
        log_it(L_WARNING, "Specified chain not found");
        return -106;
    }
    if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
        log_it(L_WARNING, "Can't apply this decree to specified chain");
        return -115;
    }
    if (!a_apply)
        return 0;
    
    // Extract stake information if present
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size,
                                    DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HARDFORK_CHANGED_ADDRS);
    void *l_hardfork_data = NULL;
    size_t l_hardfork_data_size = 0;
    if (l_tsd) {
        l_hardfork_data = l_tsd->data;
        l_hardfork_data_size = l_tsd->size;
    }
    
    dap_hash_fast_t l_decree_hash = {};
    dap_hash_fast(a_decree, dap_chain_datum_decree_get_size(a_decree), &l_decree_hash);
    l_chain->hardfork_decree_hash = l_decree_hash;
    
    // TODO: Fix signature - last parameter should be dap_json_t*, not dap_hash_fast_t*
    // return dap_chain_esbocs_set_hardfork_prepare(l_chain, l_block_num, l_hardfork_data_size,
    //                                               l_hardfork_data, &l_decree_hash);
    log_it(L_WARNING, "HARDFORK_PREPARE decree handler temporarily disabled - requires refactoring");
    return -1;
}

// Handler for HARDFORK_RETRY decree
static int s_decree_hardfork_retry_handler(
    dap_chain_datum_decree_t *a_decree,
    dap_chain_net_t *a_net,
    bool a_apply,
    bool a_anchored)
{
    UNUSED(a_anchored);
    dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
    if (!l_chain) {
        log_it(L_WARNING, "Specified chain not found");
        return -106;
    }
    if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
        log_it(L_WARNING, "Can't apply this decree to specified chain");
        return -115;
    }
    if (!dap_chain_esbocs_hardfork_engaged(l_chain)) {
        log_it(L_WARNING, "Hardfork is not engaged, can't retry");
        return -116;
    }
    if (!a_apply)
        return 0;
    dap_hash_fast_t l_decree_hash = {};
    dap_hash_fast(a_decree, dap_chain_datum_decree_get_size(a_decree), &l_decree_hash);
    l_chain->hardfork_decree_hash = l_decree_hash;
    return dap_chain_esbocs_set_hardfork_prepare(l_chain, 0, 0, NULL, NULL);
}

// Handler for HARDFORK_COMPLETE decree
static int s_decree_hardfork_complete_handler(
    dap_chain_datum_decree_t *a_decree,
    dap_chain_net_t *a_net,
    bool a_apply,
    bool a_anchored)
{
    UNUSED(a_anchored);
    dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
    if (!l_chain) {
        log_it(L_WARNING, "Specified chain not found");
        return -106;
    }
    if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
        log_it(L_WARNING, "Can't apply this decree to specified chain");
        return -115;
    }
    if (!a_apply)
        return 0;
    // Call hardfork complete callback for all registered services
    dap_chain_srv_hardfork_complete_all(a_net->pub.id);
    // Call hardfork complete for chain
    return dap_chain_esbocs_set_hardfork_complete(l_chain);
}

// Handler for HARDFORK_CANCEL decree
static int s_decree_hardfork_cancel_handler(
    dap_chain_datum_decree_t *a_decree,
    dap_chain_net_t *a_net,
    bool a_apply,
    bool a_anchored)
{
    UNUSED(a_anchored);
    dap_tsd_t *l_chain_id = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size,
                                         DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HARDFORK_CANCEL_CHAIN_ID);
    if (!l_chain_id || l_chain_id->size != sizeof(uint64_t)) {
        log_it(L_WARNING, "Can't apply this decree, it have no target chain ID set");
        return -116;
    }
    dap_chain_id_t l_target_chain_id = (dap_chain_id_t){ .uint64 = *(uint64_t *)l_chain_id->data };
    dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, l_target_chain_id);
    if (!l_chain) {
        log_it(L_WARNING, "Specified chain not found");
        return -106;
    }
    dap_tsd_t *l_generation = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size,
                                           DAP_CHAIN_DATUM_DECREE_TSD_TYPE_GENERATION);
    if (!l_generation || l_generation->size != sizeof(uint16_t)) {
        log_it(L_WARNING, "Can't apply this decree, it have no chain generation set");
        return -116;
    }
    uint16_t l_banned_generation = *(uint16_t *)l_generation->data;
    if (!a_apply)
        return 0;
    if (l_chain->generation == l_banned_generation) {
        dap_chain_esbocs_set_hardfork_complete(l_chain);
        // TODO: Fix signature - first parameter should be dap_ledger_t*, not dap_chain_t*
        // dap_ledger_chain_purge(l_chain, 0);
        log_it(L_WARNING, "Chain purge temporarily disabled - requires refactoring");
    }
    return 0;
}

// Handler for CHECK_SIGNS_STRUCTURE decree
static int s_decree_check_signs_structure_handler(
    dap_chain_datum_decree_t *a_decree,
    dap_chain_net_t *a_net,
    bool a_apply,
    bool a_anchored)
{
    UNUSED(a_anchored);
    uint8_t l_action = 0;
    if (dap_chain_datum_decree_get_action(a_decree, &l_action)) {
        log_it(L_WARNING, "Can't get action from decree.");
        return -105;
    }
    uint32_t l_signature_type = 0;
    if (dap_chain_datum_decree_get_signature_type(a_decree, &l_signature_type)) {
        log_it(L_WARNING, "Can't get signature type from decree.");
        return -106;
    }
    dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
    if (!l_chain) {
        log_it(L_WARNING, "Specified chain not found");
        return -107;
    }
    if (!a_apply)
        return 0;
    // TODO: Function dap_chain_esbocs_directive_set_signs_check not found - requires refactoring
    // return dap_chain_esbocs_directive_set_signs_check(l_chain, l_action, (dap_sign_type_t)l_signature_type);
    log_it(L_WARNING, "CHECK_SIGNS_STRUCTURE decree handler temporarily disabled - function not found");
    return -1;
}

// Handler for EMERGENCY_VALIDATORS decree
static int s_decree_emergency_validators_handler(
    dap_chain_datum_decree_t *a_decree,
    dap_chain_net_t *a_net,
    bool a_apply,
    bool a_anchored)
{
    UNUSED(a_anchored);
    uint8_t l_action = 0;
    if (dap_chain_datum_decree_get_action(a_decree, &l_action)) {
        log_it(L_WARNING,"Can't get action from decree.");
        return -105;
    }
    dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
    if (!l_chain) {
        log_it(L_WARNING, "Specified chain not found");
        return -106;
    }
    if (dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
        log_it(L_WARNING, "Can't apply this decree to specified chain");
        return -115;
    }
    if (!a_apply)
        return 0;
    // TODO: Function dap_chain_esbocs_directive_set_emergency not found - requires refactoring
    // return dap_chain_esbocs_directive_set_emergency(l_chain, l_action);
    log_it(L_WARNING, "EMERGENCY_VALIDATORS decree handler temporarily disabled - function not found");
    return -1;
}

// Registration function
int dap_chain_cs_esbocs_decree_init(void)
{
    int l_ret = 0;
    
    l_ret += dap_chain_decree_registry_register_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK,
        s_decree_hardfork_handler,
        "hardfork"
    );
    
    l_ret += dap_chain_decree_registry_register_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK_RETRY,
        s_decree_hardfork_retry_handler,
        "hardfork_retry"
    );
    
    l_ret += dap_chain_decree_registry_register_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK_COMPLETE,
        s_decree_hardfork_complete_handler,
        "hardfork_complete"
    );
    
    l_ret += dap_chain_decree_registry_register_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK_CANCEL,
        s_decree_hardfork_cancel_handler,
        "hardfork_cancel"
    );
    
    l_ret += dap_chain_decree_registry_register_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_CHECK_SIGNS_STRUCTURE,
        s_decree_check_signs_structure_handler,
        "check_signs_structure"
    );
    
    l_ret += dap_chain_decree_registry_register_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EMERGENCY_VALIDATORS,
        s_decree_emergency_validators_handler,
        "emergency_validators"
    );
    
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to register some esbocs decree handlers");
        return -1;
    }
    
    log_it(L_NOTICE, "ESBOCS decree handlers registered successfully");
    return 0;
}

void dap_chain_cs_esbocs_decree_deinit(void)
{
    dap_chain_decree_registry_unregister_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK
    );
    dap_chain_decree_registry_unregister_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK_RETRY
    );
    dap_chain_decree_registry_unregister_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK_COMPLETE
    );
    dap_chain_decree_registry_unregister_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK_CANCEL
    );
    dap_chain_decree_registry_unregister_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_CHECK_SIGNS_STRUCTURE
    );
    dap_chain_decree_registry_unregister_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EMERGENCY_VALIDATORS
    );
    
    log_it(L_NOTICE, "ESBOCS decree handlers unregistered");
}








