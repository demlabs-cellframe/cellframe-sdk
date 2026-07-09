/*
 * Authors:
 * Dmitrii Gerasimov <dmitry.gerasimov@demlabs.net>
 * Cellframe Network   https://cellframe.net
 * Copyright (c) 2026, All rights reserved.
 *
 * This file is part of CellFrame SDK the open source project
 */

#include "dap_chain_cs_chipchain.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_decree_registry.h"
#include "dap_chain.h"  // For dap_chain_find_by_id, dap_chain_get_cs_type
#include "dap_chain_net.h"
#include "dap_chain_srv.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net_api.h"  // For dap_chain_net_api_by_id
#include "dap_sign.h"           // For SIG_TYPE_DILITHIUM
#include "dap_common.h"

// Forward declaration from dap_chain_datum_decree.c
int dap_chain_datum_decree_get_hardfork_changed_addrs(dap_chain_datum_decree_t *a_decree, dap_json_t **a_json_obj);
#include "dap_hash.h"
#include "dap_tsd.h"

#define LOG_TAG "chipchain_decree"

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
    if (dap_strcmp(dap_chain_get_cs_type(l_chain), "chipchain")) {
        log_it(L_WARNING, "Can't apply this decree to specified chain");
        return -115;
    }
    if (!a_apply)
        return 0;

    // Extract generation from decree TSD
    uint16_t l_generation = 0;
    dap_tsd_t *l_gen_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size,
                                         DAP_CHAIN_DATUM_DECREE_TSD_TYPE_GENERATION);
    if (l_gen_tsd && l_gen_tsd->size == sizeof(uint16_t))
        l_generation = *(uint16_t *)l_gen_tsd->data;
    else {
        log_it(L_WARNING, "Can't get generation from hardfork prepare decree");
        return -105;
    }

    // Extract changed addresses as JSON from decree TSD
    dap_json_t *l_changed_addrs = NULL;
    dap_chain_datum_decree_get_hardfork_changed_addrs(a_decree, &l_changed_addrs);

    dap_hash_sha3_256_t l_decree_hash = {};
    dap_hash_sha3_256(a_decree, dap_chain_datum_decree_get_size(a_decree), &l_decree_hash);
    l_chain->hardfork_decree_hash = l_decree_hash;

    int l_rc = dap_chain_chipchain_set_hardfork_prepare(l_chain, l_generation, l_block_num, NULL, l_changed_addrs);
    if (l_changed_addrs)
        dap_json_object_free(l_changed_addrs);
    return l_rc;
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
    if (dap_strcmp(dap_chain_get_cs_type(l_chain), "chipchain")) {
        log_it(L_WARNING, "Can't apply this decree to specified chain");
        return -115;
    }
    if (!dap_chain_chipchain_hardfork_engaged(l_chain)) {
        log_it(L_WARNING, "Hardfork is not engaged, can't retry");
        return -116;
    }
    if (!a_apply)
        return 0;
    dap_hash_sha3_256_t l_decree_hash = {};
    dap_hash_sha3_256(a_decree, dap_chain_datum_decree_get_size(a_decree), &l_decree_hash);
    l_chain->hardfork_decree_hash = l_decree_hash;
    return dap_chain_chipchain_set_hardfork_prepare(l_chain, 0, 0, NULL, NULL);
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
    if (dap_strcmp(dap_chain_get_cs_type(l_chain), "chipchain")) {
        log_it(L_WARNING, "Can't apply this decree to specified chain");
        return -115;
    }
    if (!a_apply)
        return 0;
    // Call hardfork complete callback for all registered services
    dap_chain_srv_hardfork_complete_all(a_net->pub.id);
    // Call hardfork complete for chain
    return dap_chain_chipchain_set_hardfork_complete(l_chain);
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
        dap_chain_chipchain_set_hardfork_complete(l_chain);
        // Purge ledger data for the chain
        dap_chain_net_t *l_net = dap_chain_net_api_by_id(a_net->pub.id);
        if (l_net && l_net->pub.ledger)
            dap_ledger_chain_purge(l_net->pub.ledger, l_chain->id, 0);
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

    // Use public API to enable/disable sign structure check
    int l_rc = dap_chain_chipchain_set_signs_struct_check(l_chain, (l_action != 0));
    log_it(L_INFO, "CHECK_SIGNS_STRUCTURE: %s (signature_type=0x%x, rc=%d)",
           l_action ? "enabled" : "disabled", l_signature_type, l_rc);
    return l_rc;
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
    if (dap_strcmp(dap_chain_get_cs_type(l_chain), "chipchain")) {
        log_it(L_WARNING, "Can't apply this decree to specified chain");
        return -115;
    }
    if (!a_apply)
        return 0;

    // Extract pkey hash from decree TSD
    dap_tsd_t *l_pkey_hash_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size,
                                               DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_PKEY);
    if (!l_pkey_hash_tsd || l_pkey_hash_tsd->size != sizeof(dap_hash_sha3_256_t)) {
        log_it(L_WARNING, "Can't get pkey hash from emergency validators decree");
        return -105;
    }
    dap_hash_sha3_256_t *l_pkey_hash = (dap_hash_sha3_256_t *)l_pkey_hash_tsd->data;

    // Extract signature type (default to Dilithium if not present)
    uint32_t l_sign_type_raw = SIG_TYPE_DILITHIUM;

    // Use public API to add/remove emergency validator
    return dap_chain_chipchain_set_emergency_validator(l_chain, (l_action != 0), l_sign_type_raw, l_pkey_hash);
}

// Registration function
int dap_chain_cs_chipchain_decree_init(void)
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
        log_it(L_ERROR, "Failed to register some chipchain decree handlers");
        return -1;
    }

    log_it(L_NOTICE, "chipchain decree handlers registered successfully");
    return 0;
}

void dap_chain_cs_chipchain_decree_deinit(void)
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

    log_it(L_NOTICE, "chipchain decree handlers unregistered");
}
