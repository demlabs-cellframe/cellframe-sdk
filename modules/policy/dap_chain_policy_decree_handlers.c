/*
 * Authors:
 * Daniil Frolov <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright (c) 2025, All rights reserved.
 *
 * This file is part of CellFrame SDK the open source project
 */

#include "dap_chain_policy.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_decree_registry.h"
#include "dap_chain_net.h"
#include "dap_common.h"

#define LOG_TAG "policy_decree"

// Handler for POLICY decree
static int s_decree_policy_handler(
    dap_chain_datum_decree_t *a_decree,
    dap_chain_net_t *a_net,
    bool a_apply,
    bool a_anchored)
{
    UNUSED(a_anchored);
    if (!a_apply)
        return 0;
    dap_chain_policy_t *l_policy = NULL;
    if ( !(l_policy = dap_chain_datum_decree_get_policy(a_decree)) ){
        log_it(L_WARNING,"Can't get policy from decree.");
        return -105;
    }
    return dap_chain_policy_apply(l_policy, a_net->pub.id);
}

// Registration function
int dap_chain_policy_decree_init(void)
{
    int l_ret = dap_chain_decree_registry_register_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_POLICY,
        s_decree_policy_handler,
        "policy"
    );
    
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to register policy decree handler");
        return -1;
    }
    
    log_it(L_NOTICE, "Policy decree handler registered successfully");
    return 0;
}

void dap_chain_policy_decree_deinit(void)
{
    dap_chain_decree_registry_unregister_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_POLICY
    );
    log_it(L_NOTICE, "Policy decree handler unregistered");
}
