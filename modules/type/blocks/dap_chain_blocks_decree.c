/*
 * Authors:
 * Daniil Frolov <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright (c) 2025, All rights reserved.
 */

#include "dap_chain.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_decree_registry.h"
#include "dap_chain_net_types.h"
#include "dap_common.h"

#define LOG_TAG "blocks_decree"

// Handler for EMPTY_BLOCKGEN decree
static int s_decree_empty_blockgen_handler(
    dap_chain_datum_decree_t *a_decree,
    dap_chain_net_t *a_net,
    bool a_apply,
    bool a_anchored)
{
    UNUSED(a_anchored);
    if (!a_apply)
        return 0;
    uint16_t l_blockgen_period = 0;
    if (dap_chain_datum_decree_get_empty_block_every_times(a_decree, &l_blockgen_period)) {
        log_it(L_WARNING, "Can't get empty block period from decree.");
        return -105;
    }
    dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, a_decree->header.common_decree_params.chain_id);
    if (!l_chain) {
        log_it(L_WARNING, "Specified chain not found");
        return -106;
    }
    l_chain->block_gen_period = l_blockgen_period;
    log_it(L_NOTICE, "Empty block generation period set to %hu for chain %s", l_blockgen_period, l_chain->name);
    return 0;
}

// Register blocks decree handlers
void dap_chain_blocks_decree_init(void)
{
    dap_chain_decree_registry_register_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EMPTY_BLOCKGEN,
        s_decree_empty_blockgen_handler,
        "empty_blockgen"
    );
    
    log_it(L_NOTICE, "Blocks decree handler registered (empty_blockgen)");
}

void dap_chain_blocks_decree_deinit(void)
{
    dap_chain_decree_registry_unregister_handler(
        DAP_CHAIN_DATUM_DECREE_TYPE_COMMON,
        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EMPTY_BLOCKGEN
    );
    
    log_it(L_NOTICE, "Blocks decree handler unregistered");
}

