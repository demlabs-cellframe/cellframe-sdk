/**
 * @file dap_chain_cs.c
 * @brief Consensus common API and callbacks (stored per chain)
 */

#include "dap_chain_cs.h"
#include "dap_chain.h"
#include "dap_common.h"

#define LOG_TAG "dap_chain_cs"

/**
 * @brief Register consensus callbacks for specific chain
 */
void dap_chain_cs_set_callbacks(dap_chain_t *a_chain, dap_chain_cs_callbacks_t *a_callbacks)
{
    if (!a_chain) {
        log_it(L_ERROR, "Cannot register callbacks: NULL chain");
        return;
    }
    if (!a_callbacks) {
        log_it(L_WARNING, "Attempting to register NULL consensus callbacks for chain %s", a_chain->name);
        return;
    }
    a_chain->cs_callbacks = a_callbacks;
    log_it(L_INFO, "Consensus callbacks registered for chain %s", a_chain->name);
}

/**
 * @brief Get registered callbacks for specific chain
 */
dap_chain_cs_callbacks_t* dap_chain_cs_get_callbacks(dap_chain_t *a_chain)
{
    if (!a_chain) {
        log_it(L_WARNING, "Cannot get callbacks: NULL chain");
        return NULL;
    }
    if (!a_chain->cs_callbacks) {
        log_it(L_DEBUG, "Callbacks not registered for chain %s", a_chain->name);
    }
    return a_chain->cs_callbacks;
}

// ===== Wrapper functions for safe callback invocation =====

// Consensus wrappers
char* dap_chain_cs_get_fee_group(dap_chain_t *a_chain, const char *a_net_name)
{
    dap_chain_cs_callbacks_t *cbs = dap_chain_cs_get_callbacks(a_chain);
    return (cbs && cbs->get_fee_group) ? cbs->get_fee_group(a_net_name) : NULL;
}

char* dap_chain_cs_get_reward_group(dap_chain_t *a_chain, const char *a_net_name)
{
    dap_chain_cs_callbacks_t *cbs = dap_chain_cs_get_callbacks(a_chain);
    return (cbs && cbs->get_reward_group) ? cbs->get_reward_group(a_net_name) : NULL;
}

uint256_t dap_chain_cs_get_fee(dap_chain_t *a_chain)
{
    dap_chain_cs_callbacks_t *cbs = dap_chain_cs_get_callbacks(a_chain);
    return (cbs && cbs->get_fee) ? cbs->get_fee(a_chain->net_id) : uint256_0;
}

dap_pkey_t* dap_chain_cs_get_sign_pkey(dap_chain_t *a_chain)
{
    dap_chain_cs_callbacks_t *cbs = dap_chain_cs_get_callbacks(a_chain);
    return (cbs && cbs->get_sign_pkey) ? cbs->get_sign_pkey(a_chain->net_id) : NULL;
}

uint256_t dap_chain_cs_get_collecting_level(dap_chain_t *a_chain)
{
    dap_chain_cs_callbacks_t *cbs = dap_chain_cs_get_callbacks(a_chain);
    return (cbs && cbs->get_collecting_level) ? cbs->get_collecting_level(a_chain) : uint256_0;
}

void dap_chain_cs_add_block_collect(dap_chain_t *a_chain, void *a_block_cache, void *a_params, int a_type)
{
    dap_chain_cs_callbacks_t *cbs = dap_chain_cs_get_callbacks(a_chain);
    if (cbs && cbs->add_block_collect)
        cbs->add_block_collect(a_block_cache, a_params, a_type);
}

bool dap_chain_cs_get_autocollect_status(dap_chain_t *a_chain)
{
    dap_chain_cs_callbacks_t *cbs = dap_chain_cs_get_callbacks(a_chain);
    return (cbs && cbs->get_autocollect_status) ? cbs->get_autocollect_status(a_chain->net_id) : false;
}

int dap_chain_cs_set_hardfork_state(dap_chain_t *a_chain, bool a_state)
{
    dap_chain_cs_callbacks_t *cbs = dap_chain_cs_get_callbacks(a_chain);
    return (cbs && cbs->set_hardfork_state) ? cbs->set_hardfork_state(a_chain, a_state) : -1;
}

bool dap_chain_cs_hardfork_engaged(dap_chain_t *a_chain)
{
    dap_chain_cs_callbacks_t *cbs = dap_chain_cs_get_callbacks(a_chain);
    return (cbs && cbs->hardfork_engaged) ? cbs->hardfork_engaged(a_chain) : false;
}

// Stake service wrappers
int dap_chain_cs_stake_check_pkey_hash(dap_chain_t *a_chain, dap_hash_fast_t *a_pkey_hash, 
                                       uint256_t *a_sovereign_tax, dap_chain_addr_t *a_sovereign_addr)
{
    dap_chain_cs_callbacks_t *cbs = dap_chain_cs_get_callbacks(a_chain);
    return (cbs && cbs->stake_check_pkey_hash) ? 
        cbs->stake_check_pkey_hash(a_chain->net_id, a_pkey_hash, a_sovereign_tax, a_sovereign_addr) : 0;
}

int dap_chain_cs_stake_hardfork_data_import(dap_chain_t *a_chain, dap_hash_fast_t *a_decree_hash)
{
    dap_chain_cs_callbacks_t *cbs = dap_chain_cs_get_callbacks(a_chain);
    return (cbs && cbs->stake_hardfork_data_import) ? 
        cbs->stake_hardfork_data_import(a_chain->net_id, a_decree_hash) : -1;
}

int dap_chain_cs_stake_switch_table(dap_chain_t *a_chain, bool a_to_sandbox)
{
    dap_chain_cs_callbacks_t *cbs = dap_chain_cs_get_callbacks(a_chain);
    return (cbs && cbs->stake_switch_table) ? 
        cbs->stake_switch_table(a_chain->net_id, a_to_sandbox) : -1;
}

// Mempool wrappers
char* dap_chain_cs_mempool_group_new(dap_chain_t *a_chain)
{
    dap_chain_cs_callbacks_t *cbs = dap_chain_cs_get_callbacks(a_chain);
    return (cbs && cbs->mempool_group_new) ? cbs->mempool_group_new(a_chain) : NULL;
}

char* dap_chain_cs_mempool_datum_add(dap_chain_t *a_chain, dap_chain_datum_t *a_datum, const char *a_hash_out_type)
{
    dap_chain_cs_callbacks_t *cbs = dap_chain_cs_get_callbacks(a_chain);
    return (cbs && cbs->mempool_datum_add) ? cbs->mempool_datum_add(a_datum, a_chain, a_hash_out_type) : NULL;
}

