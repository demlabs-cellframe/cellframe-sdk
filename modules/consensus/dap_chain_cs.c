/**
 * @file dap_chain_cs.c
 * @brief Consensus common API and callbacks (stored per chain)
 */

#include "dap_chain_cs.h"
#include "dap_chain.h"
#include "dap_common.h"
#include "dap_config.h"
#include "uthash.h"

#define LOG_TAG "dap_chain_cs"
#define DAP_CHAIN_CS_NAME_STRLEN_MAX 32

// Consensus registration (esbocs, dag_poa, none)
typedef struct dap_chain_cs_item {
    char name[DAP_CHAIN_CS_NAME_STRLEN_MAX];
    dap_chain_cs_lifecycle_t callbacks;
    UT_hash_handle hh;
} dap_chain_cs_item_t;

static dap_chain_cs_item_t *s_cs_registry = NULL;

/**
 * @brief dap_chain_cs_init - initialize consensus registry
 * @return 0 on success
 */
int dap_chain_cs_init(void)
{
    log_it(L_INFO, "Consensus registry initialized");
    return 0;
}

/**
 * @brief dap_chain_cs_deinit - cleanup consensus registry
 */
void dap_chain_cs_deinit(void)
{
    dap_chain_cs_item_t *l_item, *l_tmp;
    HASH_ITER(hh, s_cs_registry, l_item, l_tmp) {
        HASH_DEL(s_cs_registry, l_item);
        DAP_DELETE(l_item);
    }
    log_it(L_INFO, "Consensus registry cleaned up");
}

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

// ===== Consensus registration and lifecycle =====

/**
 * @brief Register consensus implementation
 */
void dap_chain_cs_add(const char *a_cs_str, dap_chain_cs_lifecycle_t a_callbacks)
{
    dap_chain_cs_item_t *l_item = DAP_NEW_Z_RET_IF_FAIL(dap_chain_cs_item_t);
    dap_strncpy(l_item->name, a_cs_str, sizeof(l_item->name));
    l_item->callbacks = a_callbacks;
    HASH_ADD_STR(s_cs_registry, name, l_item);
    log_it(L_NOTICE, "Consensus '%s' registered", a_cs_str);
}

/**
 * @brief Create consensus from config
 */
int dap_chain_cs_create(dap_chain_t *a_chain, dap_config_t *a_chain_cfg)
{
    const char *l_consensus = dap_config_get_item_str(a_chain_cfg, "chain", "consensus");
    
    if (!l_consensus) {
        log_it(L_ERROR, "No consensus specified in chain config");
        return -1;
    }
    
    dap_chain_cs_item_t *l_item = NULL;
    HASH_FIND_STR(s_cs_registry, l_consensus, l_item);
    if (!l_item) {
        log_it(L_ERROR, "Consensus '%s' not registered", l_consensus);
        return -1;
    }
    
    log_it(L_NOTICE, "Creating consensus '%s' for chain", l_item->name);
    
    // Set consensus name BEFORE callback (callback will set cs_type to chain type)
    DAP_CHAIN_PVT(a_chain)->cs_name = dap_strdup(l_item->name);
    
    int res = 0;
    if (l_item->callbacks.callback_init)
        res = l_item->callbacks.callback_init(a_chain, a_chain_cfg);
    
    return res;
}

int dap_chain_cs_load(dap_chain_t *a_chain, dap_config_t *a_chain_cfg)
{
    dap_chain_cs_item_t *l_item = NULL;
    HASH_FIND_STR(s_cs_registry, DAP_CHAIN_PVT(a_chain)->cs_name, l_item);
    dap_return_val_if_fail_err(l_item, -1, "Consensus %s not registered!", DAP_CHAIN_PVT(a_chain)->cs_name);
    return l_item->callbacks.callback_load
        ? l_item->callbacks.callback_load(a_chain, a_chain_cfg)
        : 0;
}

int dap_chain_cs_start(dap_chain_t *a_chain)
{
    dap_chain_cs_item_t *l_item = NULL;
    HASH_FIND_STR(s_cs_registry, DAP_CHAIN_PVT(a_chain)->cs_name, l_item);
    dap_return_val_if_fail(l_item, -1);
    return l_item->callbacks.callback_start
        ? l_item->callbacks.callback_start(a_chain)
        : 0;
}

int dap_chain_cs_stop(dap_chain_t *a_chain)
{
    dap_chain_cs_item_t *l_item = NULL;
    HASH_FIND_STR(s_cs_registry, DAP_CHAIN_PVT(a_chain)->cs_name, l_item);
    dap_return_val_if_fail(l_item, -1);
    return l_item->callbacks.callback_stop
        ? l_item->callbacks.callback_stop(a_chain)
        : 0;
}

int dap_chain_cs_purge(dap_chain_t *a_chain)
{
    dap_chain_cs_item_t *l_item = NULL;
    HASH_FIND_STR(s_cs_registry, DAP_CHAIN_PVT(a_chain)->cs_name, l_item);
    dap_return_val_if_fail(l_item, -1);
    return l_item->callbacks.callback_purge
        ? l_item->callbacks.callback_purge(a_chain)
        : 0;
}

