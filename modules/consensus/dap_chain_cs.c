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

