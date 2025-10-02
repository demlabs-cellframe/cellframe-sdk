/**
 * @file dap_chain_cs.h
 * @brief Chain callbacks helper functions
 * 
 * Callback structure dap_chain_cs_callbacks_t defined in dap_chain.h
 * This file provides registration and retrieval functions
 */

#pragma once

#include "dap_chain.h"

/**
 * @brief Register callbacks for specific chain
 * @param a_chain Chain instance
 * @param a_callbacks Pointer to callbacks structure (must remain valid during chain lifetime)
 */
void dap_chain_cs_set_callbacks(dap_chain_t *a_chain, dap_chain_cs_callbacks_t *a_callbacks);

/**
 * @brief Get registered callbacks for specific chain
 * @param a_chain Chain instance
 * @return Pointer to callbacks structure or NULL if not registered
 */
dap_chain_cs_callbacks_t* dap_chain_cs_get_callbacks(dap_chain_t *a_chain);

