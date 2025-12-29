/*
 * Authors:
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2017-2025
 */

#pragma once

#include "dap_json.h"
#include "dap_chain.h"
#include "dap_chain_net_types.h"  // Base types from common (NOT dap_chain_net.h!)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Network core module
 * @details Base network module containing:
 *  - Global network registry (by name and ID)
 *  - Network lookup functions
 *  - CLI argument parsers
 */

// ============ NETWORK REGISTRY ============

/**
 * @brief Register network in global registry
 * @param a_net Network to register
 */
void dap_chain_net_register(dap_chain_net_t *a_net);

/**
 * @brief Unregister network from global registry
 * @param a_net Network to unregister
 */
void dap_chain_net_unregister(dap_chain_net_t *a_net);

/**
 * @brief Find network by name
 * @param a_name Network name
 * @return Network pointer or NULL if not found
 */
dap_chain_net_t *dap_chain_net_by_name(const char *a_name);

/**
 * @brief Find network by ID
 * @param a_id Network ID
 * @return Network pointer or NULL if not found
 */
dap_chain_net_t *dap_chain_net_by_id(dap_chain_net_id_t a_id);

// ============ CLI UTILITIES ============

/**
 * @brief Parse -net and -chain arguments from CLI
 * @param a_json_arr_reply JSON reply array for errors
 * @param a_arg_index Current argument index (will be updated)
 * @param a_argc Argument count
 * @param a_argv Argument vector
 * @param a_chain Output: parsed chain (can be NULL if not needed)
 * @param a_net Output: parsed network (can be NULL if not needed)
 * @param a_default_chain_type Default chain type if -chain not specified
 * @return 0 on success, negative error code on failure
 */
int dap_chain_net_parse_net_chain(dap_json_t *a_json_arr_reply, int *a_arg_index,
                                       int a_argc, char **a_argv,
                                       dap_chain_t **a_chain, dap_chain_net_t **a_net,
                                       dap_chain_type_t a_default_chain_type);

// Compatibility alias for old name
#define dap_chain_node_cli_cmd_values_parse_net_chain_for_json dap_chain_net_parse_net_chain

#ifdef __cplusplus
}
#endif

