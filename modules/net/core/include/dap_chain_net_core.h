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
// Note: Network registration happens in dap_chain_net.c:s_net_new()
// These lookup functions access the global registry from there

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

// ============ MODULE INITIALIZATION ============

/**
 * @brief Initialize network core module and register API functions
 * @details This function must be called before dap_chain_net_init()
 *          to properly register API functions and avoid circular dependencies
 * @return 0 on success, negative error code on failure
 */
int dap_chain_net_core_init(void);

#ifdef __cplusplus
}
#endif

