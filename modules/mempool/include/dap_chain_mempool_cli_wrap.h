/**
 * @file dap_chain_mempool_cli_wrap.h
 * @brief Wrapper functions for mempool CLI commands (for mocking in tests)
 * 
 * This file declares wrapper functions that can be mocked using the DAP Mock Framework.
 * The wrappers are used to intercept calls to underlying mempool/network functions
 * during unit testing, allowing controlled test behavior.
 * 
 * @author Cellframe Team
 * @copyright DeM Labs Inc. 2025
 * @license GPL-3.0
 */

#pragma once

#include "dap_chain_net.h"
#include "dap_chain.h"
#include "dap_global_db.h"
#include "dap_chain_mempool.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Wrapper for dap_chain_net_by_name
 * @param a_name Network name to look up
 * @return Pointer to network structure or NULL if not found
 */
dap_chain_net_t* dap_chain_net_by_name_w(const char *a_name);

/**
 * @brief Wrapper for dap_global_db_get_all_sync
 * @param a_group Group name to query
 * @param a_count Output parameter for object count
 * @return Array of database objects
 */
dap_global_db_obj_t* dap_global_db_get_all_sync_w(const char *a_group, size_t *a_count);

/**
 * @brief Wrapper for dap_global_db_driver_is
 * @param a_group Group name
 * @param a_key Key to check
 * @return true if key exists in group
 */
bool dap_global_db_driver_is_w(const char *a_group, const char *a_key);

/**
 * @brief Wrapper for dap_chain_mempool_group_new
 * @param a_chain Chain to create mempool group for
 * @return Mempool group name string (must be freed by caller)
 */
char* dap_chain_mempool_group_new_w(dap_chain_t *a_chain);

/**
 * @brief Wrapper for dap_chain_mempool_filter
 * @param a_chain Chain to filter mempool for
 * @param a_removed Output parameter for removed count
 */
void dap_chain_mempool_filter_w(dap_chain_t *a_chain, int *a_removed);

/**
 * @brief Wrapper for dap_chain_mempool_datum_add
 * @param a_datum Datum to add
 * @param a_chain Chain to add to
 * @param a_hash_out_type Hash output type
 * @return Hash string of added datum or NULL on error
 */
char* dap_chain_mempool_datum_add_w(const dap_chain_datum_t *a_datum, dap_chain_t *a_chain, const char *a_hash_out_type);

#ifdef __cplusplus
}
#endif

