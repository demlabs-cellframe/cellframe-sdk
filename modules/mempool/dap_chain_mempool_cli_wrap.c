/**
 * @file dap_chain_mempool_cli_wrap.c
 * @brief Wrapper function implementations for mempool CLI commands
 * 
 * These wrapper functions delegate to the real implementations and can be
 * intercepted by the DAP Mock Framework during unit testing.
 * 
 * @author Cellframe Team
 * @copyright DeM Labs Inc. 2025
 * @license GPL-3.0
 */

#include "dap_chain_mempool_cli_wrap.h"
#include "dap_chain_net.h"
#include "dap_global_db.h"
#include "dap_global_db_driver.h"
#include "dap_chain_mempool.h"

/**
 * @brief Wrapper for dap_chain_net_by_name
 */
dap_chain_net_t* dap_chain_net_by_name_w(const char *a_name)
{
    return dap_chain_net_by_name(a_name);
}

/**
 * @brief Wrapper for dap_global_db_get_all_sync
 */
dap_global_db_obj_t* dap_global_db_get_all_sync_w(const char *a_group, size_t *a_count)
{
    return dap_global_db_get_all_sync(a_group, a_count);
}

/**
 * @brief Wrapper for dap_global_db_driver_is
 */
bool dap_global_db_driver_is_w(const char *a_group, const char *a_key)
{
    return dap_global_db_driver_is(a_group, a_key);
}

/**
 * @brief Wrapper for dap_chain_mempool_group_new
 */
char* dap_chain_mempool_group_new_w(dap_chain_t *a_chain)
{
    return dap_chain_mempool_group_new(a_chain);
}

/**
 * @brief Wrapper for dap_chain_mempool_filter
 */
void dap_chain_mempool_filter_w(dap_chain_t *a_chain, int *a_removed)
{
    dap_chain_mempool_filter(a_chain, a_removed);
}

/**
 * @brief Wrapper for dap_chain_mempool_datum_add
 */
char* dap_chain_mempool_datum_add_w(const dap_chain_datum_t *a_datum, dap_chain_t *a_chain, const char *a_hash_out_type)
{
    return dap_chain_mempool_datum_add(a_datum, a_chain, a_hash_out_type);
}


