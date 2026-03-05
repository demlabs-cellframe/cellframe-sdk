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
#include "dap_chain_mempool.h"

/**
 * @brief Wrapper for checking if record exists in global_db
 */
bool dap_global_db_driver_is_w(const char *a_group, const char *a_key)
{
    dap_global_db_store_obj_t *l_obj = dap_global_db_get_raw_sync(a_group, a_key);
    if (l_obj) {
        dap_global_db_store_obj_free(l_obj, 1);
        return true;
    }
    return false;
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


