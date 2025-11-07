/**
 * @file test_ledger_fixtures.h
 * @brief Test fixtures for ledger initialization and cleanup
 * @details Provides helper functions for setting up test environments
 * 
 * @author Cellframe Team
 * @date 2025-01-16
 */

#pragma once

#include "dap_chain_ledger.h"
#include "dap_chain_net.h"
#include "dap_chain.h"
#include "dap_test.h"
#include <json-c/json.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Test network fixture structure
 */
typedef struct test_net_fixture {
    dap_chain_net_t *net;
    dap_ledger_t *ledger;
    dap_chain_t *chain_zero;       ///< Zero chain (like in production networks)
    dap_chain_t *chain_main;        ///< Master/main chain (like in production networks)
    char *net_name;
    dap_chain_type_t *chain_main_datum_types; ///< Pointer to datum_types array we created (for cleanup)
} test_net_fixture_t;

/**
 * @brief Initialize test network and ledger
 * @param a_net_name Test network name
 * @return Initialized fixture or NULL on error
 */
test_net_fixture_t *test_net_fixture_create(const char *a_net_name);

/**
 * @brief Cleanup test network and ledger
 * @param a_fixture Fixture to cleanup
 */
void test_net_fixture_destroy(test_net_fixture_t *a_fixture);

/**
 * @brief Get first emission hash for token (for testing)
 * @param a_ledger Ledger instance
 * @param a_token_ticker Token ticker
 * @param a_emission_hash Output emission hash
 * @return true if emission found, false otherwise
 * @note This function uses internal ledger structures for testing purposes
 */
bool test_ledger_get_token_emission_hash(dap_ledger_t *a_ledger, 
                                          const char *a_token_ticker,
                                          dap_chain_hash_fast_t *a_emission_hash);

/**
 * @brief Initialize test environment (config, certs, global DB)
 * @param a_config_dir Directory for test config files (can be NULL for default)
 * @param a_global_db_path Path for global DB storage (can be NULL for default)
 * @return 0 on success, negative on error
 * @note This function is idempotent - can be called multiple times safely
 * @note Should be called before creating network fixtures if mempool/global DB is needed
 */
int test_env_init(const char *a_config_dir, const char *a_global_db_path);

/**
 * @brief Deinitialize test environment
 * @note This function is idempotent - can be called multiple times safely
 * @note Should be called after destroying all network fixtures
 */
void test_env_deinit(void);

/**
 * @brief Structure for JSON-RPC error information
 */
typedef struct test_json_rpc_error {
    bool has_error;         ///< Whether an error was found
    int error_code;         ///< Error code (0 if no error)
    const char *error_msg;  ///< Error message (NULL if no error)
} test_json_rpc_error_t;

/**
 * @brief Parse JSON-RPC response to extract error information
 * @param a_json_response JSON object containing the JSON-RPC response
 * @param a_error Output structure for error information
 * @return true if error was found, false otherwise
 * @note Supports both formats:
 *   - New format: result[].errors[] (array of error objects)
 *   - Legacy format: top-level error object
 * @note If multiple errors exist, only the first one is returned
 */
bool test_json_rpc_parse_error(json_object *a_json_response, test_json_rpc_error_t *a_error);

#ifdef __cplusplus
}
#endif

