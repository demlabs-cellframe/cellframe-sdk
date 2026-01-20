/*
 * Unit Test Fixtures - DAP SDK Mocking & Isolation
 * 
 * Provides fixtures for isolated unit tests with DAP SDK mocking.
 * These fixtures ensure tests are independent from DAP SDK implementation.
 */

#pragma once

#include "dap_common.h"
#include "dap_config.h"
#include "dap_chain_common.h"
#include "dap_chain_net.h"
#include "dap_chain.h"
#include "dap_chain_ledger.h"
#include "dap_hash.h"
#include "dap_mock.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// DAP SDK MOCK DECLARATIONS
// ============================================================================
// NOTE: Эти декларации включаются в test файлы, где УЖЕ вызван dap_mock_init()
// Правильный порядок в тестах:
//   1. dap_mock_init()
//   2. #include "unit_test_fixtures.h"  ← Моки регистрируются здесь
//   3. unit_test_mock_dap_sdk_ex()      ← Включает нужные моки

// Crypto module mocks
DAP_MOCK_DECLARE(dap_enc_key_new, { .return_value.ptr = NULL });
DAP_MOCK_DECLARE(dap_enc_key_delete, { });
DAP_MOCK_DECLARE(dap_enc_key_new_generate, { .return_value.ptr = NULL });
DAP_MOCK_DECLARE(dap_enc_key_serialize_priv_key, { .return_value.ptr = NULL });
DAP_MOCK_DECLARE(dap_enc_key_serialize_pub_key, { .return_value.ptr = NULL });
DAP_MOCK_DECLARE(dap_enc_key_deserialize_priv_key, { .return_value.ptr = NULL });
DAP_MOCK_DECLARE(dap_enc_key_deserialize_pub_key, { .return_value.ptr = NULL });
DAP_MOCK_DECLARE(dap_enc_key_get_pub_key_hash, { .return_value.ptr = NULL });

DAP_MOCK_DECLARE(dap_sign_create, { .return_value.ptr = NULL });
DAP_MOCK_DECLARE(dap_sign_verify, { .return_value.i = 0 });
DAP_MOCK_DECLARE(dap_sign_get_size, { .return_value.u64 = 64 });
DAP_MOCK_DECLARE(dap_sign_get_pkey_hash, { .return_value.ptr = NULL });

DAP_MOCK_DECLARE(dap_hash_fast, { });
DAP_MOCK_DECLARE(dap_hash_slow, { });

// Global DB mocks
DAP_MOCK_DECLARE(dap_global_db_get, { .return_value.ptr = NULL });
DAP_MOCK_DECLARE(dap_global_db_set, { .return_value.i = 0 });
DAP_MOCK_DECLARE(dap_global_db_set_sync, { .return_value.i = 0 });
DAP_MOCK_DECLARE(dap_global_db_del, { .return_value.i = 0 });
DAP_MOCK_DECLARE(dap_global_db_driver_add, { .return_value.i = 0 });
DAP_MOCK_DECLARE(dap_global_db_driver_delete, { });

// Time mocks
DAP_MOCK_DECLARE(dap_time_now, { .return_value.u64 = 1000000 });
DAP_MOCK_DECLARE(dap_nanotime_now, { .return_value.u64 = 1000000000 });

// JSON mocks
DAP_MOCK_DECLARE(dap_json_object_new_object, { .return_value.ptr = NULL });
DAP_MOCK_DECLARE(dap_json_object_add, { });
DAP_MOCK_DECLARE(dap_json_object_get, { .return_value.ptr = NULL });
DAP_MOCK_DECLARE(dap_json_object_to_json_string, { .return_value.ptr = NULL });

// File utils mocks
DAP_MOCK_DECLARE(dap_file_test, { .return_value.i = 0 });
DAP_MOCK_DECLARE(dap_file_get_contents, { .return_value.ptr = NULL });
DAP_MOCK_DECLARE(dap_file_set_contents, { .return_value.i = 0 });
DAP_MOCK_DECLARE(dap_mkdir_with_parents, { .return_value.i = 0 });

// Event mocks
DAP_MOCK_DECLARE(dap_events_start, { .return_value.i = 0 });
DAP_MOCK_DECLARE(dap_events_wait, { });
DAP_MOCK_DECLARE(dap_events_stop, { });
DAP_MOCK_DECLARE(dap_events_socket_create_type_unix_client, { .return_value.ptr = NULL });

// Network client mocks
DAP_MOCK_DECLARE(dap_client_new, { .return_value.ptr = NULL });
DAP_MOCK_DECLARE(dap_client_delete, { });
DAP_MOCK_DECLARE(dap_client_connect, { .return_value.i = 0 });
DAP_MOCK_DECLARE(dap_client_disconnect, { });

// Network server mocks
DAP_MOCK_DECLARE(dap_server_new, { .return_value.ptr = NULL });
DAP_MOCK_DECLARE(dap_server_delete, { });
DAP_MOCK_DECLARE(dap_server_listen, { .return_value.i = 0 });

// Stream mocks
DAP_MOCK_DECLARE(dap_stream_new, { .return_value.ptr = NULL });
DAP_MOCK_DECLARE(dap_stream_delete, { });
DAP_MOCK_DECLARE(dap_stream_write, { .return_value.u64 = 0 });
DAP_MOCK_DECLARE(dap_stream_read, { .return_value.u64 = 0 });

// Proc thread mocks
DAP_MOCK_DECLARE(dap_proc_thread_create, { .return_value.ptr = NULL });
DAP_MOCK_DECLARE(dap_proc_thread_delete, { });
DAP_MOCK_DECLARE(dap_proc_thread_assign_on_worker_inter, { .return_value.i = 0 });

// Worker mocks
DAP_MOCK_DECLARE(dap_worker_add_events_socket, { .return_value.i = 0 });
DAP_MOCK_DECLARE(dap_worker_exec_callback_on, { .return_value.i = 0 });
DAP_MOCK_DECLARE(dap_worker_exec_callback_inter, { .return_value.i = 0 });

// Ring buffer mocks
DAP_MOCK_DECLARE(dap_ring_buffer_create, { .return_value.ptr = NULL });
DAP_MOCK_DECLARE(dap_ring_buffer_delete, { });
DAP_MOCK_DECLARE(dap_ring_buffer_write, { .return_value.u64 = 0 });
DAP_MOCK_DECLARE(dap_ring_buffer_read, { .return_value.u64 = 0 });

// ============================================================================
// UNIT TEST CONTEXT
// ============================================================================

// ============================================================================
// DAP SDK MODULE MOCKING FLAGS
// ============================================================================

/**
 * @brief DAP SDK module mocking flags
 * Fine-grained control over which DAP SDK modules to mock
 */
typedef struct {
    // Core modules
    bool mock_crypto;            // dap-sdk/crypto (sign, verify, encrypt, hash)
    bool mock_global_db;         // dap-sdk/global-db (key-value storage)
    bool mock_events;            // dap-sdk/core/events
    bool mock_proc_thread;       // dap-sdk/core/proc_thread
    bool mock_worker;            // dap-sdk/core/worker
    
    // Network modules
    bool mock_net_client;        // dap-sdk/net/client
    bool mock_net_server;        // dap-sdk/net/server
    bool mock_stream;            // dap-sdk/net/stream
    
    // JSON module
    bool mock_json;              // dap-sdk/core/json
    
    // Time & timer
    bool mock_time;              // dap-sdk/core/time
    bool mock_timerfd;           // dap-sdk/core/timerfd
    
    // Memory & IO
    bool mock_file_utils;        // dap-sdk/core/file_utils
    bool mock_ring_buffer;       // dap-sdk/core/ring_buffer
} dap_sdk_mock_flags_t;

/**
 * @brief Unit test context with mocked DAP SDK
 * Contains all necessary state for isolated unit testing
 */
typedef struct {
    char *test_dir;              // Temporary test directory
    char *config_path;           // Path to generated config
    dap_config_t *config;        // Test configuration
    
    // DAP SDK mocking configuration
    dap_sdk_mock_flags_t mock_flags;
    
    // Mocked components (references only, not owned)
    void *mock_crypto;           // Mocked crypto context
    void *mock_global_db;        // Mocked global DB
    void *mock_events;           // Mocked event system
    
    // Legacy flags (deprecated, use mock_flags instead)
    bool crypto_mocked;
    bool db_mocked;
    bool events_mocked;
    bool network_mocked;
} unit_test_context_t;

// ============================================================================
// UNIT TEST FIXTURE FUNCTIONS
// ============================================================================

/**
 * @brief Initialize unit test context
 * 
 * Sets up isolated test environment with mocked DAP SDK components.
 * Creates temporary directory and minimal configuration.
 * 
 * @param a_test_name Test name (used for directory naming)
 * @return Initialized context or NULL on error
 */
unit_test_context_t *unit_test_fixture_init(const char *a_test_name);

/**
 * @brief Cleanup unit test context
 * 
 * Removes temporary files and frees resources.
 * 
 * @param a_ctx Test context to cleanup
 */
void unit_test_fixture_cleanup(unit_test_context_t *a_ctx);

/**
 * @brief Generate minimal test configuration
 * 
 * Creates a minimal config file for unit tests without external dependencies.
 * 
 * @param a_ctx Test context
 * @param a_section Section name
 * @param a_params NULL-terminated array of "key=value" strings
 * @return 0 on success, negative on error
 */
int unit_test_config_generate(unit_test_context_t *a_ctx, 
                               const char *a_section,
                               const char **a_params);

/**
 * @brief Setup DAP SDK mocks with fine-grained control
 * 
 * Initializes mocks for specific DAP SDK modules to isolate unit tests.
 * Uses dap_mock framework for function wrapping.
 * 
 * @param a_ctx Test context
 * @param a_mock_flags Flags indicating which modules to mock
 * @return 0 on success, negative on error
 */
int unit_test_mock_dap_sdk_ex(unit_test_context_t *a_ctx,
                               const dap_sdk_mock_flags_t *a_mock_flags);

/**
 * @brief Setup DAP SDK mocks (legacy API)
 * 
 * @deprecated Use unit_test_mock_dap_sdk_ex() for fine-grained control
 * @param a_ctx Test context
 * @param a_mock_crypto Enable crypto mocking
 * @param a_mock_db Enable global DB mocking
 * @param a_mock_events Enable events mocking
 * @return 0 on success, negative on error
 */
int unit_test_mock_dap_sdk(unit_test_context_t *a_ctx,
                            bool a_mock_crypto,
                            bool a_mock_db,
                            bool a_mock_events);

/**
 * @brief Enable/disable specific DAP SDK module mock at runtime
 * 
 * Allows dynamic toggling of mocks during test execution.
 * 
 * @param a_ctx Test context
 * @param a_module_name Module name (e.g. "crypto", "global_db", "events")
 * @param a_enable Enable or disable the mock
 * @return 0 on success, negative on error
 */
int unit_test_mock_toggle(unit_test_context_t *a_ctx,
                           const char *a_module_name,
                           bool a_enable);

// ============================================================================
// TEST DATA GENERATORS
// ============================================================================

/**
 * @brief Generate deterministic test hash
 * @param a_seed Seed value
 * @param a_hash Output hash
 */
void unit_test_hash_generate(uint32_t a_seed, dap_hash_fast_t *a_hash);

/**
 * @brief Generate test address
 * @param a_seed Seed value
 * @param a_net_id Network ID
 * @param a_addr Output address
 */
void unit_test_addr_generate(uint32_t a_seed, uint64_t a_net_id, dap_chain_addr_t *a_addr);

/**
 * @brief Generate test signature (mocked)
 * @param a_seed Seed value
 * @param a_data Data to sign
 * @param a_data_size Data size
 * @return Mocked signature or NULL
 */
dap_sign_t *unit_test_sign_generate(uint32_t a_seed, const void *a_data, size_t a_data_size);

/**
 * @brief Generate test uint256 value
 * @param a_value Value to convert
 * @param a_out Output uint256
 */
void unit_test_uint256_generate(uint64_t a_value, uint256_t *a_out);

#ifdef __cplusplus
}
#endif
