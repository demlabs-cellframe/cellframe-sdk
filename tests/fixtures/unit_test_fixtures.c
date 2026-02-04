/*
 * Unit Test Fixtures Implementation
 * Isolated testing with DAP SDK mocking
 */

#include "unit_test_fixtures.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_file_utils.h"
#include "dap_strfuncs.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define LOG_TAG "unit_test_fixtures"

// ============================================================================
// NOTE: DAP SDK MOCKS
// ============================================================================
// DAP_MOCK_DECLARE перенесены в unit_test_fixtures.h
// Это гарантирует правильный порядок инициализации:
//   1. Test вызывает dap_mock_init()
//   2. Test включает unit_test_fixtures.h (с DAP_MOCK_DECLARE)
//   3. Моки регистрируются ПОСЛЕ инициализации системы
// ============================================================================

// ============================================================================
// UNIT TEST CONTEXT MANAGEMENT
// ============================================================================

/**
 * @brief Initialize unit test context with isolated environment
 */
unit_test_context_t *unit_test_fixture_init(const char *a_test_name) {
    dap_return_val_if_fail(a_test_name, NULL);

    unit_test_context_t *l_ctx = DAP_NEW_Z(unit_test_context_t);
    if (!l_ctx) {
        log_it(L_ERROR, "Failed to allocate unit test context");
        return NULL;
    }

    // Create temporary test directory
    l_ctx->test_dir = dap_strdup_printf("/tmp/cellframe_test_%s_%d",
                                         a_test_name, (int)getpid());
    if (mkdir(l_ctx->test_dir, 0755) != 0 && errno != EEXIST) {
        log_it(L_ERROR, "Failed to create test directory: %s", l_ctx->test_dir);
        DAP_DELETE(l_ctx->test_dir);
        DAP_DELETE(l_ctx);
        return NULL;
    }

    // Create config path
    l_ctx->config_path = dap_strdup_printf("%s/test.cfg", l_ctx->test_dir);

    log_it(L_INFO, "Initialized unit test context: %s", l_ctx->test_dir);
    return l_ctx;
}

/**
 * @brief Cleanup unit test context
 */
void unit_test_fixture_cleanup(unit_test_context_t *a_ctx) {
    if (!a_ctx) return;

    // Close config
    if (a_ctx->config) {
        dap_config_close(a_ctx->config);
    }

    // Remove temporary directory
    if (a_ctx->test_dir) {
        char *l_cmd = dap_strdup_printf("rm -rf %s", a_ctx->test_dir);
        system(l_cmd);
        DAP_DELETE(l_cmd);
        DAP_DELETE(a_ctx->test_dir);
    }

    DAP_DELETE(a_ctx->config_path);
    DAP_DELETE(a_ctx);

    log_it(L_INFO, "Cleaned up unit test context");
}

/**
 * @brief Generate minimal test configuration
 */
int unit_test_config_generate(unit_test_context_t *a_ctx,
                               const char *a_section,
                               const char **a_params) {
    dap_return_val_if_fail(a_ctx && a_section, -1);

    FILE *l_cfg_file = fopen(a_ctx->config_path, "a");
    if (!l_cfg_file) {
        log_it(L_ERROR, "Failed to open config file: %s", a_ctx->config_path);
        return -2;
    }

    fprintf(l_cfg_file, "[%s]\n", a_section);

    if (a_params) {
        for (const char **p = a_params; *p; p++) {
            fprintf(l_cfg_file, "%s\n", *p);
        }
    }

    fprintf(l_cfg_file, "\n");
    fclose(l_cfg_file);

    // Reload config
    if (a_ctx->config) {
        dap_config_close(a_ctx->config);
    }

    a_ctx->config = dap_config_open(a_ctx->config_path);
    if (!a_ctx->config) {
        log_it(L_ERROR, "Failed to load generated config");
        return -3;
    }

    log_it(L_INFO, "Generated config section [%s]", a_section);
    return 0;
}

/**
 * @brief Setup DAP SDK mocks with fine-grained control
 */
int unit_test_mock_dap_sdk_ex(unit_test_context_t *a_ctx,
                               const dap_sdk_mock_flags_t *a_mock_flags) {
    dap_return_val_if_fail(a_ctx && a_mock_flags, -1);

    // Copy flags to context
    memcpy(&a_ctx->mock_flags, a_mock_flags, sizeof(dap_sdk_mock_flags_t));

    // Update legacy flags for backward compatibility
    a_ctx->crypto_mocked = a_mock_flags->mock_crypto;
    a_ctx->db_mocked = a_mock_flags->mock_global_db;
    a_ctx->events_mocked = a_mock_flags->mock_events;
    a_ctx->network_mocked = a_mock_flags->mock_net_client || a_mock_flags->mock_net_server;

    // Log enabled mocks
    log_it(L_INFO, "DAP SDK module mocks enabled:");

    // ========================================================================
    // CRYPTO MODULE MOCKS
    // ========================================================================
    if (a_mock_flags->mock_crypto) {
        log_it(L_INFO, "  ✓ crypto (sign, verify, encrypt, hash)");
        DAP_MOCK_ENABLE(dap_enc_key_new);
        DAP_MOCK_ENABLE(dap_enc_key_delete);
        DAP_MOCK_ENABLE(dap_enc_key_new_generate);
        DAP_MOCK_ENABLE(dap_enc_key_serialize_priv_key);
        DAP_MOCK_ENABLE(dap_enc_key_serialize_pub_key);
        DAP_MOCK_ENABLE(dap_enc_key_deserialize_priv_key);
        DAP_MOCK_ENABLE(dap_enc_key_deserialize_pub_key);
        DAP_MOCK_ENABLE(dap_enc_key_get_pub_key_hash);
        DAP_MOCK_ENABLE(dap_sign_create);
        DAP_MOCK_ENABLE(dap_sign_verify);
        DAP_MOCK_ENABLE(dap_sign_get_size);
        DAP_MOCK_ENABLE(dap_sign_get_pkey_hash);
        DAP_MOCK_ENABLE(dap_hash_sha3_256);
        DAP_MOCK_ENABLE(dap_hash_slow);
    } else {
        DAP_MOCK_DISABLE(dap_enc_key_new);
        DAP_MOCK_DISABLE(dap_enc_key_delete);
        DAP_MOCK_DISABLE(dap_enc_key_new_generate);
        DAP_MOCK_DISABLE(dap_enc_key_serialize_priv_key);
        DAP_MOCK_DISABLE(dap_enc_key_serialize_pub_key);
        DAP_MOCK_DISABLE(dap_enc_key_deserialize_priv_key);
        DAP_MOCK_DISABLE(dap_enc_key_deserialize_pub_key);
        DAP_MOCK_DISABLE(dap_enc_key_get_pub_key_hash);
        DAP_MOCK_DISABLE(dap_sign_create);
        DAP_MOCK_DISABLE(dap_sign_verify);
        DAP_MOCK_DISABLE(dap_sign_get_size);
        DAP_MOCK_DISABLE(dap_sign_get_pkey_hash);
        DAP_MOCK_DISABLE(dap_hash_sha3_256);
        DAP_MOCK_DISABLE(dap_hash_slow);
    }

    // ========================================================================
    // GLOBAL DB MOCKS
    // ========================================================================
    if (a_mock_flags->mock_global_db) {
        log_it(L_INFO, "  ✓ global_db (key-value storage)");
        DAP_MOCK_ENABLE(dap_global_db_get);
        DAP_MOCK_ENABLE(dap_global_db_set);
        DAP_MOCK_ENABLE(dap_global_db_set_sync);
        DAP_MOCK_ENABLE(dap_global_db_del);
        DAP_MOCK_ENABLE(dap_global_db_driver_add);
        DAP_MOCK_ENABLE(dap_global_db_driver_delete);
    } else {
        DAP_MOCK_DISABLE(dap_global_db_get);
        DAP_MOCK_DISABLE(dap_global_db_set);
        DAP_MOCK_DISABLE(dap_global_db_set_sync);
        DAP_MOCK_DISABLE(dap_global_db_del);
        DAP_MOCK_DISABLE(dap_global_db_driver_add);
        DAP_MOCK_DISABLE(dap_global_db_driver_delete);
    }

    // ========================================================================
    // TIME MOCKS
    // ========================================================================
    if (a_mock_flags->mock_time) {
        log_it(L_INFO, "  ✓ time (time functions)");
        DAP_MOCK_ENABLE(dap_time_now);
        DAP_MOCK_ENABLE(dap_nanotime_now);
    } else {
        DAP_MOCK_DISABLE(dap_time_now);
        DAP_MOCK_DISABLE(dap_nanotime_now);
    }

    // ========================================================================
    // JSON MOCKS
    // ========================================================================
    if (a_mock_flags->mock_json) {
        log_it(L_INFO, "  ✓ json (JSON parser)");
        DAP_MOCK_ENABLE(dap_json_object_new_object);
        DAP_MOCK_ENABLE(dap_json_object_add);
        DAP_MOCK_ENABLE(dap_json_object_get);
        DAP_MOCK_ENABLE(dap_json_object_to_json_string);
    } else {
        DAP_MOCK_DISABLE(dap_json_object_new_object);
        DAP_MOCK_DISABLE(dap_json_object_add);
        DAP_MOCK_DISABLE(dap_json_object_get);
        DAP_MOCK_DISABLE(dap_json_object_to_json_string);
    }

    // ========================================================================
    // FILE UTILS MOCKS
    // ========================================================================
    if (a_mock_flags->mock_file_utils) {
        log_it(L_INFO, "  ✓ file_utils (file operations)");
        DAP_MOCK_ENABLE(dap_file_test);
        DAP_MOCK_ENABLE(dap_file_get_contents);
        DAP_MOCK_ENABLE(dap_file_set_contents);
        DAP_MOCK_ENABLE(dap_mkdir_with_parents);
    } else {
        DAP_MOCK_DISABLE(dap_file_test);
        DAP_MOCK_DISABLE(dap_file_get_contents);
        DAP_MOCK_DISABLE(dap_file_set_contents);
        DAP_MOCK_DISABLE(dap_mkdir_with_parents);
    }

    // ========================================================================
    // EVENTS MOCKS
    // ========================================================================
    if (a_mock_flags->mock_events) {
        log_it(L_INFO, "  ✓ events (event system)");
        DAP_MOCK_ENABLE(dap_events_start);
        DAP_MOCK_ENABLE(dap_events_wait);
        DAP_MOCK_ENABLE(dap_events_stop);
        DAP_MOCK_ENABLE(dap_events_socket_create_type_unix_client);
    } else {
        DAP_MOCK_DISABLE(dap_events_start);
        DAP_MOCK_DISABLE(dap_events_wait);
        DAP_MOCK_DISABLE(dap_events_stop);
        DAP_MOCK_DISABLE(dap_events_socket_create_type_unix_client);
    }

    // ========================================================================
    // NETWORK CLIENT MOCKS
    // ========================================================================
    if (a_mock_flags->mock_net_client) {
        log_it(L_INFO, "  ✓ net_client (network client)");
        DAP_MOCK_ENABLE(dap_client_new);
        DAP_MOCK_ENABLE(dap_client_delete);
        DAP_MOCK_ENABLE(dap_client_connect);
        DAP_MOCK_ENABLE(dap_client_disconnect);
    } else {
        DAP_MOCK_DISABLE(dap_client_new);
        DAP_MOCK_DISABLE(dap_client_delete);
        DAP_MOCK_DISABLE(dap_client_connect);
        DAP_MOCK_DISABLE(dap_client_disconnect);
    }

    // ========================================================================
    // NETWORK SERVER MOCKS
    // ========================================================================
    if (a_mock_flags->mock_net_server) {
        log_it(L_INFO, "  ✓ net_server (network server)");
        DAP_MOCK_ENABLE(dap_server_new);
        DAP_MOCK_ENABLE(dap_server_delete);
        DAP_MOCK_ENABLE(dap_server_listen);
    } else {
        DAP_MOCK_DISABLE(dap_server_new);
        DAP_MOCK_DISABLE(dap_server_delete);
        DAP_MOCK_DISABLE(dap_server_listen);
    }

    // ========================================================================
    // STREAM MOCKS
    // ========================================================================
    if (a_mock_flags->mock_stream) {
        log_it(L_INFO, "  ✓ stream (data streams)");
        DAP_MOCK_ENABLE(dap_stream_new);
        DAP_MOCK_ENABLE(dap_stream_delete);
        DAP_MOCK_ENABLE(dap_stream_write);
        DAP_MOCK_ENABLE(dap_stream_read);
    } else {
        DAP_MOCK_DISABLE(dap_stream_new);
        DAP_MOCK_DISABLE(dap_stream_delete);
        DAP_MOCK_DISABLE(dap_stream_write);
        DAP_MOCK_DISABLE(dap_stream_read);
    }

    // ========================================================================
    // PROC THREAD MOCKS
    // ========================================================================
    if (a_mock_flags->mock_proc_thread) {
        log_it(L_INFO, "  ✓ proc_thread (process/thread mgmt)");
        DAP_MOCK_ENABLE(dap_proc_thread_create);
        DAP_MOCK_ENABLE(dap_proc_thread_delete);
        DAP_MOCK_ENABLE(dap_proc_thread_assign_on_worker_inter);
    } else {
        DAP_MOCK_DISABLE(dap_proc_thread_create);
        DAP_MOCK_DISABLE(dap_proc_thread_delete);
        DAP_MOCK_DISABLE(dap_proc_thread_assign_on_worker_inter);
    }

    // ========================================================================
    // WORKER MOCKS
    // ========================================================================
    if (a_mock_flags->mock_worker) {
        log_it(L_INFO, "  ✓ worker (worker threads)");
        DAP_MOCK_ENABLE(dap_worker_add_events_socket);
        DAP_MOCK_ENABLE(dap_worker_exec_callback_on);
        DAP_MOCK_ENABLE(dap_worker_exec_callback_inter);
    } else {
        DAP_MOCK_DISABLE(dap_worker_add_events_socket);
        DAP_MOCK_DISABLE(dap_worker_exec_callback_on);
        DAP_MOCK_DISABLE(dap_worker_exec_callback_inter);
    }

    // ========================================================================
    // RING BUFFER MOCKS
    // ========================================================================
    if (a_mock_flags->mock_ring_buffer) {
        log_it(L_INFO, "  ✓ ring_buffer (ring buffer)");
        DAP_MOCK_ENABLE(dap_ring_buffer_create);
        DAP_MOCK_ENABLE(dap_ring_buffer_delete);
        DAP_MOCK_ENABLE(dap_ring_buffer_write);
        DAP_MOCK_ENABLE(dap_ring_buffer_read);
    } else {
        DAP_MOCK_DISABLE(dap_ring_buffer_create);
        DAP_MOCK_DISABLE(dap_ring_buffer_delete);
        DAP_MOCK_DISABLE(dap_ring_buffer_write);
        DAP_MOCK_DISABLE(dap_ring_buffer_read);
    }

    log_it(L_INFO, "✅ DAP SDK mocks configured via dap_mock framework");

    return 0;
}

/**
 * @brief Setup DAP SDK mocks (legacy API)
 */
int unit_test_mock_dap_sdk(unit_test_context_t *a_ctx,
                            bool a_mock_crypto,
                            bool a_mock_db,
                            bool a_mock_events) {
    dap_return_val_if_fail(a_ctx, -1);

    // Convert to new API
    dap_sdk_mock_flags_t l_flags = {
        .mock_crypto = a_mock_crypto,
        .mock_global_db = a_mock_db,
        .mock_events = a_mock_events,
        .mock_proc_thread = false,
        .mock_worker = false,
        .mock_net_client = false,
        .mock_net_server = false,
        .mock_stream = false,
        .mock_json = false,
        .mock_time = false,
        .mock_timerfd = false,
        .mock_file_utils = false,
        .mock_ring_buffer = false
    };

    return unit_test_mock_dap_sdk_ex(a_ctx, &l_flags);
}

/**
 * @brief Enable/disable specific DAP SDK module mock at runtime
 */
int unit_test_mock_toggle(unit_test_context_t *a_ctx,
                           const char *a_module_name,
                           bool a_enable) {
    dap_return_val_if_fail(a_ctx && a_module_name, -1);

    bool *l_flag = NULL;

    // Find the corresponding flag
    if (strcmp(a_module_name, "crypto") == 0) {
        l_flag = &a_ctx->mock_flags.mock_crypto;
        a_ctx->crypto_mocked = a_enable;
    } else if (strcmp(a_module_name, "global_db") == 0) {
        l_flag = &a_ctx->mock_flags.mock_global_db;
        a_ctx->db_mocked = a_enable;
    } else if (strcmp(a_module_name, "events") == 0) {
        l_flag = &a_ctx->mock_flags.mock_events;
        a_ctx->events_mocked = a_enable;
    } else if (strcmp(a_module_name, "proc_thread") == 0) {
        l_flag = &a_ctx->mock_flags.mock_proc_thread;
    } else if (strcmp(a_module_name, "worker") == 0) {
        l_flag = &a_ctx->mock_flags.mock_worker;
    } else if (strcmp(a_module_name, "net_client") == 0) {
        l_flag = &a_ctx->mock_flags.mock_net_client;
    } else if (strcmp(a_module_name, "net_server") == 0) {
        l_flag = &a_ctx->mock_flags.mock_net_server;
    } else if (strcmp(a_module_name, "stream") == 0) {
        l_flag = &a_ctx->mock_flags.mock_stream;
    } else if (strcmp(a_module_name, "json") == 0) {
        l_flag = &a_ctx->mock_flags.mock_json;
    } else if (strcmp(a_module_name, "time") == 0) {
        l_flag = &a_ctx->mock_flags.mock_time;
    } else if (strcmp(a_module_name, "timerfd") == 0) {
        l_flag = &a_ctx->mock_flags.mock_timerfd;
    } else if (strcmp(a_module_name, "file_utils") == 0) {
        l_flag = &a_ctx->mock_flags.mock_file_utils;
    } else if (strcmp(a_module_name, "ring_buffer") == 0) {
        l_flag = &a_ctx->mock_flags.mock_ring_buffer;
    } else {
        log_it(L_ERROR, "Unknown DAP SDK module: %s", a_module_name);
        return -2;
    }

    if (l_flag) {
        bool l_old_value = *l_flag;
        *l_flag = a_enable;
        log_it(L_INFO, "Mock '%s': %s → %s",
               a_module_name,
               l_old_value ? "ON" : "OFF",
               a_enable ? "ON" : "OFF");
    }

    return 0;
}

// ============================================================================
// TEST DATA GENERATORS
// ============================================================================

/**
 * @brief Generate deterministic hash for testing
 */
void unit_test_hash_generate(uint32_t a_seed, dap_hash_sha3_256_t *a_hash) {
    dap_return_if_fail(a_hash);

    memset(a_hash, 0, sizeof(dap_hash_sha3_256_t));
    for (size_t i = 0; i < sizeof(dap_hash_sha3_256_t); i++) {
        a_hash->raw[i] = (uint8_t)((a_seed + i * 17) % 256);
    }
}

/**
 * @brief Generate deterministic address for testing
 */
void unit_test_addr_generate(uint32_t a_seed, uint64_t a_net_id, dap_chain_addr_t *a_addr) {
    dap_return_if_fail(a_addr);

    memset(a_addr, 0, sizeof(dap_chain_addr_t));
    a_addr->net_id.uint64 = a_net_id;

    // Generate deterministic hash part
    for (size_t i = 0; i < sizeof(a_addr->data.hash); i++) {
        a_addr->data.hash[i] = (uint8_t)((a_seed * 7 + i * 11) % 256);
    }
}

/**
 * @brief Generate mocked signature
 */
dap_sign_t *unit_test_sign_generate(uint32_t a_seed, const void *a_data, size_t a_data_size) {
    UNUSED(a_data);
    UNUSED(a_data_size);

    // Create minimal signature for testing
    size_t l_sign_size = sizeof(dap_sign_t) + 64; // Mock signature data
    dap_sign_t *l_sign = DAP_NEW_Z_SIZE(dap_sign_t, l_sign_size);
    if (!l_sign) {
        return NULL;
    }

    // Set mock signature type
    l_sign->header.type.type = SIG_TYPE_NULL;
    l_sign->header.sign_size = 64;

    // Fill with deterministic data
    uint8_t *l_sign_data = (uint8_t*)(l_sign + 1);
    for (size_t i = 0; i < 64; i++) {
        l_sign_data[i] = (uint8_t)((a_seed + i * 13) % 256);
    }

    return l_sign;
}

/**
 * @brief Generate uint256 from uint64
 */
void unit_test_uint256_generate(uint64_t a_value, uint256_t *a_out) {
    dap_return_if_fail(a_out);

    memset(a_out, 0, sizeof(uint256_t));
    *((uint64_t*)a_out) = a_value;
}
