/**
 * @file test_ledger_fixtures.c
 * @brief Implementation of ledger test fixtures
 */

#include "test_ledger_fixtures.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_chain.h"
#include "dap_chain_cs.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_node.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum.h"
#include "dap_chain_arbitrage.h"
#include "dap_global_db.h"
#include "dap_global_db_driver.h"
#include "dap_global_db_cluster.h"
#include "dap_cert.h"
#include "dap_stream.h"
#include "dap_file_utils.h"
#include "dap_proc_thread.h"
#include "dap_events.h"
#include "dap_common.h"
#include <json-c/json.h>

#define LOG_TAG "test_ledger_fixtures"

// Global state for test environment initialization
static bool s_test_env_initialized = false;
static bool s_global_db_initialized = false;
static bool s_cert_system_initialized = false;
static bool s_common_initialized = false; // Track common/events/proc_threads initialization

test_net_fixture_t *test_net_fixture_create(const char *a_net_name)
{
    if (!a_net_name) {
        log_it(L_ERROR, "Network name is NULL");
        return NULL;
    }

    test_net_fixture_t *l_fixture = DAP_NEW_Z(test_net_fixture_t);
    if (!l_fixture) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }

    l_fixture->net_name = dap_strdup(a_net_name);
    
    // Initialize test network infrastructure
    dap_chain_net_test_init();
    
    // Get or create test network with ID 0xFA0
    dap_chain_net_id_t l_net_id = {.uint64 = 0x0FA0};
    l_fixture->net = dap_chain_net_by_id(l_net_id);
    
    if (!l_fixture->net) {
        log_it(L_ERROR, "Failed to get test network");
        DAP_DELETE(l_fixture->net_name);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Create ledger with token emission checking
    uint16_t l_flags = DAP_LEDGER_CHECK_TOKEN_EMISSION | DAP_LEDGER_CHECK_LOCAL_DS;
    l_fixture->ledger = dap_ledger_create(l_fixture->net, l_flags);
    if (!l_fixture->ledger) {
        log_it(L_ERROR, "Failed to create ledger");
        DAP_DELETE(l_fixture->net_name);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Link ledger to network
    l_fixture->net->pub.ledger = l_fixture->ledger;
    
    // Create zero chain (like in production networks)
    char l_zero_chain_name[128];
    snprintf(l_zero_chain_name, sizeof(l_zero_chain_name), "%s_zero", a_net_name);
    l_fixture->chain_zero = dap_chain_create(
        l_fixture->net->pub.name,
        l_zero_chain_name,
        l_fixture->net->pub.id,
        (dap_chain_id_t){.uint64 = 0}
    );
    
    if (!l_fixture->chain_zero) {
        log_it(L_ERROR, "Failed to create zero chain");
        dap_ledger_handle_free(l_fixture->ledger);
        DAP_DELETE(l_fixture->net_name);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Create consensus for zero chain (DAG PoA auto-selected by DAP_LEDGER_TEST for chain_id=0)
    if (dap_chain_cs_create(l_fixture->chain_zero, NULL) != 0) {
        log_it(L_ERROR, "Failed to create consensus for zero chain");
        dap_chain_delete(l_fixture->chain_zero);
        dap_ledger_handle_free(l_fixture->ledger);
        DAP_DELETE(l_fixture->net_name);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Add zero chain to network
    DL_APPEND(l_fixture->net->pub.chains, l_fixture->chain_zero);
    
    // Create master/main chain (like in production networks)
    char l_main_chain_name[128];
    snprintf(l_main_chain_name, sizeof(l_main_chain_name), "%s_master", a_net_name);
    l_fixture->chain_main = dap_chain_create(
        l_fixture->net->pub.name,
        l_main_chain_name,
        l_fixture->net->pub.id,
        (dap_chain_id_t){.uint64 = 1}
    );
    
    if (!l_fixture->chain_main) {
        log_it(L_ERROR, "Failed to create master chain");
        // Cleanup zero chain
        DL_DELETE(l_fixture->net->pub.chains, l_fixture->chain_zero);
        dap_chain_delete(l_fixture->chain_zero);
        dap_ledger_handle_free(l_fixture->ledger);
        DAP_DELETE(l_fixture->net_name);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    
    // Create datum_types BEFORE consensus creation (like dap_chain_load_from_cfg does)
    // Use static storage to avoid memory management issues - this array will live for the lifetime of the chain
    // and will be cleared (but not freed) by dap_chain_delete
    // Include token, emission, and transaction types for tests
    static dap_chain_type_t s_chain_main_datum_types[3] = {CHAIN_TYPE_TOKEN, CHAIN_TYPE_EMISSION, CHAIN_TYPE_TX};
    if (!l_fixture->chain_main->datum_types) {
        l_fixture->chain_main->datum_types = s_chain_main_datum_types;
        l_fixture->chain_main->datum_types_count = 3;
        l_fixture->chain_main_datum_types = NULL; // Static array, no need to track for cleanup
        log_it(L_DEBUG, "Set datum_types array for chain_main with token, emission, and transaction types (before consensus, static storage)");
    } else {
        l_fixture->chain_main_datum_types = NULL; // Array already exists, not ours
    }
    
    // Set autoproc_datum_types to enable automatic mempool processing
    // This is normally set from config file "mempool_auto_types", but we set it manually for tests
    // Include token, emission, and transaction types for automatic processing
    static uint16_t s_chain_main_autoproc_datum_types[3] = {
        DAP_CHAIN_DATUM_TOKEN, DAP_CHAIN_DATUM_TOKEN_EMISSION, DAP_CHAIN_DATUM_TX
    };
    if (!l_fixture->chain_main->autoproc_datum_types) {
        l_fixture->chain_main->autoproc_datum_types = s_chain_main_autoproc_datum_types;
        l_fixture->chain_main->autoproc_datum_types_count = 3;
        log_it(L_DEBUG, "Set autoproc_datum_types for chain_main to enable automatic mempool processing");
    }
    
    // Create 'none' consensus for master chain
    // Use 'none' consensus for tests - datums are added directly to ledger without block accumulation
    // This allows immediate emission processing without waiting for block publication
    log_it(L_NOTICE, "Creating 'none' consensus for test chain (datums processed immediately)");
    
    // Create temporary config with consensus="none"
    // This will override DAP_LEDGER_TEST logic that defaults to "esbocs"
    char l_temp_cfg_path[256];
    snprintf(l_temp_cfg_path, sizeof(l_temp_cfg_path), "/tmp/test_none_consensus_%s.cfg", a_net_name);
    FILE *l_temp_cfg_file = fopen(l_temp_cfg_path, "w");
    if (l_temp_cfg_file) {
        fprintf(l_temp_cfg_file, "[chain]\nconsensus=none\n");
        fclose(l_temp_cfg_file);
    }
    
    dap_config_t *l_temp_cfg = dap_config_open(l_temp_cfg_path);
    int l_none_create_res = dap_chain_cs_create(l_fixture->chain_main, l_temp_cfg);
    
    if (l_temp_cfg) {
        dap_config_close(l_temp_cfg);
    }
    unlink(l_temp_cfg_path);
    if (l_none_create_res != 0) {
        log_it(L_ERROR, "Failed to create 'none' consensus for master chain (result: %d)", l_none_create_res);
        // Clear datum_types pointer (it points to static storage, shouldn't be freed)
        l_fixture->chain_main->datum_types = NULL;
        l_fixture->chain_main->datum_types_count = 0;
        dap_chain_delete(l_fixture->chain_main);
        DL_DELETE(l_fixture->net->pub.chains, l_fixture->chain_zero);
        dap_chain_delete(l_fixture->chain_zero);
        dap_ledger_handle_free(l_fixture->ledger);
        DAP_DELETE(l_fixture->net_name);
        DAP_DELETE(l_fixture);
        return NULL;
    }
    log_it(L_INFO, "'none' consensus created successfully, callback_add_datums: %p", (void*)l_fixture->chain_main->callback_add_datums);
    
    // Add master chain to network
    DL_APPEND(l_fixture->net->pub.chains, l_fixture->chain_main);
    
    // Create global DB clusters for mempool groups (needed for datum pool operations)
    // This is normally done in dap_chain_net_init(), but we create network manually in tests
    if (dap_global_db_instance_get_default()) {
        // Set gdb_groups_prefix if not set (it's a const char* pointer, so we set it to point to name)
        if (!l_fixture->net->pub.gdb_groups_prefix) {
            l_fixture->net->pub.gdb_groups_prefix = l_fixture->net->pub.name;
        }
        
        // Create mempool cluster for each chain
        // Note: This must be done AFTER g_node_addr is initialized (which happens in test_env_init)
        dap_chain_t *l_chain = NULL;
        DL_FOREACH(l_fixture->net->pub.chains, l_chain) {
            char *l_gdb_groups_mask = dap_strdup_printf("%s.chain-%s.mempool", 
                                                         l_fixture->net->pub.gdb_groups_prefix, l_chain->name);
            // Use 0 for TTL to avoid division issues - let it use default from store_time_limit
            dap_global_db_cluster_t *l_cluster = dap_global_db_cluster_add(
                dap_global_db_instance_get_default(), 
                l_fixture->net->pub.name,
                dap_guuid_compose(l_fixture->net->pub.id.uint64, 0), 
                l_gdb_groups_mask,
                0,     // 0 TTL - will use store_time_limit from dbi if set, or unlimited
                true,  // owner_root_access
                DAP_GDB_MEMBER_ROLE_USER, 
                DAP_CLUSTER_TYPE_EMBEDDED);
            if (!l_cluster) {
                log_it(L_WARNING, "Failed to create mempool cluster for chain %s - mempool operations may fail", l_chain->name);
            } else {
                log_it(L_DEBUG, "Created mempool cluster for chain %s with group mask %s", l_chain->name, l_gdb_groups_mask);
            }
            DAP_DELETE(l_gdb_groups_mask);
        }
    }
    
    log_it(L_INFO, "Test network fixture created: %s (net_id=0x%016"DAP_UINT64_FORMAT_X") with zero and master chains", 
           a_net_name, l_fixture->net->pub.id.uint64);
    return l_fixture;
}

void test_net_fixture_destroy(test_net_fixture_t *a_fixture)
{
    if (!a_fixture)
        return;

    // Remove chains from network and delete them
    if (a_fixture->chain_main) {
        DL_DELETE(a_fixture->net->pub.chains, a_fixture->chain_main);
        // Clear datum_types and autoproc_datum_types pointers before deletion
        // They point to static storage, and dap_chain_delete will try to free them via DAP_DEL_MULTY
        // but static storage shouldn't be freed
        a_fixture->chain_main->datum_types = NULL;
        a_fixture->chain_main->datum_types_count = 0;
        a_fixture->chain_main->autoproc_datum_types = NULL;
        a_fixture->chain_main->autoproc_datum_types_count = 0;
        dap_chain_delete(a_fixture->chain_main);
        a_fixture->chain_main = NULL;
        a_fixture->chain_main_datum_types = NULL; // Clear reference
    }
    
    if (a_fixture->chain_zero) {
        DL_DELETE(a_fixture->net->pub.chains, a_fixture->chain_zero);
        dap_chain_delete(a_fixture->chain_zero);
        a_fixture->chain_zero = NULL;
    }
    
    // Cleanup ledger
    if (a_fixture->ledger) {
        dap_ledger_handle_free(a_fixture->ledger);
        a_fixture->ledger = NULL;
    }
    
    // Note: Network cleanup is handled by global network infrastructure
    // Don't delete the network directly as it may be shared
    
    DAP_DELETE(a_fixture->net_name);
    DAP_DELETE(a_fixture);
    
    log_it(L_INFO, "Test network fixture destroyed");
}

/**
 * @brief Helper function to get token emission hash (wrapper around public API)
 * @details This is a convenience wrapper for test fixtures
 */
bool test_ledger_get_token_emission_hash(dap_ledger_t *a_ledger, 
                                          const char *a_token_ticker,
                                          dap_chain_hash_fast_t *a_emission_hash)
{
    // Use new public API function
    return dap_ledger_token_get_first_emission_hash(a_ledger, a_token_ticker, a_emission_hash);
}

bool test_json_rpc_parse_error(json_object *a_json_response, test_json_rpc_error_t *a_error)
{
    if (!a_json_response || !a_error) {
        return false;
    }
    
    // Initialize output structure
    a_error->has_error = false;
    a_error->error_code = 0;
    a_error->error_msg = NULL;
    
    // Check for errors in result[].errors[] format (new JSON-RPC error format)
    json_object *l_result_array = NULL;
    if (json_object_object_get_ex(a_json_response, "result", &l_result_array) && 
        json_object_get_type(l_result_array) == json_type_array) {
        int l_array_len = json_object_array_length(l_result_array);
        for (int i = 0; i < l_array_len && !a_error->has_error; i++) {
            json_object *l_result_item = json_object_array_get_idx(l_result_array, i);
            if (l_result_item && json_object_get_type(l_result_item) == json_type_object) {
                json_object *l_errors_array = NULL;
                if (json_object_object_get_ex(l_result_item, "errors", &l_errors_array) &&
                    json_object_get_type(l_errors_array) == json_type_array) {
                    int l_errors_len = json_object_array_length(l_errors_array);
                    if (l_errors_len > 0) {
                        json_object *l_error_obj = json_object_array_get_idx(l_errors_array, 0);
                        if (l_error_obj) {
                            json_object *l_code = NULL, *l_message = NULL;
                            if (json_object_object_get_ex(l_error_obj, "code", &l_code) &&
                                json_object_object_get_ex(l_error_obj, "message", &l_message)) {
                                int l_error_code = json_object_get_int(l_code);
                                // Code 0 means success (informational message), not an error
                                if (l_error_code != 0) {
                                    a_error->has_error = true;
                                    a_error->error_code = l_error_code;
                                    a_error->error_msg = json_object_get_string(l_message);
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Also check for top-level error field (legacy format)
    json_object *l_error_top = NULL;
    if (json_object_object_get_ex(a_json_response, "error", &l_error_top)) {
        json_object *l_code = NULL, *l_message = NULL;
        if (json_object_object_get_ex(l_error_top, "code", &l_code) &&
            json_object_object_get_ex(l_error_top, "message", &l_message)) {
            int l_error_code = json_object_get_int(l_code);
            // Code 0 means success (informational message), not an error
            if (l_error_code != 0) {
                a_error->has_error = true;
                a_error->error_code = l_error_code;
                a_error->error_msg = json_object_get_string(l_message);
                return true;
            }
        }
    }
    
    return false;
}

/**
 * @brief Initialize test environment (config, certs, global DB)
 * @param a_config_dir Directory for test config files (can be NULL for default)
 * @param a_global_db_path Path for global DB storage (can be NULL for default)
 * @return 0 on success, negative on error
 * @note This function is idempotent - can be called multiple times safely
 */
int test_env_init(const char *a_config_dir, const char *a_global_db_path)
{
    if (s_test_env_initialized) {
        log_it(L_DEBUG, "Test environment already initialized, skipping");
        return 0;
    }
    
    // Initialize logging output to stderr for fixtures (tests redirect stdout)
    // Note: Tests already set LOGGER_OUTPUT_STDERR in main(), but we ensure it's set here too
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    
    log_it(L_NOTICE, "Initializing test environment...");
    
    // Step 0: Initialize common and events (needed for proc threads)
    // This must be done before dap_proc_thread_init
    if (!s_common_initialized) {
        // Initialize common (if not already done)
        if (dap_common_init("test", NULL) != 0) {
            log_it(L_WARNING, "dap_common_init failed - some features may not work");
        }
        // Initialize events (needed for proc threads)
        // Use reasonable defaults: 2 threads (for tests), 60 second timeout
        if (dap_events_init(2, 60) != 0) {
            log_it(L_WARNING, "dap_events_init failed - proc threads may fail");
        } else {
            log_it(L_DEBUG, "Events initialized");
            // Start events (required for proc threads to work)
            dap_events_start();
            log_it(L_DEBUG, "Events started");
        }
        s_common_initialized = true;
    }
    
    // Step 0.5: Initialize proc threads (needed for cluster timers)
    // This must be done before any dap_proc_thread_timer_add calls
    if (dap_proc_thread_get_count() == 0) {
        int l_proc_thread_res = dap_proc_thread_init(0); // 0 = autodetect
        if (l_proc_thread_res != 0) {
            log_it(L_WARNING, "Failed to initialize proc threads (code %d) - cluster timers may fail", l_proc_thread_res);
        } else {
            log_it(L_DEBUG, "Proc threads initialized");
        }
    }
    
    // Step 1: Initialize config if directory provided
    if (a_config_dir) {
        dap_config_init(a_config_dir);
        g_config = dap_config_open("test");
        if (!g_config) {
            log_it(L_ERROR, "Failed to open config from %s", a_config_dir);
            return -1;
        }
    } else if (!g_config) {
        // Try to initialize with default path
        dap_config_init("/tmp/test_config");
        g_config = dap_config_open("test");
        if (!g_config) {
            log_it(L_WARNING, "No config available - some features may not work");
        }
    }
    
    // Step 2: Initialize cert system and create node address certificate for global DB signing
    // Also initialize node address (needed for cluster member addition)
    if (!s_cert_system_initialized) {
        dap_cert_init();
        s_cert_system_initialized = true;
        
        // Check if certificate already exists
        dap_cert_t *l_existing_cert = dap_cert_find_by_name(DAP_STREAM_NODE_ADDR_CERT_NAME);
        dap_cert_t *l_node_cert = NULL;
        if (l_existing_cert) {
            log_it(L_DEBUG, "Node address certificate already exists, using existing one");
            l_node_cert = l_existing_cert;
        } else {
            // Create new certificate
            const char *l_cert_folder = dap_cert_get_folder(DAP_CERT_FOLDER_PATH_DEFAULT);
            if (!l_cert_folder) {
                // Try to get folder from config or use default
                if (g_config) {
                    uint16_t l_ca_folders_size = 0;
                    char **l_ca_folders = dap_config_get_item_str_path_array(g_config, "resources", "ca_folders", &l_ca_folders_size);
                    if (l_ca_folders_size > 0 && l_ca_folders[0]) {
                        // Add folder manually if not already added
                        dap_cert_add_folder(l_ca_folders[0]);
                        l_cert_folder = dap_cert_get_folder(DAP_CERT_FOLDER_PATH_DEFAULT);
                        dap_config_get_item_str_path_array_free(l_ca_folders, l_ca_folders_size);
                    }
                }
                // If still no folder, use default test path
                if (!l_cert_folder) {
                    const char *l_default_cert_folder = "/tmp/test_certs";
                    dap_mkdir_with_parents(l_default_cert_folder);
                    dap_cert_add_folder(l_default_cert_folder);
                    l_cert_folder = dap_cert_get_folder(DAP_CERT_FOLDER_PATH_DEFAULT);
                }
            }
            
            if (l_cert_folder) {
                char l_cert_path[512];
                snprintf(l_cert_path, sizeof(l_cert_path), "%s/" DAP_STREAM_NODE_ADDR_CERT_NAME ".dcert", l_cert_folder);
                l_node_cert = dap_cert_generate(DAP_STREAM_NODE_ADDR_CERT_NAME, l_cert_path, DAP_STREAM_NODE_ADDR_CERT_TYPE);
                if (!l_node_cert) {
                    log_it(L_ERROR, "Failed to generate node address certificate - global DB signing will fail");
                    return -2;
                } else {
                    log_it(L_DEBUG, "Node address certificate created for global DB signing");
                    // Verify certificate is accessible
                    l_node_cert = dap_cert_find_by_name(DAP_STREAM_NODE_ADDR_CERT_NAME);
                    if (!l_node_cert) {
                        log_it(L_ERROR, "Certificate created but not found in system - global DB signing will fail");
                        return -3;
                    }
                    // Verify certificate has encryption key
                    if (!l_node_cert->enc_key) {
                        log_it(L_ERROR, "Certificate has no encryption key - global DB signing will fail");
                        return -4;
                    }
                    log_it(L_DEBUG, "Node address certificate verified and ready for global DB signing");
                }
            } else {
                log_it(L_ERROR, "Certificate folder not available - cannot create node address certificate");
                return -5;
            }
        }
        
        // Initialize node address from certificate (needed for cluster member addition)
        // dap_global_db_cluster_init() uses g_node_addr, so we must initialize it here
        // Use the same approach as s_stream_init_node_addr_cert()
        l_node_cert = dap_cert_find_by_name(DAP_STREAM_NODE_ADDR_CERT_NAME);
        if (l_node_cert) {
            extern dap_stream_node_addr_t g_node_addr;
            g_node_addr = dap_stream_node_addr_from_cert(l_node_cert);
            log_it(L_DEBUG, "Node address initialized from certificate for cluster member addition");
        } else {
            log_it(L_WARNING, "Node address certificate not found - cluster member addition may fail");
        }
    }
    
    // Step 3: Initialize global DB (needed for mempool/datum pool)
    if (!s_global_db_initialized && g_config) {
        // Ensure global_db section exists in config with path and driver
        // Config should have [global_db] section with driver and path options
        // If driver is not specified in config, dap_global_db_init() will use default "mdbx"
        
        // Get path from config or use parameter
        const char *l_gdb_path = dap_config_get_item_path(g_config, "global_db", "path");
        const char *l_final_path = l_gdb_path ? l_gdb_path : a_global_db_path;
        
        if (l_final_path) {
            // Create directory for GlobalDB if it doesn't exist
            dap_mkdir_with_parents(l_final_path);
            log_it(L_DEBUG, "Ensured GlobalDB directory exists: %s", l_final_path);
        }
        
        // Verify driver is specified (should be in config file)
        const char *l_driver_name = dap_config_get_item_str(g_config, "global_db", "driver");
        if (l_driver_name) {
            log_it(L_DEBUG, "GlobalDB driver from config: %s", l_driver_name);
        } else {
            log_it(L_DEBUG, "GlobalDB driver not specified in config, will use default 'mdbx'");
        }
        
        int l_gdb_init_res = dap_global_db_init();
        if (l_gdb_init_res != 0) {
            log_it(L_ERROR, "Global DB initialization failed (code %d)", l_gdb_init_res);
            log_it(L_ERROR, "Available GlobalDB drivers:");
#ifdef DAP_CHAIN_GDB_ENGINE_SQLITE
            log_it(L_ERROR, "  - sqlite (available)");
#else
            log_it(L_ERROR, "  - sqlite (NOT compiled)");
#endif
#ifdef DAP_CHAIN_GDB_ENGINE_MDBX
            log_it(L_ERROR, "  - mdbx (available)");
#else
            log_it(L_ERROR, "  - mdbx (NOT compiled)");
#endif
#ifdef DAP_CHAIN_GDB_ENGINE_PGSQL
            log_it(L_ERROR, "  - pgsql (available)");
#else
            log_it(L_ERROR, "  - pgsql (NOT compiled)");
#endif
            log_it(L_ERROR, "To enable a driver, rebuild with: -DBUILD_WITH_GDB_DRIVER_SQLITE=ON (or MDBX/PGSQL)");
            log_it(L_ERROR, "Mempool operations require GlobalDB - test initialization failed");
            // This is critical for mempool operations - fail initialization
            return -6;
        } else {
            s_global_db_initialized = true;
            log_it(L_INFO, "Global DB initialized successfully");
            
            // Verify instance is available
            dap_global_db_instance_t *l_dbi = dap_global_db_instance_get_default();
            if (!l_dbi) {
                log_it(L_ERROR, "GlobalDB instance not available after initialization");
                return -7;
            }
            log_it(L_DEBUG, "GlobalDB instance verified: driver=%s, path=%s", 
                   l_dbi->driver_name ? l_dbi->driver_name : "NULL",
                   l_dbi->storage_path ? l_dbi->storage_path : "NULL");
        }
    }
    
    s_test_env_initialized = true;
    log_it(L_NOTICE, "✓ Test environment initialized");
    return 0;
}

/**
 * @brief Deinitialize test environment
 * @note This function is idempotent - can be called multiple times safely
 */
void test_env_deinit(void)
{
    if (!s_test_env_initialized) {
        return;
    }
    
    log_it(L_DEBUG, "Deinitializing test environment...");
    
    // CRITICAL: Clean up events and proc threads BEFORE GlobalDB
    // GlobalDB uses proc_thread timers and callbacks, so we must stop events
    // and wait for threads to finish BEFORE cleaning up GlobalDB structures
    // This prevents use-after-free errors when proc_thread callbacks try to
    // access GlobalDB structures that have already been freed
    if (s_common_initialized) {
        // Step 1: Stop events (sends stop signal to all event threads)
        dap_events_stop_all();
        log_it(L_DEBUG, "Events stop signal sent");
        
        // Step 2: Wait for all event threads to finish
        // This ensures all proc_thread callbacks and timers have completed
        // before we clean up GlobalDB structures they might reference
        dap_events_wait();
        log_it(L_DEBUG, "All event threads finished");
        
        // Step 3: Now it's safe to clean up GlobalDB (proc_threads are stopped)
        if (s_global_db_initialized) {
            dap_global_db_deinit();
            dap_global_db_driver_deinit();
            s_global_db_initialized = false;
            log_it(L_DEBUG, "GlobalDB deinitialized");
        }
        
        // Step 4: Deinit events (this also deinits proc threads internally)
        dap_events_deinit();
        log_it(L_DEBUG, "Events deinitialized");
        
        // Step 5: Deinit common
        dap_common_deinit();
        s_common_initialized = false;
        log_it(L_DEBUG, "Common deinitialized");
    } else {
        // If events weren't initialized, just clean up GlobalDB
        if (s_global_db_initialized) {
            dap_global_db_deinit();
            dap_global_db_driver_deinit();
            s_global_db_initialized = false;
            log_it(L_DEBUG, "GlobalDB deinitialized (events not initialized)");
        }
    }
    
    // Note: Cert system cleanup is handled by global infrastructure
    // We don't need to explicitly clean it up here
    
    s_test_env_initialized = false;
    log_it(L_DEBUG, "Test environment deinitialized");
}

/**
 * @brief Wait for transaction to be processed from mempool to ledger
 * @note This function always processes mempool and waits for transaction to appear in ledger
 * @note Returns transaction from ledger only (persistent pointer, no need to free)
 */
dap_chain_datum_tx_t *test_wait_tx_mempool_to_ledger(
    test_net_fixture_t *a_fixture,
    dap_chain_hash_fast_t *a_tx_hash,
    int a_max_attempts,
    int a_delay_ms,
    bool a_process_mempool)
{
    if (!a_fixture || !a_tx_hash) {
        log_it(L_ERROR, "Invalid parameters");
        return NULL;
    }
    
    // Default values
    if (a_max_attempts <= 0) {
        a_max_attempts = 5;
    }
    if (a_delay_ms <= 0) {
        a_delay_ms = 200;
    }
    
    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(a_tx_hash, l_hash_str, sizeof(l_hash_str));
    
    log_it(L_DEBUG, "Waiting for TX %s to be processed from mempool to ledger (max_attempts=%d, delay_ms=%d)",
           l_hash_str, a_max_attempts, a_delay_ms);
    
    dap_chain_datum_tx_t *l_tx = NULL;
    
    for (int l_attempt = 0; l_attempt < a_max_attempts; l_attempt++) {
        // Force mempool processing if requested
        if (a_process_mempool && a_fixture->chain_main) {
            dap_chain_node_mempool_process_all(a_fixture->chain_main, true);
        }
        
        // First try to find in ledger (if already processed)
        l_tx = dap_ledger_tx_find_by_hash(a_fixture->ledger, a_tx_hash);
        if (l_tx) {
            log_it(L_INFO, "✓ TX %s found in ledger after %d attempt(s)", l_hash_str, l_attempt + 1);
            return l_tx;
        }
        
        // Try network search (searches both ledger and mempool)
        // This might return mempool transaction, but we want ledger transaction
        l_tx = dap_chain_net_get_tx_by_hash(a_fixture->net, a_tx_hash, TX_SEARCH_TYPE_NET);
        if (l_tx) {
            // Double-check it's actually in ledger (not just mempool)
            dap_chain_datum_tx_t *l_tx_ledger = dap_ledger_tx_find_by_hash(a_fixture->ledger, a_tx_hash);
            if (l_tx_ledger) {
                log_it(L_INFO, "✓ TX %s found in ledger via network search after %d attempt(s)", 
                       l_hash_str, l_attempt + 1);
                return l_tx_ledger;
            }
            // Transaction found in mempool but not yet in ledger - continue waiting
            log_it(L_DEBUG, "TX %s found in mempool but not yet in ledger, continuing wait...", l_hash_str);
        }
        
        // Check mempool directly to see if transaction exists there
        // For TX datums, recalculate hash to handle multi-sig updates
        bool l_in_mempool = false;
        dap_chain_hash_fast_t l_actual_tx_hash = *a_tx_hash;
        
        if (a_fixture->chain_main) {
            char *l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_new(a_fixture->chain_main);
            if (l_gdb_group_mempool) {
                size_t l_datum_size = 0;
                dap_chain_datum_t *l_tx_datum_mempool = (dap_chain_datum_t *)dap_global_db_get_sync(
                    l_gdb_group_mempool, l_hash_str, &l_datum_size, NULL, NULL);
                
                // If TX found in mempool, recalculate hash (multi-sig may have changed it)
                if (l_tx_datum_mempool && l_datum_size >= sizeof(dap_chain_datum_t) && 
                    l_tx_datum_mempool->header.type_id == DAP_CHAIN_DATUM_TX) {
                    dap_chain_datum_calc_hash(l_tx_datum_mempool, &l_actual_tx_hash);
                    char l_actual_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                    dap_chain_hash_fast_to_str(&l_actual_tx_hash, l_actual_hash_str, sizeof(l_actual_hash_str));
                    
                    if (!dap_hash_fast_compare(a_tx_hash, &l_actual_tx_hash)) {
                        log_it(L_DEBUG, "TX hash updated: old=%s, new=%s (multi-sig collection)", 
                               l_hash_str, l_actual_hash_str);
                        
                        // Try finding with new hash
                        dap_chain_datum_tx_t *l_tx_new = dap_ledger_tx_find_by_hash(a_fixture->ledger, &l_actual_tx_hash);
                        if (l_tx_new) {
                            log_it(L_INFO, "✓ TX found in ledger by recalculated hash after %d attempt(s)", l_attempt + 1);
                            DAP_DELETE(l_tx_datum_mempool);
                            DAP_DELETE(l_gdb_group_mempool);
                            return l_tx_new;
                        }
                    }
                }
                
                if (l_tx_datum_mempool && l_datum_size >= sizeof(dap_chain_datum_t) && 
                    l_tx_datum_mempool->header.type_id == DAP_CHAIN_DATUM_TX) {
                    l_in_mempool = true;
                    dap_chain_datum_tx_t *l_tx_mempool = (dap_chain_datum_tx_t *)l_tx_datum_mempool->data;
                    bool l_is_arbitrage = dap_chain_arbitrage_tx_is_arbitrage(l_tx_mempool);
                    log_it(L_DEBUG, "TX %s found in mempool (attempt %d/%d), is_arbitrage=%d, waiting for processing...", 
                           l_hash_str, l_attempt + 1, a_max_attempts, l_is_arbitrage);
                    if (!l_is_arbitrage) {
                        log_it(L_WARNING, "TX %s in mempool but NOT recognized as arbitrage - TSD marker may be missing!", l_hash_str);
                    }
                }
                
                if (l_tx_datum_mempool) {
                    DAP_DELETE(l_tx_datum_mempool);
                }
                DAP_DELETE(l_gdb_group_mempool);
            }
        }
        
        // If transaction is not in mempool and not in ledger, it might not exist
        if (!l_in_mempool && !l_tx) {
            log_it(L_DEBUG, "TX %s not found in mempool or ledger (attempt %d/%d)", 
                   l_hash_str, l_attempt + 1, a_max_attempts);
        }
        
        // Wait before next attempt (except on last attempt)
        if (l_attempt < a_max_attempts - 1) {
            dap_usleep(a_delay_ms * 1000); // Convert ms to microseconds
        }
    }
    
    log_it(L_WARNING, "✗ TX %s not found in ledger after %d attempt(s)", l_hash_str, a_max_attempts);
    return NULL;
}

/**
 * @brief Wait for any datum to be processed from mempool to ledger
 * @note This function processes mempool and waits for datum to appear in ledger
 * @note Returns datum from ledger only (persistent pointer, no need to free)
 */
dap_chain_datum_t *test_wait_datum_mempool_to_ledger(
    test_net_fixture_t *a_fixture,
    dap_chain_hash_fast_t *a_datum_hash,
    int a_max_attempts,
    int a_delay_ms,
    bool a_process_mempool)
{
    if (!a_fixture || !a_datum_hash) {
        log_it(L_ERROR, "Invalid parameters");
        return NULL;
    }
    
    // Default values
    if (a_max_attempts <= 0) {
        a_max_attempts = 5;
    }
    if (a_delay_ms <= 0) {
        a_delay_ms = 200;
    }
    
    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(a_datum_hash, l_hash_str, sizeof(l_hash_str));
    
    log_it(L_DEBUG, "Waiting for datum %s to be processed from mempool to ledger (max_attempts=%d, delay_ms=%d)",
           l_hash_str, a_max_attempts, a_delay_ms);
    
    dap_chain_datum_t *l_datum = NULL;
    
    for (int l_attempt = 0; l_attempt < a_max_attempts; l_attempt++) {
        // Force mempool processing if requested
        if (a_process_mempool && a_fixture->chain_main) {
            dap_chain_node_mempool_process_all(a_fixture->chain_main, true);
        }
        
        // Try to find in ledger using chain callback (works for any datum type)
        if (a_fixture->chain_main && a_fixture->chain_main->callback_datum_find_by_hash) {
            dap_hash_fast_t l_atom_hash = {0};
            int l_ret_code = 0;
            l_datum = a_fixture->chain_main->callback_datum_find_by_hash(
                a_fixture->chain_main, a_datum_hash, &l_atom_hash, &l_ret_code);
            
            if (l_datum) {
                log_it(L_INFO, "✓ Datum %s found in ledger after %d attempt(s)", l_hash_str, l_attempt + 1);
                return l_datum;
            } else {
                log_it(L_DEBUG, "Datum %s not found via callback_datum_find_by_hash (attempt %d/%d), ret_code=%d", 
                       l_hash_str, l_attempt + 1, a_max_attempts, l_ret_code);
            }
        } else {
            log_it(L_DEBUG, "callback_datum_find_by_hash not available for chain %s", 
                   a_fixture->chain_main ? a_fixture->chain_main->name : "NULL");
        }
        
        // Check mempool directly to see if datum exists there
        bool l_in_mempool = false;
        if (a_fixture->chain_main) {
            char *l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_new(a_fixture->chain_main);
            if (l_gdb_group_mempool) {
                size_t l_datum_size = 0;
                dap_chain_datum_t *l_datum_mempool = (dap_chain_datum_t *)dap_global_db_get_sync(
                    l_gdb_group_mempool, l_hash_str, &l_datum_size, NULL, NULL);
                
                if (l_datum_mempool && l_datum_size >= sizeof(dap_chain_datum_t)) {
                    l_in_mempool = true;
                    log_it(L_DEBUG, "Datum %s found in mempool (attempt %d/%d), type_id=%u, waiting for processing...", 
                           l_hash_str, l_attempt + 1, a_max_attempts, l_datum_mempool->header.type_id);
                }
                
                if (l_datum_mempool) {
                    DAP_DELETE(l_datum_mempool);
                }
                DAP_DELETE(l_gdb_group_mempool);
            }
        }
        
        // If datum is not in mempool and not in ledger, it might not exist
        if (!l_in_mempool && !l_datum) {
            log_it(L_DEBUG, "Datum %s not found in mempool or ledger (attempt %d/%d)", 
                   l_hash_str, l_attempt + 1, a_max_attempts);
        }
        
        // Wait before next attempt (except on last attempt)
        if (l_attempt < a_max_attempts - 1) {
            dap_usleep(a_delay_ms * 1000); // Convert ms to microseconds
        }
    }
    
    log_it(L_WARNING, "✗ Datum %s not found in ledger after %d attempt(s)", l_hash_str, a_max_attempts);
    return NULL;
}
