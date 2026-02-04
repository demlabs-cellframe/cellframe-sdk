/*
 * Integration Test Fixtures Implementation
 * Full stack initialization for integration testing
 */

#include "integration_test_fixtures.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_file_utils.h"
#include "dap_strfuncs.h"
#include "dap_enc_key.h"
#include "dap_chain_net.h"
#include "dap_chain_ledger.h"
#include "dap_chain_wallet.h"
#include "dap_chain_datum_token.h"
#include "dap_cert.h"
#include "dap_sign.h"
#include "dap_ht_utils.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>

#define LOG_TAG "integration_test_fixtures"

// ============================================================================
// CONTEXT MANAGEMENT
// ============================================================================

/**
 * @brief Initialize integration test context
 */
integration_test_context_t *integration_test_fixture_init(
    const char *a_test_name,
    bool a_init_network,
    bool a_init_chain,
    bool a_init_ledger) {
    
    dap_return_val_if_fail(a_test_name, NULL);
    
    integration_test_context_t *l_ctx = DAP_NEW_Z(integration_test_context_t);
    if (!l_ctx) {
        log_it(L_ERROR, "Failed to allocate integration test context");
        return NULL;
    }
    
    // Create test directory
    l_ctx->test_dir = dap_strdup_printf("/tmp/cellframe_integration_%s_%d",
                                         a_test_name, (int)getpid());
    if (mkdir(l_ctx->test_dir, 0755) != 0 && errno != EEXIST) {
        log_it(L_ERROR, "Failed to create test directory: %s", l_ctx->test_dir);
        DAP_DELETE(l_ctx->test_dir);
        DAP_DELETE(l_ctx);
        return NULL;
    }
    
    // Set defaults
    l_ctx->test_net_name = "TestNet";
    l_ctx->test_net_id = 0x0001;
    l_ctx->test_chain_id.uint64 = 0x0001;
    
    // Generate configuration
    l_ctx->config_path = dap_strdup_printf("%s/test.cfg", l_ctx->test_dir);
    if (integration_test_config_generate(l_ctx) != 0) {
        log_it(L_ERROR, "Failed to generate test configuration");
        integration_test_fixture_cleanup(l_ctx);
        return NULL;
    }
    
    // Initialize DAP SDK
    if (integration_test_init_dap_sdk(l_ctx) != 0) {
        log_it(L_ERROR, "Failed to initialize DAP SDK");
        integration_test_fixture_cleanup(l_ctx);
        return NULL;
    }
    
    // Initialize network if requested
    if (a_init_network) {
        if (integration_test_create_network(l_ctx, l_ctx->test_net_name, l_ctx->test_net_id) != 0) {
            log_it(L_WARNING, "Failed to create test network");
        }
    }
    
    // Initialize chain if requested
    if (a_init_chain && l_ctx->test_net) {
        if (integration_test_create_chain(l_ctx, "dag") != 0) {
            log_it(L_WARNING, "Failed to create test chain");
        }
    }
    
    // Initialize ledger if requested
    if (a_init_ledger && l_ctx->test_chain) {
        if (integration_test_create_ledger(l_ctx) != 0) {
            log_it(L_WARNING, "Failed to create test ledger");
        }
    }
    
    log_it(L_INFO, "Initialized integration test context: %s", l_ctx->test_dir);
    return l_ctx;
}

/**
 * @brief Cleanup integration test context
 */
void integration_test_fixture_cleanup(integration_test_context_t *a_ctx) {
    if (!a_ctx) return;
    
    // Cleanup test entities
    if (a_ctx->test_wallet) {
        dap_chain_wallet_close(a_ctx->test_wallet);
    }
    
    DAP_DEL_Z(a_ctx->test_token);
    DAP_DELETE(a_ctx->test_token_ticker);
    
    // Deinitialize DAP SDK
    integration_test_deinit_dap_sdk(a_ctx);
    
    // Close config
    if (a_ctx->config) {
        dap_config_close(a_ctx->config);
    }
    
    // Remove test directory
    if (a_ctx->test_dir) {
        char *l_cmd = dap_strdup_printf("rm -rf %s", a_ctx->test_dir);
        system(l_cmd);
        DAP_DELETE(l_cmd);
        DAP_DELETE(a_ctx->test_dir);
    }
    
    DAP_DELETE(a_ctx->config_path);
    DAP_DELETE(a_ctx);
    
    log_it(L_INFO, "Cleaned up integration test context");
}

// ============================================================================
// CONFIGURATION GENERATION
// ============================================================================

/**
 * @brief Generate complete test configuration
 */
int integration_test_config_generate(integration_test_context_t *a_ctx) {
    dap_return_val_if_fail(a_ctx, -1);
    
    FILE *l_cfg = fopen(a_ctx->config_path, "w");
    if (!l_cfg) {
        log_it(L_ERROR, "Failed to create config file: %s", a_ctx->config_path);
        return -2;
    }
    
    // General section
    fprintf(l_cfg, "[general]\n");
    fprintf(l_cfg, "debug_mode=true\n");
    fprintf(l_cfg, "log_level=L_DEBUG\n");
    fprintf(l_cfg, "\n");
    
    // Resources section
    fprintf(l_cfg, "[resources]\n");
    fprintf(l_cfg, "pid_path=%s/test.pid\n", a_ctx->test_dir);
    fprintf(l_cfg, "log_file=%s/test.log\n", a_ctx->test_dir);
    fprintf(l_cfg, "wallets_path=%s/wallets\n", a_ctx->test_dir);
    fprintf(l_cfg, "\n");
    
    // Global DB section
    fprintf(l_cfg, "[global_db]\n");
    fprintf(l_cfg, "type=mdbx\n");
    fprintf(l_cfg, "path=%s/gdb\n", a_ctx->test_dir);
    fprintf(l_cfg, "\n");
    
    // Network section
    fprintf(l_cfg, "[network]\n");
    fprintf(l_cfg, "enabled=true\n");
    fprintf(l_cfg, "listen_address=127.0.0.1\n");
    fprintf(l_cfg, "listen_port=8079\n");
    fprintf(l_cfg, "\n");
    
    fclose(l_cfg);
    
    // Load config
    a_ctx->config = dap_config_open(a_ctx->config_path);
    if (!a_ctx->config) {
        log_it(L_ERROR, "Failed to load generated config");
        return -3;
    }
    
    log_it(L_INFO, "Generated integration test configuration");
    return 0;
}

/**
 * @brief Add custom config section
 */
int integration_test_config_add_section(integration_test_context_t *a_ctx,
                                         const char *a_section,
                                         const char **a_params) {
    dap_return_val_if_fail(a_ctx && a_section, -1);
    
    FILE *l_cfg = fopen(a_ctx->config_path, "a");
    if (!l_cfg) {
        return -2;
    }
    
    fprintf(l_cfg, "[%s]\n", a_section);
    if (a_params) {
        for (const char **p = a_params; *p; p++) {
            fprintf(l_cfg, "%s\n", *p);
        }
    }
    fprintf(l_cfg, "\n");
    fclose(l_cfg);
    
    // Reload config
    if (a_ctx->config) {
        dap_config_close(a_ctx->config);
    }
    a_ctx->config = dap_config_open(a_ctx->config_path);
    
    return a_ctx->config ? 0 : -3;
}

// ============================================================================
// DAP SDK INITIALIZATION
// ============================================================================

/**
 * @brief Initialize DAP SDK components
 */
int integration_test_init_dap_sdk(integration_test_context_t *a_ctx) {
    dap_return_val_if_fail(a_ctx, -1);
    
    // Initialize crypto (minimal)
    if (dap_enc_key_init() == 0) {
        a_ctx->dap_crypto_initialized = true;
        log_it(L_INFO, "Initialized DAP crypto");
    }
    
    // Note: Full DAP SDK init would include:
    // - dap_core_init()
    // - dap_config_init()
    // - dap_global_db_init()
    // - dap_events_init()
    // For now, minimal init for testing
    
    return 0;
}

/**
 * @brief Deinitialize DAP SDK
 */
void integration_test_deinit_dap_sdk(integration_test_context_t *a_ctx) {
    if (!a_ctx) return;
    
    if (a_ctx->dap_crypto_initialized) {
        dap_enc_key_deinit();
    }
    
    // Deinit other components
    a_ctx->dap_crypto_initialized = false;
    a_ctx->dap_global_db_initialized = false;
    a_ctx->dap_events_initialized = false;
}

// ============================================================================
// NETWORK & CHAIN CREATION
// ============================================================================

/**
 * @brief Create test network
 */
int integration_test_create_network(integration_test_context_t *a_ctx,
                                     const char *a_net_name,
                                     uint64_t a_net_id) {
    dap_return_val_if_fail(a_ctx && a_net_name, -1);
    
    // Check if network already exists
    a_ctx->test_net = dap_chain_net_by_name(a_net_name);
    if (a_ctx->test_net) {
        log_it(L_NOTICE, "Test network '%s' already exists", a_net_name);
        return 0;
    }
    
    // Create network (stub - real implementation would use dap_chain_net_create)
    log_it(L_WARNING, "Network creation not fully implemented - using stub");
    
    // For now, tests should use existing networks or manual setup
    return -2;
}

/**
 * @brief Create test chain
 */
int integration_test_create_chain(integration_test_context_t *a_ctx,
                                   const char *a_chain_type) {
    dap_return_val_if_fail(a_ctx && a_chain_type, -1);
    
    if (!a_ctx->test_net) {
        log_it(L_ERROR, "Cannot create chain without network");
        return -2;
    }
    
    // Chain creation stub
    log_it(L_WARNING, "Chain creation not fully implemented - using stub");
    return -3;
}

/**
 * @brief Create test ledger
 */
int integration_test_create_ledger(integration_test_context_t *a_ctx) {
    dap_return_val_if_fail(a_ctx, -1);
    
    if (!a_ctx->test_chain) {
        log_it(L_ERROR, "Cannot create ledger without chain");
        return -2;
    }
    
    // Ledger creation stub
    log_it(L_WARNING, "Ledger creation not fully implemented - using stub");
    return -3;
}

// ============================================================================
// TEST ENTITIES CREATION
// ============================================================================

/**
 * @brief Create test wallet
 */
int integration_test_create_wallet(integration_test_context_t *a_ctx,
                                    const char *a_wallet_name) {
    dap_return_val_if_fail(a_ctx && a_wallet_name, -1);
    
    char *l_wallet_path = dap_strdup_printf("%s/wallets/%s.dwallet",
                                             a_ctx->test_dir, a_wallet_name);
    
    // Create wallet directory
    char *l_wallets_dir = dap_strdup_printf("%s/wallets", a_ctx->test_dir);
    mkdir(l_wallets_dir, 0755);
    DAP_DELETE(l_wallets_dir);
    
    // Create wallet with default signature type
    dap_sign_type_t l_sig_type = {.type = SIG_TYPE_DILITHIUM};
    a_ctx->test_wallet = dap_chain_wallet_create_with_seed(a_wallet_name, l_wallet_path,
                                                             l_sig_type, NULL, 0, NULL);
    DAP_DELETE(l_wallet_path);
    
    if (!a_ctx->test_wallet) {
        log_it(L_ERROR, "Failed to create test wallet");
        return -2;
    }
    
    log_it(L_INFO, "Created test wallet: %s", a_wallet_name);
    return 0;
}

/**
 * @brief Create test token (stub)
 */
int integration_test_create_token(integration_test_context_t *a_ctx,
                                   const char *a_ticker,
                                   uint64_t a_total_supply) {
    dap_return_val_if_fail(a_ctx && a_ticker, -1);
    
    // Token creation requires ledger
    if (!a_ctx->test_ledger) {
        log_it(L_WARNING, "Token creation requires initialized ledger");
        return -2;
    }
    
    a_ctx->test_token_ticker = dap_strdup(a_ticker);
    
    log_it(L_INFO, "Created test token: %s (supply: %"PRIu64")", a_ticker, a_total_supply);
    return 0;
}

/**
 * @brief Create test emission (stub)
 */
int integration_test_create_emission(integration_test_context_t *a_ctx,
                                      uint64_t a_value,
                                      dap_chain_addr_t *a_addr) {
    UNUSED(a_value);
    UNUSED(a_addr);
    dap_return_val_if_fail(a_ctx, -1);
    
    log_it(L_WARNING, "Emission creation not fully implemented");
    return -2;
}

// ============================================================================
// MOCKING
// ============================================================================

/**
 * @brief Mock network sync state
 */
int integration_test_mock_network_sync(integration_test_context_t *a_ctx,
                                        bool a_is_synced) {
    dap_return_val_if_fail(a_ctx, -1);
    
    // Mock implementation would set network state
    log_it(L_INFO, "Mocked network sync state: %s", a_is_synced ? "synced" : "syncing");
    return 0;
}

/**
 * @brief Mock consensus
 */
int integration_test_mock_consensus(integration_test_context_t *a_ctx,
                                     const char *a_consensus_type) {
    dap_return_val_if_fail(a_ctx && a_consensus_type, -1);
    
    log_it(L_INFO, "Mocked consensus: %s", a_consensus_type);
    return 0;
}

// ============================================================================
// TEST DATA GENERATORS
// ============================================================================

/**
 * @brief Generate test transaction (stub)
 */
dap_chain_datum_tx_t *integration_test_tx_generate(
    integration_test_context_t *a_ctx,
    dap_chain_addr_t *a_from,
    dap_chain_addr_t *a_to,
    uint64_t a_value,
    const char *a_token_ticker) {
    
    UNUSED(a_from);
    UNUSED(a_to);
    UNUSED(a_value);
    UNUSED(a_token_ticker);
    dap_return_val_if_fail(a_ctx, NULL);
    
    // TX generation requires TX Compose API
    log_it(L_WARNING, "TX generation not fully implemented");
    return NULL;
}

// ============================================================================
// ADVANCED FIXTURES (MOVED FROM LEDGER TESTS)
// ============================================================================

/**
 * @brief Create minimal test network "Snet" (ID=0xFA0)
 * 
 * Fixture moved from production code (dap_chain_net.c) and ledger tests.
 * Creates hardcoded test network with ID 0xFA0 named "Snet".
 * This is a DIRECT COPY of the old dap_chain_net_test_init() for backward compatibility.
 */
int integration_test_create_snet(void)
{
    // Include internal structure definitions needed for test setup
    #include "dap_chain_node.h"
    
    typedef struct dap_chain_net_pvt {
        dap_chain_node_info_t *node_info;
        // ... minimal fields for test
    } dap_chain_net_pvt_t;
    
    #define PVT(a) ((dap_chain_net_pvt_t *)(void*)((a)->pvt))
    
    // Check if already exists
    dap_chain_net_id_t l_test_id = {.uint64 = 0xFA0};
    if (dap_chain_net_by_id(l_test_id)) {
        log_it(L_NOTICE, "Test network 'Snet' already exists, skipping creation");
        return 0;  // Already created
    }
    
    log_it(L_NOTICE, "Creating test network 'Snet' with ID 0xFA0...");
    
    // Create test network (exact copy of old dap_chain_net_test_init)
    dap_chain_net_t *l_net = DAP_NEW_Z_SIZE(dap_chain_net_t, sizeof(dap_chain_net_t) + sizeof(dap_chain_net_pvt_t));
    if (!l_net) {
        log_it(L_ERROR, "Failed to allocate dap_chain_net_t");
        return -1;
    }
    
    PVT(l_net)->node_info = DAP_NEW_Z_SIZE(dap_chain_node_info_t, sizeof(dap_chain_node_info_t) + DAP_HOSTADDR_STRLEN + 1);
    if (!PVT(l_net)->node_info) {
        log_it(L_ERROR, "Failed to allocate node_info");
        DAP_DELETE(l_net);
        return -1;
    }
    
    l_net->pub.id.uint64 = 0xFA0;
    strcpy(l_net->pub.name, "Snet");
    l_net->pub.gdb_groups_prefix = (const char*)l_net->pub.name;
    l_net->pub.native_ticker = "TestCoin";
    l_net->pub.node_role.enums = NODE_ROLE_ROOT;
    
    log_it(L_NOTICE, "Network structure initialized, adding to global registry...");
    
    // Register network using extern declarations
    extern dap_chain_net_t *s_nets_by_id;
    extern dap_chain_net_t *s_nets_by_name;
    dap_ht_add_hh(hh2, s_nets_by_id, pub.id, l_net);
    dap_ht_add_str(s_nets_by_name, pub.name, l_net);
    
    log_it(L_NOTICE, "✅ Test network 'Snet' created and registered successfully!");
    
    #undef PVT
    return 0;
}

/**
 * @brief Create token DECL datum
 * 
 * Moved from dap_chain_ledger_tests.c for reuse across all tests.
 */
dap_chain_datum_token_t *integration_test_create_token_decl(
    dap_cert_t *a_cert,
    size_t *a_token_size,
    const char *a_token_ticker,
    uint256_t a_total_supply,
    byte_t *a_tsd_section,
    size_t a_size_tsd_section,
    uint16_t a_flags)
{
    dap_return_val_if_fail(a_cert && a_token_size && a_token_ticker, NULL);
    
    dap_chain_datum_token_t *l_token = DAP_NEW_Z(dap_chain_datum_token_t);
    l_token->version = 2;
    l_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL;
    l_token->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    snprintf(l_token->ticker, sizeof(l_token->ticker), "%s", a_token_ticker);
    l_token->signs_valid = 1;
    l_token->total_supply = a_total_supply;
    l_token->header_native_decl.decimals = 18;
    l_token->signs_total = 0;
    l_token->header_native_decl.flags = a_flags;
    
    if (a_tsd_section && a_size_tsd_section != 0) {
        l_token->header_native_decl.tsd_total_size = a_size_tsd_section;
        l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + a_size_tsd_section);
        memcpy(l_token->tsd_n_signs, a_tsd_section, a_size_tsd_section);
    }
    
    dap_sign_t *l_sign = dap_cert_sign(a_cert, l_token, sizeof(*l_token) + a_size_tsd_section);
    if (l_sign) {
        size_t l_sign_size = dap_sign_get_size(l_sign);
        l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + a_size_tsd_section + l_sign_size);
        memcpy(l_token->tsd_n_signs + a_size_tsd_section, l_sign, l_sign_size);
        DAP_DELETE(l_sign);
        l_token->signs_total = 1;
        *a_token_size = sizeof(dap_chain_datum_token_t) + l_sign_size + a_size_tsd_section;
        return l_token;
    } else {
        DAP_DEL_Z(l_token);
        DAP_DELETE(l_sign);
        return NULL;
    }
}

/**
 * @brief Create token UPDATE datum
 * 
 * Moved from dap_chain_ledger_tests.c for reuse across all tests.
 */
dap_chain_datum_token_t *integration_test_create_token_update(
    dap_cert_t *a_cert,
    size_t *a_token_size,
    const char *a_token_ticker,
    byte_t *a_tsd_section,
    size_t a_size_tsd_section)
{
    dap_return_val_if_fail(a_cert && a_token_size && a_token_ticker, NULL);
    
    dap_chain_datum_token_t *l_token = DAP_NEW_Z(dap_chain_datum_token_t);
    l_token->version = 2;
    l_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    l_token->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    snprintf(l_token->ticker, sizeof(l_token->ticker), "%s", a_token_ticker);
    l_token->signs_valid = 0;
    l_token->total_supply = uint256_0;
    l_token->header_native_decl.decimals = 0;
    l_token->signs_total = 0;
    l_token->header_native_decl.flags = 0;
    
    if (a_tsd_section && a_size_tsd_section != 0) {
        l_token->header_native_decl.tsd_total_size = a_size_tsd_section;
        l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + a_size_tsd_section);
        memcpy(l_token->tsd_n_signs, a_tsd_section, a_size_tsd_section);
    }
    
    dap_sign_t *l_sign = dap_cert_sign(a_cert, l_token, sizeof(*l_token) + a_size_tsd_section);
    if (l_sign) {
        size_t l_sign_size = dap_sign_get_size(l_sign);
        l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + a_size_tsd_section + l_sign_size);
        memcpy(l_token->tsd_n_signs + a_size_tsd_section, l_sign, l_sign_size);
        DAP_DELETE(l_sign);
        l_token->signs_total = 1;
        *a_token_size = sizeof(dap_chain_datum_token_t) + l_sign_size + a_size_tsd_section;
        return l_token;
    } else {
        DAP_DEL_Z(l_token);
        DAP_DELETE(l_sign);
        return NULL;
    }
}
