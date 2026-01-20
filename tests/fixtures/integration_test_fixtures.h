/*
 * Integration Test Fixtures - Full Stack Initialization
 * 
 * Provides fixtures for integration tests with real DAP SDK and Cellframe SDK.
 * Initializes networks, chains, ledgers, and provides test entities.
 */

#pragma once

#include "dap_common.h"
#include "dap_config.h"
#include "dap_chain_common.h"
#include "dap_chain_net.h"
#include "dap_chain.h"
#include "dap_chain_ledger.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_wallet.h"
#include "dap_hash.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// INTEGRATION TEST CONTEXT
// ============================================================================

/**
 * @brief Integration test context with full stack
 * Contains initialized DAP SDK, networks, chains, and test entities
 */
typedef struct {
    char *test_dir;              // Test directory
    char *config_path;           // Configuration file path
    dap_config_t *config;        // Global configuration
    
    // DAP SDK components
    bool dap_crypto_initialized;
    bool dap_global_db_initialized;
    bool dap_events_initialized;
    
    // Cellframe SDK components
    bool chains_initialized;
    bool ledger_initialized;
    bool services_initialized;
    
    // Test network
    dap_chain_net_t *test_net;
    uint64_t test_net_id;
    const char *test_net_name;
    
    // Test chains
    dap_chain_t *test_chain;
    dap_chain_id_t test_chain_id;
    
    // Test ledger
    dap_ledger_t *test_ledger;
    
    // Test entities
    dap_chain_wallet_t *test_wallet;
    dap_chain_datum_token_t *test_token;
    char *test_token_ticker;
    
    // Mocking (optional for integration tests)
    void *mock_network_state;    // Mock network sync state
    void *mock_consensus;         // Mock consensus if needed
} integration_test_context_t;

// ============================================================================
// INTEGRATION TEST FIXTURE FUNCTIONS
// ============================================================================

/**
 * @brief Initialize integration test context
 * 
 * Sets up full Cellframe SDK stack including:
 * - DAP SDK initialization (crypto, db, events)
 * - Test network and chain creation
 * - Ledger initialization
 * - Configuration generation
 * 
 * @param a_test_name Test name
 * @param a_init_network Initialize test network
 * @param a_init_chain Initialize test chain
 * @param a_init_ledger Initialize test ledger
 * @return Initialized context or NULL on error
 */
integration_test_context_t *integration_test_fixture_init(
    const char *a_test_name,
    bool a_init_network,
    bool a_init_chain,
    bool a_init_ledger
);

/**
 * @brief Cleanup integration test context
 * 
 * Properly shuts down all initialized components.
 * 
 * @param a_ctx Test context
 */
void integration_test_fixture_cleanup(integration_test_context_t *a_ctx);

// ============================================================================
// CONFIGURATION GENERATION
// ============================================================================

/**
 * @brief Generate complete test configuration
 * 
 * Creates full configuration for integration tests with all necessary sections.
 * 
 * @param a_ctx Test context
 * @return 0 on success, negative on error
 */
int integration_test_config_generate(integration_test_context_t *a_ctx);

/**
 * @brief Add custom config section
 * 
 * @param a_ctx Test context
 * @param a_section Section name
 * @param a_params NULL-terminated array of "key=value" strings
 * @return 0 on success, negative on error
 */
int integration_test_config_add_section(integration_test_context_t *a_ctx,
                                         const char *a_section,
                                         const char **a_params);

// ============================================================================
// DAP SDK INITIALIZATION
// ============================================================================

/**
 * @brief Initialize DAP SDK for integration tests
 * 
 * @param a_ctx Test context
 * @return 0 on success, negative on error
 */
int integration_test_init_dap_sdk(integration_test_context_t *a_ctx);

/**
 * @brief Deinitialize DAP SDK
 * 
 * @param a_ctx Test context
 */
void integration_test_deinit_dap_sdk(integration_test_context_t *a_ctx);

// ============================================================================
// NETWORK & CHAIN CREATION
// ============================================================================

/**
 * @brief Create test network (legacy fixture)
 * 
 * Creates a minimal working network for integration tests.
 * DIRECT COPY of old dap_chain_net_test_init() for backward compatibility.
 * 
 * @param a_ctx Test context
 * @param a_net_name Network name
 * @param a_net_id Network ID
 * @return 0 on success, negative on error
 */
int integration_test_create_network(integration_test_context_t *a_ctx,
                                     const char *a_net_name,
                                     uint64_t a_net_id);

/**
 * @brief Create minimal test network "Snet" (ID=0xFA0)
 * 
 * Fixture moved from production code (dap_chain_net.c).
 * Creates hardcoded test network with ID 0xFA0 named "Snet".
 * 
 * @return 0 on success, negative on error
 */
int integration_test_create_snet(void);

/**
 * @brief Create test chain
 * 
 * Creates a chain (DAG/Blocks) for testing.
 * 
 * @param a_ctx Test context
 * @param a_chain_type Chain type ("dag", "blocks", "none")
 * @return 0 on success, negative on error
 */
int integration_test_create_chain(integration_test_context_t *a_ctx,
                                   const char *a_chain_type);

/**
 * @brief Create test ledger
 * 
 * Initializes ledger for the test chain.
 * 
 * @param a_ctx Test context
 * @return 0 on success, negative on error
 */
int integration_test_create_ledger(integration_test_context_t *a_ctx);

// ============================================================================
// TEST ENTITIES CREATION
// ============================================================================

/**
 * @brief Create test wallet
 * 
 * @param a_ctx Test context
 * @param a_wallet_name Wallet name
 * @return 0 on success, negative on error
 */
int integration_test_create_wallet(integration_test_context_t *a_ctx,
                                    const char *a_wallet_name);

/**
 * @brief Create test token
 * 
 * @param a_ctx Test context
 * @param a_ticker Token ticker
 * @param a_total_supply Total supply (uint64)
 * @return 0 on success, negative on error
 */
int integration_test_create_token(integration_test_context_t *a_ctx,
                                   const char *a_ticker,
                                   uint64_t a_total_supply);

/**
 * @brief Create test emission for token
 * 
 * @param a_ctx Test context
 * @param a_value Emission value
 * @param a_addr Target address
 * @return 0 on success, negative on error
 */
int integration_test_create_emission(integration_test_context_t *a_ctx,
                                      uint64_t a_value,
                                      dap_chain_addr_t *a_addr);

// ============================================================================
// MOCKING FOR INTEGRATION TESTS (OPTIONAL)
// ============================================================================

/**
 * @brief Mock network synchronization state
 * 
 * For integration tests that don't need real network sync.
 * 
 * @param a_ctx Test context
 * @param a_is_synced Mock sync status
 * @return 0 on success, negative on error
 */
int integration_test_mock_network_sync(integration_test_context_t *a_ctx,
                                        bool a_is_synced);

/**
 * @brief Mock consensus for faster testing
 * 
 * @param a_ctx Test context
 * @param a_consensus_type Consensus type to mock
 * @return 0 on success, negative on error
 */
int integration_test_mock_consensus(integration_test_context_t *a_ctx,
                                     const char *a_consensus_type);

// ============================================================================
// TEST DATA GENERATORS (INTEGRATION-SPECIFIC)
// ============================================================================

/**
 * @brief Generate test transaction
 * 
 * @param a_ctx Test context
 * @param a_from Source address
 * @param a_to Destination address
 * @param a_value Value to transfer
 * @param a_token_ticker Token ticker
 * @return Created transaction or NULL
 */
dap_chain_datum_tx_t *integration_test_tx_generate(
    integration_test_context_t *a_ctx,
    dap_chain_addr_t *a_from,
    dap_chain_addr_t *a_to,
    uint64_t a_value,
    const char *a_token_ticker
);

/**
 * @brief Create token DECL datum
 * 
 * Creates token declaration datum with signature.
 * 
 * @param a_cert Certificate for signing
 * @param a_token_size Output: token size
 * @param a_token_ticker Token ticker
 * @param a_total_supply Total supply
 * @param a_tsd_section TSD section data
 * @param a_size_tsd_section TSD section size
 * @param a_flags Token flags
 * @return Token datum or NULL on error
 */
dap_chain_datum_token_t *integration_test_create_token_decl(
    dap_cert_t *a_cert,
    size_t *a_token_size,
    const char *a_token_ticker,
    uint256_t a_total_supply,
    byte_t *a_tsd_section,
    size_t a_size_tsd_section,
    uint16_t a_flags
);

/**
 * @brief Create token UPDATE datum
 * 
 * Creates token update datum with signature.
 * 
 * @param a_cert Certificate for signing
 * @param a_token_size Output: token size
 * @param a_token_ticker Token ticker
 * @param a_tsd_section TSD section data
 * @param a_size_tsd_section TSD section size
 * @return Token datum or NULL on error
 */
dap_chain_datum_token_t *integration_test_create_token_update(
    dap_cert_t *a_cert,
    size_t *a_token_size,
    const char *a_token_ticker,
    byte_t *a_tsd_section,
    size_t a_size_tsd_section
);

#ifdef __cplusplus
}
#endif
