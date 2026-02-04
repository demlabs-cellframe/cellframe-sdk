/*
 * Common test fixtures for Cellframe SDK tests
 * Provides network initialization and test utilities
 */

#include "test_fixtures.h"
#include "dap_common.h"
#include "dap_chain_net.h"
#include "dap_chain.h"
#include "dap_chain_ledger.h"

#define LOG_TAG "test_fixtures"

// ===== NETWORK FIXTURES =====

/**
 * @brief Create a test network for testing
 * @param a_net_name Network name
 * @param a_net_id Network ID
 * @return Created network or NULL on error
 */
dap_chain_net_t *test_network_create(const char *a_net_name, uint64_t a_net_id) {
    dap_return_val_if_fail(a_net_name, NULL);

    // This is a simplified test network creation
    // In real tests, you'd initialize the full network stack
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    if (l_net) {
        log_it(L_NOTICE, "Test network '%s' already exists", a_net_name);
        return l_net;
    }

    log_it(L_NOTICE, "Creating test network '%s' with ID %"PRIu64, a_net_name, a_net_id);

    // Real implementation would call dap_chain_net_create or similar
    // For now, return NULL - tests will need to be updated with proper network init
    return NULL;
}

/**
 * @brief Delete a test network
 * @param a_net Network to delete
 */
void test_network_delete(dap_chain_net_t *a_net) {
    if (!a_net) return;

    log_it(L_NOTICE, "Deleting test network '%s'", a_net->pub.name);
    // Real implementation would clean up network resources
}

// ===== DATA GENERATORS =====

/**
 * @brief Generate a deterministic test hash
 * @param a_seed Seed value for generation
 * @param a_hash Output hash
 */
void test_hash_generate(uint32_t a_seed, dap_hash_sha3_256_t *a_hash) {
    dap_return_if_fail(a_hash);

    memset(a_hash, 0, sizeof(dap_hash_sha3_256_t));
    for (size_t i = 0; i < sizeof(dap_hash_sha3_256_t); i++) {
        a_hash->raw[i] = (uint8_t)((a_seed + i * 17) % 256);
    }
}

/**
 * @brief Generate test address
 * @param a_seed Seed value
 * @param a_addr Output address
 */
void test_addr_generate(uint32_t a_seed, dap_chain_addr_t *a_addr) {
    dap_return_if_fail(a_addr);

    memset(a_addr, 0, sizeof(dap_chain_addr_t));
    // Simple deterministic address generation for testing
    for (size_t i = 0; i < sizeof(dap_chain_addr_t); i++) {
        ((uint8_t*)a_addr)[i] = (uint8_t)((a_seed * 7 + i * 11) % 256);
    }
}
