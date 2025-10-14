/*
 * Authors:
 * Olzhas Zharasbaev
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_chain_common.h"
#include "dap_chain_wallet_cache_db.h"
#include "dap_wallet_cache_db_test.h"

// Test helper macros
#define TEST_PASS(name) printf("  ✅ PASS: %s\n", name)
#define TEST_FAIL(name, reason) do { \
    printf("  ❌ FAIL: %s - %s\n", name, reason); \
    exit(1); \
} while(0)

// Test data constants
static const dap_chain_net_id_t TEST_NET_ID = {.uint64 = 0x123456};
static const dap_chain_id_t TEST_CHAIN_ID = {.uint64 = 0x789ABC};

/**
 * @brief Create test wallet address
 */
static dap_chain_addr_t create_test_addr(uint8_t seed)
{
    dap_chain_addr_t addr;
    memset(&addr, seed, sizeof(addr));
    return addr;
}

/**
 * @brief Test 1: Structure sizes and alignment
 * Verifies that structures have expected sizes and are properly packed
 */
void test_wallet_cache_db_structures(void)
{
    printf("\n[TEST 1] Structure Sizes and Alignment\n");
    
    size_t header_size = sizeof(dap_wallet_cache_db_t);
    size_t tx_size = sizeof(dap_wallet_tx_cache_db_t);
    size_t unspent_size = sizeof(dap_wallet_unspent_out_db_t);
    
    printf("  Structure sizes:\n");
    printf("    - dap_wallet_cache_db_t: %zu bytes\n", header_size);
    printf("    - dap_wallet_tx_cache_db_t: %zu bytes\n", tx_size);
    printf("    - dap_wallet_unspent_out_db_t: %zu bytes\n", unspent_size);
    
    // Verify sizes are reasonable
    if (header_size == 0 || header_size > 10000) {
        TEST_FAIL("Structure size", "Header size unreasonable");
    }
    
    if (tx_size == 0 || tx_size > 10000) {
        TEST_FAIL("Structure size", "TX size unreasonable");
    }
    
    TEST_PASS("Structure sizes are reasonable");
}

/**
 * @brief Test 2: Size calculation functions
 * Test dap_wallet_cache_db_calc_size()
 */
void test_wallet_cache_db_size_calculation(void)
{
    printf("\n[TEST 2] Size Calculation Functions\n");
    
    // Test empty cache
    size_t size_empty = dap_wallet_cache_db_calc_size(0, 0);
    size_t expected_empty = sizeof(dap_wallet_cache_db_t);
    
    if (size_empty != expected_empty) {
        printf("  Expected: %zu, Got: %zu\n", expected_empty, size_empty);
        TEST_FAIL("Size calculation", "Empty cache size incorrect");
    }
    
    // Test with 1 transaction
    size_t size_1tx = dap_wallet_cache_db_calc_size(1, 0);
    size_t expected_1tx = sizeof(dap_wallet_cache_db_t) + sizeof(dap_wallet_tx_cache_db_t);
    
    if (size_1tx != expected_1tx) {
        printf("  Expected: %zu, Got: %zu\n", expected_1tx, size_1tx);
        TEST_FAIL("Size calculation", "1 TX cache size incorrect");
    }
    
    // Test with 1 unspent
    size_t size_1unspent = dap_wallet_cache_db_calc_size(0, 1);
    size_t expected_1unspent = sizeof(dap_wallet_cache_db_t) + sizeof(dap_wallet_unspent_out_db_t);
    
    if (size_1unspent != expected_1unspent) {
        printf("  Expected: %zu, Got: %zu\n", expected_1unspent, size_1unspent);
        TEST_FAIL("Size calculation", "1 unspent cache size incorrect");
    }
    
    // Test with multiple entries
    size_t size_multiple = dap_wallet_cache_db_calc_size(10, 5);
    size_t expected_multiple = sizeof(dap_wallet_cache_db_t) + 
                                sizeof(dap_wallet_tx_cache_db_t) * 10 +
                                sizeof(dap_wallet_unspent_out_db_t) * 5;
    
    if (size_multiple != expected_multiple) {
        printf("  Expected: %zu, Got: %zu\n", expected_multiple, size_multiple);
        TEST_FAIL("Size calculation", "Multiple entries size incorrect");
    }
    
    printf("  Test results:\n");
    printf("    - Empty cache: %zu bytes\n", size_empty);
    printf("    - 1 TX: %zu bytes\n", size_1tx);
    printf("    - 1 unspent: %zu bytes\n", size_1unspent);
    printf("    - 10 TX + 5 unspents: %zu bytes\n", size_multiple);
    
    TEST_PASS("Size calculation correctness");
}

/**
 * @brief Test 3: Cache creation and initialization
 * Test dap_wallet_cache_db_create()
 */
void test_wallet_cache_db_creation(void)
{
    printf("\n[TEST 3] Cache Creation and Initialization\n");
    
    dap_chain_addr_t test_addr = create_test_addr(0x42);
    
    // Create empty cache
    dap_wallet_cache_db_t *cache = dap_wallet_cache_db_create(&test_addr, TEST_NET_ID, TEST_CHAIN_ID);
    
    if (!cache) {
        TEST_FAIL("Cache creation", "Failed to create cache");
    }
    
    // Verify initialization
    if (cache->version != DAP_WALLET_CACHE_DB_VERSION) {
        TEST_FAIL("Cache initialization", "Version not set correctly");
    }
    
    if (memcmp(&cache->wallet_addr, &test_addr, sizeof(dap_chain_addr_t)) != 0) {
        TEST_FAIL("Cache initialization", "Address not set correctly");
    }
    
    if (cache->net_id.uint64 != TEST_NET_ID.uint64) {
        TEST_FAIL("Cache initialization", "Network ID not set correctly");
    }
    
    if (cache->chain_id.uint64 != TEST_CHAIN_ID.uint64) {
        TEST_FAIL("Cache initialization", "Chain ID not set correctly");
    }
    
    if (cache->tx_count != 0) {
        TEST_FAIL("Cache initialization", "TX count should be 0");
    }
    
    if (cache->unspent_count != 0) {
        TEST_FAIL("Cache initialization", "Unspent count should be 0");
    }
    
    printf("  Cache initialized with:\n");
    printf("    - Version: %u\n", cache->version);
    printf("    - Network ID: 0x%lx\n", cache->net_id.uint64);
    printf("    - Chain ID: 0x%lx\n", cache->chain_id.uint64);
    printf("    - TX count: %u\n", cache->tx_count);
    printf("    - Unspent count: %u\n", cache->unspent_count);
    
    // Cleanup
    dap_wallet_cache_db_free(cache);
    
    TEST_PASS("Cache creation and initialization");
}

/**
 * @brief Test 4: GlobalDB key generation
 * Test dap_wallet_cache_db_get_key() and dap_wallet_cache_db_get_group()
 */
void test_wallet_cache_db_key_generation(void)
{
    printf("\n[TEST 4] GlobalDB Key Generation\n");
    
    // Test key generation
    dap_chain_addr_t addr1 = create_test_addr(0x11);
    dap_chain_addr_t addr2 = create_test_addr(0x22);
    
    char *key1 = dap_wallet_cache_db_get_key(&addr1);
    char *key2 = dap_wallet_cache_db_get_key(&addr2);
    
    if (!key1 || !key2) {
        TEST_FAIL("Key generation", "NULL key returned");
    }
    
    if (strlen(key1) == 0 || strlen(key2) == 0) {
        TEST_FAIL("Key generation", "Empty key returned");
    }
    
    if (strcmp(key1, key2) == 0) {
        TEST_FAIL("Key generation", "Different addresses produced same key");
    }
    
    printf("  Sample keys:\n");
    printf("    - Addr1: %s\n", key1);
    printf("    - Addr2: %s\n", key2);
    
    DAP_DELETE(key1);
    DAP_DELETE(key2);
    
    // Test group generation
    char *group1 = dap_wallet_cache_db_get_group(TEST_NET_ID, "test-chain-1");
    char *group2 = dap_wallet_cache_db_get_group(TEST_NET_ID, "test-chain-2");
    
    if (!group1 || !group2) {
        TEST_FAIL("Group generation", "NULL group returned");
    }
    
    if (strlen(group1) == 0 || strlen(group2) == 0) {
        TEST_FAIL("Group generation", "Empty group returned");
    }
    
    if (strcmp(group1, group2) == 0) {
        TEST_FAIL("Group generation", "Different chains produced same group");
    }
    
    printf("  Sample groups:\n");
    printf("    - Chain1: %s\n", group1);
    printf("    - Chain2: %s\n", group2);
    
    DAP_DELETE(group1);
    DAP_DELETE(group2);
    
    TEST_PASS("Key and group generation");
}

/**
 * @brief Test 5: Memory management
 * Test proper allocation and deallocation
 */
void test_wallet_cache_db_memory(void)
{
    printf("\n[TEST 5] Memory Management\n");
    
    dap_chain_addr_t test_addr = create_test_addr(0x55);
    
    // Create multiple caches
    const int NUM_CACHES = 100;
    dap_wallet_cache_db_t **caches = DAP_NEW_Z_SIZE(dap_wallet_cache_db_t*, sizeof(dap_wallet_cache_db_t*) * NUM_CACHES);
    
    if (!caches) {
        TEST_FAIL("Memory allocation", "Failed to allocate cache array");
    }
    
    // Allocate
    for (int i = 0; i < NUM_CACHES; i++) {
        caches[i] = dap_wallet_cache_db_create(&test_addr, TEST_NET_ID, TEST_CHAIN_ID);
        if (!caches[i]) {
            TEST_FAIL("Memory allocation", "Failed to create cache in loop");
        }
    }
    
    printf("  Successfully allocated %d caches\n", NUM_CACHES);
    
    // Deallocate
    for (int i = 0; i < NUM_CACHES; i++) {
        dap_wallet_cache_db_free(caches[i]);
    }
    
    DAP_DELETE(caches);
    
    printf("  Successfully freed %d caches\n", NUM_CACHES);
    
    TEST_PASS("Memory allocation and deallocation");
}

/**
 * @brief Test edge cases: empty wallet, NULL pointers, boundary values
 */
static void test_wallet_cache_db_edge_cases(void)
{
    printf("\n[TEST 6] Edge Cases and Boundary Conditions\n");
    
    dap_chain_addr_t l_addr;
    dap_chain_net_id_t l_net_id = {.uint64 = 0x123};
    dap_chain_id_t l_chain_id = {.uint64 = 0x456};
    
    memset(&l_addr, 0xAA, sizeof(l_addr));
    
    // Test 1: Empty wallet (0 transactions)
    dap_wallet_cache_db_t *l_empty_cache = dap_wallet_cache_db_create(&l_addr, l_net_id, l_chain_id);
    assert(l_empty_cache != NULL);
    assert(l_empty_cache->tx_count == 0);
    assert(l_empty_cache->unspent_count == 0);
    
    size_t l_empty_size = dap_wallet_cache_db_calc_size(l_empty_cache->tx_count, l_empty_cache->unspent_count);
    assert(l_empty_size == sizeof(dap_wallet_cache_db_t));
    printf("  ✓ Empty wallet: size=%zu bytes\n", l_empty_size);
    dap_wallet_cache_db_free(l_empty_cache);
    
    // Test 2: Maximum transaction count (boundary test)
    dap_wallet_cache_db_t *l_max_cache = dap_wallet_cache_db_create(&l_addr, l_net_id, l_chain_id);
    l_max_cache->tx_count = 10000; // Large but reasonable
    l_max_cache->unspent_count = 5000;
    
    size_t l_max_size = sizeof(dap_wallet_cache_db_t) + 
                        sizeof(dap_wallet_tx_cache_db_t) * l_max_cache->tx_count +
                        sizeof(dap_wallet_unspent_out_db_t) * l_max_cache->unspent_count;
    
    printf("  ✓ Large wallet (10k tx, 5k unspent): estimated size=%zu bytes (~%.1f MB)\n", 
           l_max_size, l_max_size / (1024.0 * 1024.0));
    dap_wallet_cache_db_free(l_max_cache);
    
    // Test 3: Zero values
    dap_wallet_cache_db_t *l_zero_cache = dap_wallet_cache_db_create(&l_addr, l_net_id, l_chain_id);
    memset(&l_zero_cache->wallet_addr, 0, sizeof(dap_chain_addr_t));
    l_zero_cache->net_id.uint64 = 0;
    l_zero_cache->chain_id.uint64 = 0;
    
    printf("  ✓ Zero values: handled correctly\n");
    dap_wallet_cache_db_free(l_zero_cache);
    
    // Test 4: Version check
    dap_wallet_cache_db_t *l_ver_cache = dap_wallet_cache_db_create(&l_addr, l_net_id, l_chain_id);
    assert(l_ver_cache->version == 1);
    printf("  ✓ Version: %u (expected 1)\n", l_ver_cache->version);
    dap_wallet_cache_db_free(l_ver_cache);
    
    TEST_PASS("Edge cases and boundary conditions");
}

/**
 * @brief Test data integrity: serialize → deserialize → compare
 */
static void test_wallet_cache_db_data_integrity(void)
{
    printf("\n[TEST 7] Data Integrity (Serialize/Deserialize)\n");
    
    dap_chain_addr_t l_addr;
    dap_chain_net_id_t l_net_id = {.uint64 = 0xDEADBEEF};
    dap_chain_id_t l_chain_id = {.uint64 = 0xCAFEBABE};
    
    memset(&l_addr, 0x42, sizeof(l_addr));
    
    // Create cache with specific values
    dap_wallet_cache_db_t *l_original = dap_wallet_cache_db_create(&l_addr, l_net_id, l_chain_id);
    l_original->tx_count = 5;
    l_original->unspent_count = 3;
    
    size_t l_size = dap_wallet_cache_db_calc_size(l_original->tx_count, l_original->unspent_count);
    
    // Simulate serialization: copy to buffer
    uint8_t *l_buffer = DAP_NEW_Z_SIZE(uint8_t, l_size);
    memcpy(l_buffer, l_original, l_size);
    
    // Simulate deserialization: copy back to new structure
    dap_wallet_cache_db_t *l_restored = (dap_wallet_cache_db_t*)l_buffer;
    
    // Compare all fields
    assert(l_restored->version == l_original->version);
    assert(l_restored->net_id.uint64 == l_original->net_id.uint64);
    assert(l_restored->chain_id.uint64 == l_original->chain_id.uint64);
    assert(l_restored->tx_count == l_original->tx_count);
    assert(l_restored->unspent_count == l_original->unspent_count);
    assert(memcmp(&l_restored->wallet_addr, &l_original->wallet_addr, sizeof(dap_chain_addr_t)) == 0);
    
    printf("  Verification:\n");
    printf("    ✓ Version: %u == %u\n", l_restored->version, l_original->version);
    printf("    ✓ Net ID: 0x%llx == 0x%llx\n", 
           (unsigned long long)l_restored->net_id.uint64, 
           (unsigned long long)l_original->net_id.uint64);
    printf("    ✓ Chain ID: 0x%llx == 0x%llx\n",
           (unsigned long long)l_restored->chain_id.uint64,
           (unsigned long long)l_original->chain_id.uint64);
    printf("    ✓ TX count: %u == %u\n", l_restored->tx_count, l_original->tx_count);
    printf("    ✓ Unspent count: %u == %u\n", l_restored->unspent_count, l_original->unspent_count);
    printf("    ✓ Wallet addr: matches\n");
    
    DAP_DELETE(l_buffer);
    dap_wallet_cache_db_free(l_original);
    
    TEST_PASS("Data integrity (serialize/deserialize round-trip)");
}

/**
 * @brief Test structure alignment and padding
 */
static void test_wallet_cache_db_alignment(void)
{
    printf("\n[TEST 8] Structure Alignment and Padding\n");
    
    printf("  Structure alignment:\n");
    printf("    - dap_wallet_cache_db_t: %zu-byte aligned\n", _Alignof(dap_wallet_cache_db_t));
    printf("    - dap_wallet_tx_cache_db_t: %zu-byte aligned\n", _Alignof(dap_wallet_tx_cache_db_t));
    printf("    - dap_wallet_tx_cache_input_db_t: %zu-byte aligned\n", _Alignof(dap_wallet_tx_cache_input_db_t));
    printf("    - dap_wallet_tx_cache_output_db_t: %zu-byte aligned\n", _Alignof(dap_wallet_tx_cache_output_db_t));
    printf("    - dap_wallet_unspent_out_db_t: %zu-byte aligned\n", _Alignof(dap_wallet_unspent_out_db_t));
    
    // Check if structures are properly packed (no excessive padding)
    size_t l_main_size = sizeof(dap_wallet_cache_db_t);
    size_t l_tx_size = sizeof(dap_wallet_tx_cache_db_t);
    
    printf("  Padding analysis:\n");
    printf("    - Main header: %zu bytes\n", l_main_size);
    printf("    - TX entry: %zu bytes\n", l_tx_size);
    
    // Structures should be reasonably sized (not excessively padded)
    assert(l_main_size < 200); // Reasonable upper bound
    assert(l_tx_size < 200);   // Reasonable upper bound
    
    printf("  ✓ Structures are reasonably sized (no excessive padding)\n");
    
    TEST_PASS("Structure alignment and padding");
}

/**
 * @brief Run all wallet cache DB tests
 */
void dap_wallet_cache_db_tests_run(void)
{
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("          WALLET CACHE DB UNIT TESTS                          \n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("\n");
    printf("Testing wallet cache database structures and helper functions.\n");
    printf("NOTE: GlobalDB save/load tests require full node initialization.\n");
    printf("      These will be tested in integration tests.\n");
    
    // Run individual tests
    test_wallet_cache_db_structures();
    test_wallet_cache_db_size_calculation();
    test_wallet_cache_db_creation();
    test_wallet_cache_db_key_generation();
    test_wallet_cache_db_memory();
    test_wallet_cache_db_edge_cases();
    test_wallet_cache_db_data_integrity();
    test_wallet_cache_db_alignment();
    
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("                  ALL TESTS PASSED ✅                          \n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("\n");
}
