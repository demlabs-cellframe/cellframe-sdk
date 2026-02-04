/*
 * Example Unit Test using Unit Test Fixtures
 * 
 * Demonstrates isolated testing with DAP SDK mocking
 */

#include "unit_test_fixtures.h"
#include "dap_common.h"
#include "dap_chain_common.h"
#include <assert.h>

#define LOG_TAG "example_unit_test"

// Test: Hash generation is deterministic
void test_hash_deterministic(void) {
    dap_hash_sha3_256_t hash1, hash2;
    
    // Same seed produces same hash
    unit_test_hash_generate(42, &hash1);
    unit_test_hash_generate(42, &hash2);
    
    assert(memcmp(&hash1, &hash2, sizeof(dap_hash_sha3_256_t)) == 0);
    
    // Different seed produces different hash
    dap_hash_sha3_256_t hash3;
    unit_test_hash_generate(123, &hash3);
    assert(memcmp(&hash1, &hash3, sizeof(dap_hash_sha3_256_t)) != 0);
    
    log_it(L_INFO, "✓ Hash generation is deterministic");
}

// Test: Address generation with network ID
void test_addr_generation(void) {
    dap_chain_addr_t addr1, addr2;
    
    // Generate address for network 0x01
    unit_test_addr_generate(100, 0x01, &addr1);
    assert(addr1.net_id.uint64 == 0x01);
    
    // Same seed + network = same address
    unit_test_addr_generate(100, 0x01, &addr2);
    assert(memcmp(&addr1, &addr2, sizeof(dap_chain_addr_t)) == 0);
    
    // Different network = different address
    dap_chain_addr_t addr3;
    unit_test_addr_generate(100, 0x02, &addr3);
    assert(addr3.net_id.uint64 == 0x02);
    assert(memcmp(&addr1, &addr3, sizeof(dap_chain_addr_t)) != 0);
    
    log_it(L_INFO, "✓ Address generation works correctly");
}

// Test: Configuration generation
void test_config_generation(void) {
    unit_test_context_t *ctx = unit_test_fixture_init("config_test");
    assert(ctx != NULL);
    
    // Generate config section
    const char *params[] = {
        "key1=value1",
        "key2=value2",
        "number=42",
        NULL
    };
    
    int ret = unit_test_config_generate(ctx, "test_section", params);
    assert(ret == 0);
    assert(ctx->config != NULL);
    
    // Verify config values
    const char *val1 = dap_config_get_item_str(ctx->config, "test_section", "key1");
    assert(val1 && strcmp(val1, "value1") == 0);
    
    const char *val2 = dap_config_get_item_str(ctx->config, "test_section", "key2");
    assert(val2 && strcmp(val2, "value2") == 0);
    
    int num = dap_config_get_item_int32(ctx->config, "test_section", "number");
    assert(num == 42);
    
    unit_test_fixture_cleanup(ctx);
    log_it(L_INFO, "✓ Configuration generation works");
}

// Test: DAP SDK mocking
void test_dap_sdk_mocking(void) {
    unit_test_context_t *ctx = unit_test_fixture_init("mock_test");
    assert(ctx != NULL);
    
    // Enable mocks
    int ret = unit_test_mock_dap_sdk(ctx, true, true, false);
    assert(ret == 0);
    
    assert(ctx->crypto_mocked == true);
    assert(ctx->db_mocked == true);
    assert(ctx->events_mocked == false);
    
    unit_test_fixture_cleanup(ctx);
    log_it(L_INFO, "✓ DAP SDK mocking configured");
}

// Test: Full fixture workflow
void test_full_workflow(void) {
    // 1. Init context
    unit_test_context_t *ctx = unit_test_fixture_init("workflow_test");
    assert(ctx != NULL);
    
    // 2. Generate config
    const char *params[] = {"test_param=test_value", NULL};
    int ret = unit_test_config_generate(ctx, "workflow", params);
    assert(ret == 0);
    
    // 3. Enable mocking
    ret = unit_test_mock_dap_sdk(ctx, true, true, true);
    assert(ret == 0);
    
    // 4. Generate test data
    dap_hash_sha3_256_t hash;
    unit_test_hash_generate(999, &hash);
    
    dap_chain_addr_t addr;
    unit_test_addr_generate(888, 0xFF, &addr);
    
    uint256_t value;
    unit_test_uint256_generate(1000000, &value);
    
    // 5. Test logic would go here
    // ...
    
    // 6. Cleanup
    unit_test_fixture_cleanup(ctx);
    log_it(L_INFO, "✓ Full workflow test passed");
}

// Main test runner
int main(void) {
    log_it(L_INFO, "=== Running Unit Test Fixtures Examples ===");
    
    test_hash_deterministic();
    test_addr_generation();
    test_config_generation();
    test_dap_sdk_mocking();
    test_full_workflow();
    
    log_it(L_INFO, "=== All tests passed ===");
    return 0;
}
