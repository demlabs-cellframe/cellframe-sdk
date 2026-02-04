# Test Fixtures for Cellframe SDK

## Overview

This directory contains shared test fixtures for Cellframe SDK tests.

## Structure

### 1. **Unit Test Fixtures** (`unit_test_fixtures.[ch]`)

Isolated testing with DAP SDK mocking for pure unit tests.

**Features:**
- Temporary test directories
- Configuration generation
- DAP SDK mocking (crypto, global_db, events)
- Test data generators (hashes, addresses, signatures)
- Isolated from external dependencies

**Usage:**
```c
#include "unit_test_fixtures.h"

void test_my_function(void) {
    // Initialize isolated environment
    unit_test_context_t *ctx = unit_test_fixture_init("my_test");
    assert(ctx != NULL);
    
    // Generate test config
    const char *params[] = {"key1=value1", "key2=value2", NULL};
    unit_test_config_generate(ctx, "my_section", params);
    
    // Mock DAP SDK
    unit_test_mock_dap_sdk(ctx, true, true, false);
    
    // Generate test data
    dap_hash_sha3_256_t hash;
    unit_test_hash_generate(42, &hash);
    
    dap_chain_addr_t addr;
    unit_test_addr_generate(123, 0x01, &addr);
    
    // Run test logic
    // ...
    
    // Cleanup
    unit_test_fixture_cleanup(ctx);
}
```

### 2. **Integration Test Fixtures** (`integration_test_fixtures.[ch]`)

Full stack initialization for integration tests with real components.

**Features:**
- DAP SDK initialization (crypto, db, events)
- Network creation
- Chain creation (DAG/Blocks)
- Ledger initialization
- Test entities (wallets, tokens, emissions)
- Configuration generation
- Optional mocking for non-critical components

**Usage:**
```c
#include "integration_test_fixtures.h"

void test_ledger_integration(void) {
    // Initialize full stack
    integration_test_context_t *ctx = integration_test_fixture_init(
        "ledger_test",
        true,  // init network
        true,  // init chain
        true   // init ledger
    );
    assert(ctx != NULL);
    
    // Create test wallet
    integration_test_create_wallet(ctx, "test_wallet");
    
    // Create test token
    integration_test_create_token(ctx, "TST", 1000000);
    
    // Run integration test
    // ...
    
    // Cleanup
    integration_test_fixture_cleanup(ctx);
}
```

### 3. **Legacy Fixtures** (`test_fixtures.[ch]`)

Basic fixtures (deprecated, use unit/integration fixtures instead).

## Configuration Generation

### Unit Tests
```c
unit_test_context_t *ctx = unit_test_fixture_init("test");

const char *params[] = {
    "param1=value1",
    "param2=value2",
    NULL
};
unit_test_config_generate(ctx, "section_name", params);
```

### Integration Tests
```c
integration_test_context_t *ctx = integration_test_fixture_init(...);

// Automatic config generation with all sections
integration_test_config_generate(ctx);

// Add custom section
const char *custom_params[] = {"custom_key=custom_value", NULL};
integration_test_config_add_section(ctx, "custom_section", custom_params);
```

## Mocking

### Unit Tests (DAP SDK Mocking)

Unit tests use `dap_mock` framework to mock DAP SDK functions:

```c
unit_test_context_t *ctx = unit_test_fixture_init("test");

// Mock crypto, global_db, but not events
unit_test_mock_dap_sdk(ctx, 
    true,   // mock_crypto
    true,   // mock_db
    false   // mock_events
);

// Custom mocks using DAP_MOCK_CUSTOM
DAP_MOCK_CUSTOM(int, dap_enc_key_new, (dap_enc_key_t **a_key)) {
    *a_key = /* mock key */;
    return 0;
}

// Tests run with mocked functions
```

### Integration Tests (Optional Mocking)

Integration tests use real components but can mock non-critical parts:

```c
integration_test_context_t *ctx = integration_test_fixture_init(...);

// Mock network sync state (avoid waiting for real sync)
integration_test_mock_network_sync(ctx, true);

// Mock consensus for faster testing
integration_test_mock_consensus(ctx, "dag-poa");

// Tests run with real components + selective mocking
```

## Test Data Generators

### Unit Tests
```c
// Generate deterministic hash
dap_hash_sha3_256_t hash;
unit_test_hash_generate(42, &hash);  // seed=42

// Generate deterministic address
dap_chain_addr_t addr;
unit_test_addr_generate(123, 0x01, &addr);  // seed=123, net_id=0x01

// Generate mocked signature
dap_sign_t *sign = unit_test_sign_generate(456, data, data_size);

// Generate uint256
uint256_t value;
unit_test_uint256_generate(1000000, &value);
```

### Integration Tests
```c
// Generate real transaction (uses TX Compose API)
dap_chain_datum_tx_t *tx = integration_test_tx_generate(
    ctx,
    &from_addr,
    &to_addr,
    1000,
    "KEL"
);
```

## CMake Integration

Fixtures are automatically linked to tests:

```cmake
# Unit tests
dap_test_unit(
    NAME my_unit_test
    SOURCES my_unit_test.c
    MOCKS dap_enc_key dap_global_db  # DAP SDK mocks
    FIXTURES unit  # Link unit_test_fixtures
)

# Integration tests
dap_test_integration(
    NAME my_integration_test
    SOURCES my_integration_test.c
    FIXTURES integration  # Link integration_test_fixtures
)
```

## Best Practices

1. **Unit Tests:**
   - Use `unit_test_fixtures` for isolated testing
   - Mock ALL external dependencies (DAP SDK)
   - Use deterministic data generators
   - Keep tests fast (<1ms per test)
   - Test ONLY the code under test

2. **Integration Tests:**
   - Use `integration_test_fixtures` for multi-component testing
   - Initialize only needed components
   - Mock only non-critical parts (network sync, consensus)
   - Test interactions between modules
   - Acceptable slower tests (<100ms per test)

3. **Configuration:**
   - Always generate minimal configs for tests
   - Use temporary directories (auto-cleaned)
   - Never rely on system-wide configs

4. **Cleanup:**
   - ALWAYS call cleanup functions
   - Use RAII pattern where possible
   - Fixtures auto-remove temporary directories

## Examples

See:
- `tests/unit/ledger/test_ledger_tx_operations.c` - Unit test example
- `tests/integration/ledger/test_ledger_integration.c` - Integration test example
