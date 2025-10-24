# Cellframe SDK Test Suite

Comprehensive test suite for Cellframe SDK using DAP SDK test framework.

## Structure

```
tests/
├── CMakeLists.txt          # Main test suite configuration
├── FIXTURES_API.md         # 📚 Complete Fixtures API documentation
├── fixtures/               # Test fixtures and utilities
│   ├── test_ledger_fixtures.[ch]      # Ledger initialization helpers
│   ├── test_token_fixtures.[ch]       # Token creation helpers
│   ├── test_emission_fixtures.[ch]    # 🆕 Emission creation helpers
│   └── test_transaction_fixtures.[ch] # Transaction creation helpers
├── unit/                   # Unit tests
│   ├── utxo_blocking_unit_test.c      # UTXO blocking tests
│   └── CMakeLists.txt
└── integration/            # Integration tests
    └── CMakeLists.txt
```

## Building Tests

Tests are built with the `BUILD_TESTS=On` CMake option:

```bash
cd build
cmake .. -DBUILD_TESTS=On
make
```

## Running Tests

### All tests via CTest:
```bash
cd build
ctest
# or
make test
```

### Individual test:
```bash
cd build
./cellframe-sdk/tests/unit/example_test
```

### With verbose output:
```bash
ctest --verbose
# or
ctest -V
```

## Writing Tests

### Unit Tests

Unit tests use the `dap_test.h` framework from DAP SDK:

```c
#include "dap_test.h"
#include "test_ledger_fixtures.h"

static void test_my_function(void)
{
    dap_print_module_name("My Function");
    
    // Setup
    test_net_fixture_t *fixture = test_net_fixture_create("test");
    
    // Test
    dap_assert(condition, "Test description");
    dap_pass_msg("Test passed");
    
    // Cleanup
    test_net_fixture_destroy(fixture);
}

int main(void)
{
    test_my_function();
    return 0;
}
```

### Available Assertions

- `dap_assert(expr, msg)` - Assert with message, abort on failure
- `dap_assert_PIF(expr, msg)` - Print only if failed (for loops)
- `dap_pass_msg(msg)` - Print success message
- `dap_fail(msg)` - Fail test with message
- `dap_test_msg(...)` - Print debug info during test
- `dap_str_equals(s1, s2)` - String comparison helper

### Test Fixtures

Fixtures are reusable test setups. **See [FIXTURES_API.md](FIXTURES_API.md) for complete API documentation.**

- **Ledger Fixtures**: Network and ledger initialization
- **Token Fixtures**: CF20 token creation with various flags
- **Emission Fixtures**: 🆕 Token emission creation and management
- **Transaction Fixtures**: Transaction creation (mock and real)

Quick example:
```c
// Create network
test_net_fixture_t *net = test_net_fixture_create("mynet");

// Create token WITH emission automatically
dap_chain_hash_fast_t emission_hash;
test_token_fixture_t *token = test_token_fixture_create_with_emission(
    net->ledger, "TEST", "10000.0", "5000.0", &addr, &emission_hash
);

// Create REAL transaction from emission
test_tx_fixture_t *tx = test_tx_fixture_create_from_emission(
    &emission_hash, "TEST", "100.0", &addr_to, token->owner_cert
);

// Add to ledger and test
test_tx_fixture_add_to_ledger(net->ledger, tx);

// Cleanup
test_tx_fixture_destroy(tx);
test_token_fixture_destroy(token);
test_net_fixture_destroy(net);
```

**📚 For detailed API reference and examples, see [FIXTURES_API.md](FIXTURES_API.md)**

## Test Coverage

### Current Status
- ✅ Test infrastructure setup
- ✅ Basic fixtures implemented
- ✅ Example test demonstrating framework
- ⏳ UTXO blocking tests (implementation in progress)

### Planned Tests (UTXO Blocking Feature)

#### Unit Tests:
1. `utxo_blocklist_structures_test.c` - Data structure tests
2. `utxo_blocklist_api_test.c` - API function tests
3. `token_update_utxo_test.c` - Token update integration
4. `ledger_utxo_validation_test.c` - Validation logic tests
5. `cli_utxo_commands_test.c` - CLI command tests

#### Integration Tests:
1. `utxo_blocking_basic_test.c` - Basic lifecycle test
2. `utxo_blocking_static_test.c` - Static flag enforcement
3. `utxo_blocking_mass_test.c` - Mass operations test
4. `utxo_blocking_perf_test.c` - Performance test

## Memory Leak Detection

Run tests with valgrind:

```bash
valgrind --leak-check=full ./cellframe-sdk/tests/unit/example_test
```

## Thread Safety Testing

Run tests with helgrind:

```bash
valgrind --tool=helgrind ./cellframe-sdk/tests/unit/example_test
```

## CI/CD Integration

Tests are designed to integrate with CI/CD pipelines:

```bash
# In CI pipeline:
cmake .. -DBUILD_TESTS=On
make
ctest --output-on-failure
```

## References

- DAP SDK Test Framework: `dap-sdk/test-framework/`
- DAP SDK Examples: `dap-sdk/test-framework/docs/`
- Cellframe SDK Task: `.context/tasks/cf20_token_utxo_blocking_mechanism.json`

