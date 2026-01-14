# Cellframe SDK Test Suite

This directory contains all tests for Cellframe SDK, organized by category and type.

## Structure

```
tests/
├── CMakeLists.txt          # Main test configuration
├── fixtures/               # Common test utilities and fixtures
│   ├── network_fixtures.c  # Network setup helpers
│   ├── ledger_fixtures.c   # Ledger test helpers
│   └── mock_helpers.c      # Custom dap_mock implementations
├── unit/                   # Unit tests for individual modules
│   ├── chain/
│   ├── ledger/
│   ├── datum/
│   ├── net/
│   └── service/
├── integration/            # Integration tests between modules
│   ├── chain/
│   ├── ledger/
│   └── service/
├── performance/            # Performance and TPS tests
└── e2e/                    # End-to-end tests

## Building Tests

```bash
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DBUILD_CELLFRAME_SDK_TESTS=ON
cmake --build . -j4
```

## Running Tests

```bash
# Run all tests
ctest

# Run specific test category
ctest -R unit
ctest -R integration
ctest -R performance

# Run specific test
./tests/unit/ledger/test_ledger_cache
./tests/integration/service/test_stake_ext
```

## Test Guidelines

1. **Unit Tests**: Test individual functions/modules in isolation
   - Use mocks for external dependencies
   - Fast execution (< 1 second per test)
   - No network or filesystem operations

2. **Integration Tests**: Test interaction between modules
   - Can use real dependencies
   - May take longer (< 10 seconds per test)
   - Can use test networks and temporary storage

3. **Performance Tests**: Benchmark and TPS tests
   - Optional by default (enable with `-DENABLE_PERFORMANCE_TESTS=ON`)
   - Focus on throughput and latency metrics

4. **Fixtures**: Reusable test setup code
   - Network initialization
   - Test data generators
   - Custom mocks for complex scenarios

## Writing Tests

All tests use the `dap_test` framework. Example:

```c
#include "dap_test.h"
#include "my_module.h"

void test_my_function(void) {
    dap_print_module_name("test_my_function");
    
    // Setup
    int result = my_function(42);
    
    // Assert
    dap_assert(result == 42, "Expected 42, got %d", result);
    
    dap_pass_msg("Test passed");
}

int main(void) {
    dap_test_msg("Starting my_module tests");
    test_my_function();
    return 0;
}
```

## Removed Test Macros

All `#ifdef TEST_MACRO` blocks have been removed from production code. Test-specific logic now lives in:
- Test files in this directory
- Fixtures for common test setup
- Mock implementations where needed

## Migration Notes

Tests were migrated from `modules/*/tests/` to this centralized structure for:
- Better organization and discoverability
- Separation of test code from production code
- Consistent test infrastructure
- Easier maintenance and CI/CD integration
