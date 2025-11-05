# DAP Ledger Event Unit Tests

## Overview

This directory contains comprehensive unit tests for the DAP Ledger Event module (`dap_chain_ledger_event.c`), implemented using the DAP SDK MOCK framework.

## Test Coverage

### Tested Functions

1. **Event Notification System**
   - `dap_ledger_event_notify_add()` - Add notification callbacks
   - Notification triggering on event add/remove operations

2. **Event Management**
   - `dap_ledger_event_find()` - Find events by transaction hash
   - `dap_ledger_event_get_list()` - Get list of events (all or filtered by group)
   - `dap_ledger_event_get_list_ex()` - Get list with lock control
   - `dap_ledger_pvt_event_remove()` - Remove events from ledger

3. **Public Key Management**
   - `dap_ledger_event_pkey_check()` - Check if public key is allowed
   - `dap_ledger_event_pkey_add()` - Add public key to allowed list
   - `dap_ledger_event_pkey_rm()` - Remove public key from allowed list
   - `dap_ledger_event_pkey_list()` - Get list of allowed public keys

4. **Event Aggregation**
   - `dap_ledger_events_aggregate()` - Aggregate events for hardfork

### Test Features

- ✅ Full API coverage of all public functions
- ✅ Mock framework integration for service verificator and decree functions
- ✅ Thread safety tests with concurrent operations
- ✅ NULL parameter validation
- ✅ Edge case handling (empty lists, non-existing items)
- ✅ Notification callback verification
- ✅ Memory management validation

## Building and Running Tests

### Prerequisites

- CMake 3.10 or higher
- GCC with GNU11 support
- DAP SDK with test framework and mock support
- Cellframe SDK

### Build Configuration

Tests are integrated into the CMake build system and can be enabled with:

```bash
cmake .. -DBUILD_CELLFRAME_SDK_TESTS=ON
make ledger-event-test
```

### Running Tests

#### Via CTest

```bash
cd build
ctest -R ledger-event-test -V
```

#### Direct Execution

```bash
cd build/cellframe-sdk/modules/ledger/tests
./ledger-event-test
```

### Expected Output

```
=== DAP Ledger Event Unit Tests ===
Testing all ledger event functions...

Ledger Event Notification System passing the tests...
        Event notification callback added PASS.
        Event notification callback triggered PASS.
        
Ledger Event Finding passing the tests...
        Event found by hash PASS.
        Non-existing event returns NULL PASS.
        
...

=== All Ledger Event Tests PASSED! ===
Total: 14 test functions
Coverage: All public API functions tested
```

## Test Structure

### Main Test File

- `test_dap_ledger_event.c` - Main test suite with all test cases

### Test Organization

1. **Test Fixtures** - Setup and teardown functions for each test
2. **Mock Declarations** - Mock functions for external dependencies
3. **Helper Functions** - Utility functions for test data creation
4. **Test Cases** - Individual test functions grouped by functionality
5. **Main Suite** - Test runner with initialization and cleanup

## Mock Framework Usage

### Mocked Functions

The following external functions are mocked to isolate ledger event logic:

- `dap_chain_srv_event_verify()` - Service verificator
- `dap_chain_srv_decree()` - Decree handler  
- `dap_chain_datum_tx_verify_sign()` - Transaction signature verification

### Mock Configuration

```c
// Default success behavior
DAP_MOCK_DECLARE(dap_chain_srv_event_verify, {
    .return_value.i = 0
});

// Custom behavior can be set per test:
DAP_MOCK_SET_RETURN(dap_chain_srv_event_verify, (void*)(intptr_t)-1);
```

## Extending Tests

To add new test cases:

1. Create a new test function:
```c
static void test_new_feature(void)
{
    setup_test();
    
    // Test code here
    dap_assert(condition, "Test description");
    
    teardown_test();
}
```

2. Add to main test suite:
```c
int main(int argc, char **argv)
{
    // ... initialization ...
    
    test_new_feature();  // Add here
    
    // ... cleanup ...
}
```

## Debugging Tests

### Enable Verbose Logging

```c
// In test file, before tests:
dap_log_level_set(L_DEBUG);
```

### Run Under GDB

```bash
gdb ./ledger-event-test
(gdb) run
```

### Memory Leak Detection

```bash
valgrind --leak-check=full ./ledger-event-test
```

## Integration with CI/CD

Tests are automatically discovered by CTest and can be integrated into CI/CD pipelines:

```yaml
# .gitlab-ci.yml example
test:
  script:
    - mkdir build && cd build
    - cmake .. -DBUILD_CELLFRAME_SDK_TESTS=ON
    - make
    - ctest --output-on-failure
```

## Standards Compliance

This test suite follows СЛК (Smart Layered Context) standards:

- ✅ All tests integrated into CMake build system
- ✅ NO standalone test executables
- ✅ Tests discoverable via `make test` / `ctest`
- ✅ Code comments in English only
- ✅ Doxygen-style documentation
- ✅ Mock framework for external dependencies
- ✅ Thread safety testing included

## Contact

For questions or issues with these tests, please refer to:
- Main project repository
- СЛК documentation
- DAP SDK test framework documentation

