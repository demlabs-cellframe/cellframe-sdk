cmake_minimum_required(VERSION 3.10)

# Ledger integration tests

# Test 1: Ledger Event Tests
project(ledger-event-test)

add_executable(${PROJECT_NAME}
    test_dap_ledger_event.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/tests/fixtures  # ✓ Integration test fixtures
)

target_link_libraries(${PROJECT_NAME}
    dap_test
    dap_sdk
    cellframe_sdk
    test_fixtures
)

add_test(
    NAME ledger-event-test
    COMMAND ledger-event-test
)

# Test 2: Full Ledger Tests (chain/ledger interaction)
project(ledger-integration-test)

add_executable(${PROJECT_NAME}
    dap_chain_ledger_tests.c
    main_ledger.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/tests/fixtures  # ✓ Integration test fixtures
)

target_link_libraries(${PROJECT_NAME}
    dap_test
    dap_sdk
    cellframe_sdk
    test_fixtures
)

add_test(
    NAME ledger-integration-test
    COMMAND ledger-integration-test
)
