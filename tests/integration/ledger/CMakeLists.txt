cmake_minimum_required(VERSION 3.10)

# Ledger integration tests

# Test 1: Ledger Event Tests
project(ledger-event-test)

add_executable(${PROJECT_NAME}
    test_dap_ledger_event.c
    $<TARGET_OBJECTS:test_fixtures>
)

# Only include local test headers - fixtures/modules propagate via OBJECT lib
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link modules - includes propagate automatically
target_link_libraries(${PROJECT_NAME}
    dap_test        # Test framework
    dap_sdk         # DAP SDK
    cellframe_sdk   # Cellframe SDK (provides all module headers)
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
    $<TARGET_OBJECTS:test_fixtures>
)

# Only include local test headers - fixtures/modules propagate via OBJECT lib
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link modules - includes propagate automatically
target_link_libraries(${PROJECT_NAME}
    dap_test        # Test framework
    dap_sdk         # DAP SDK
    cellframe_sdk   # Cellframe SDK (provides all module headers)
)

add_test(
    NAME ledger-integration-test
    COMMAND ledger-integration-test
)
