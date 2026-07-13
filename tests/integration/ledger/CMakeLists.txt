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

# Test 3: Anon ledger plain-UTXO orchestrator (I2 / WS-B4)
project(ledger-anon-plain-utxo-test)

add_executable(${PROJECT_NAME}
    test_ledger_anon_plain_utxo.c
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME}
    dap_test
    dap_sdk
    cellframe_sdk
)

add_test(
    NAME ledger-anon-plain-utxo-test
    COMMAND ledger-anon-plain-utxo-test
)

# Test 4: Key Image integrity (I2 / WS-C1/C2)
project(ledger-ki-integrity-test)

add_executable(${PROJECT_NAME}
    test_ki_integrity.c
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME}
    dap_test
    dap_sdk
    cellframe_sdk
)

add_test(
    NAME ledger-ki-integrity-test
    COMMAND ledger-ki-integrity-test
)

# Test 5: Mempool/block verify parity (I2 / WS-B5)
project(ledger-mempool-block-parity-test)

add_executable(${PROJECT_NAME}
    test_mempool_block_verify_parity.c
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME}
    dap_test
    dap_sdk
    cellframe_sdk
)

add_test(
    NAME ledger-mempool-block-parity-test
    COMMAND ledger-mempool-block-parity-test
)
