# Integration Tests for Cellframe SDK

# UTXO Blocking Integration Tests
add_executable(utxo_blocking_integration_test
    utxo_blocking_integration_test.c
    utxo_blocking_test_helpers.c
    utxo_blocking_basic_tests.c
    utxo_blocking_arbitrage_tests.c
)

target_include_directories(utxo_blocking_integration_test PRIVATE 
    ${CELLFRAME_TEST_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/../fixtures
)

target_link_libraries(utxo_blocking_integration_test
    dap_test
    cellframe_test_fixtures
    dap_core
    dap_crypto
    dap_chain
    dap_chain_net
    dap_chain_common
    dap_chain_wallet
    dap_chain_cs_dag
    dap_chain_cs_dag_poa
    dap_chain_cs_esbocs
)

# Register with CTest
add_test(NAME utxo_blocking_integration COMMAND utxo_blocking_integration_test)

# Set test properties
set_tests_properties(utxo_blocking_integration PROPERTIES
    TIMEOUT 120
    LABELS "integration;utxo;blocking;ledger"
)

# UTXO Blocking CLI Integration Tests
add_executable(utxo_blocking_cli_integration_test
    utxo_blocking_cli_integration_test.c
    utxo_blocking_test_helpers.c
)

target_include_directories(utxo_blocking_cli_integration_test PRIVATE 
    ${CELLFRAME_TEST_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/../fixtures
)

target_link_libraries(utxo_blocking_cli_integration_test
    dap_test
    cellframe_test_fixtures
    dap_core
    dap_crypto
    dap_chain
    dap_chain_net
    dap_chain_common
    dap_chain_wallet
    dap_chain_cs_dag
    dap_chain_cs_dag_poa
    dap_chain_cs_esbocs
)

# Register with CTest
add_test(NAME utxo_blocking_cli_integration COMMAND utxo_blocking_cli_integration_test)

# Set test properties
set_tests_properties(utxo_blocking_cli_integration PROPERTIES
    TIMEOUT 120
    LABELS "integration;utxo;blocking;cli"
)

# Arbitrage CLI Integration Tests
add_executable(arbitrage_cli_integration_test
    arbitrage_cli_integration_test.c
    utxo_blocking_test_helpers.c
)

target_include_directories(arbitrage_cli_integration_test PRIVATE 
    ${CELLFRAME_TEST_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/../fixtures
)

target_link_libraries(arbitrage_cli_integration_test
    dap_test
    cellframe_test_fixtures
    dap_core
    dap_crypto
    dap_chain
    dap_chain_net
    dap_chain_common
    dap_chain_wallet
    dap_chain_cs_dag
    dap_chain_cs_dag_poa
    dap_chain_cs_esbocs
)

# Register with CTest
add_test(NAME arbitrage_cli_integration COMMAND arbitrage_cli_integration_test)

# Set test properties
set_tests_properties(arbitrage_cli_integration PROPERTIES
    TIMEOUT 120
    LABELS "integration;arbitrage;cli"
)

message(STATUS "Integration tests configured: utxo_blocking_integration_test, utxo_blocking_cli_integration_test, arbitrage_cli_integration_test")
