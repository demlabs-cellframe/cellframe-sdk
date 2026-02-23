# UTXO Blocking Integration Tests
#
# Tests for UTXO blocking/locking functionality in ledger.

cmake_minimum_required(VERSION 3.10)

# UTXO Blocking Integration Test
add_executable(utxo_blocking_integration_test
    utxo_blocking_integration_test.c
)

target_include_directories(utxo_blocking_integration_test PRIVATE 
    ${CELLFRAME_TEST_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../fixtures
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

add_test(NAME utxo_blocking_integration COMMAND utxo_blocking_integration_test)

set_tests_properties(utxo_blocking_integration PROPERTIES
    TIMEOUT 120
    LABELS "integration;utxo;blocking;ledger"
)

# UTXO Blocking CLI Integration Test
add_executable(utxo_blocking_cli_integration_test
    utxo_blocking_cli_integration_test.c
)

target_include_directories(utxo_blocking_cli_integration_test PRIVATE 
    ${CELLFRAME_TEST_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../fixtures
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

add_test(NAME utxo_blocking_cli_integration COMMAND utxo_blocking_cli_integration_test)

set_tests_properties(utxo_blocking_cli_integration PROPERTIES
    TIMEOUT 120
    LABELS "integration;utxo;blocking;cli"
)

message(STATUS "UTXO blocking integration tests configured")

