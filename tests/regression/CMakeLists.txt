# Regression Tests for Cellframe SDK

# Arbitrage Bugs Regression Test
add_executable(test_bug_arbitrage
    test_bug_arbitrage.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../integration/utxo_blocking/utxo_blocking_test_helpers.c
)

target_include_directories(test_bug_arbitrage PRIVATE 
    ${CELLFRAME_TEST_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/../fixtures
    ${CMAKE_CURRENT_SOURCE_DIR}/../integration/utxo_blocking
)

target_link_libraries(test_bug_arbitrage
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
add_test(NAME regression_19886 COMMAND test_bug_arbitrage)

# Set test properties
set_tests_properties(regression_19886 PROPERTIES
    TIMEOUT 120
    LABELS "regression;arbitrage;cli;bug_19886"
)

# Bug #20138 Regression Test
add_executable(test_bug_20138
    test_bug_20138.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../integration/utxo_blocking/utxo_blocking_test_helpers.c
)

target_include_directories(test_bug_20138 PRIVATE 
    ${CELLFRAME_TEST_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/../fixtures
    ${CMAKE_CURRENT_SOURCE_DIR}/../integration/utxo_blocking
)

target_link_libraries(test_bug_20138
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

add_test(NAME regression_bug_20138 COMMAND test_bug_20138)

set_tests_properties(regression_bug_20138 PROPERTIES
    TIMEOUT 120
    LABELS "regression;arbitrage;bug_20138"
)

# Bug #20273 Regression Test
add_executable(test_bug_20273
    test_bug_20273.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../integration/utxo_blocking/utxo_blocking_test_helpers.c
)

target_include_directories(test_bug_20273 PRIVATE 
    ${CELLFRAME_TEST_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/../fixtures
    ${CMAKE_CURRENT_SOURCE_DIR}/../integration/utxo_blocking
)

target_link_libraries(test_bug_20273
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

add_test(NAME regression_bug_20273 COMMAND test_bug_20273)

set_tests_properties(regression_bug_20273 PROPERTIES
    TIMEOUT 120
    LABELS "regression;arbitrage;bug_20273"
)

