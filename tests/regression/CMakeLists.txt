# Regression Tests for Cellframe SDK

# Arbitrage Bugs Regression Test
add_executable(test_bug_arbitrage
    test_bug_arbitrage.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../integration/utxo_blocking_test_helpers.c
)

target_include_directories(test_bug_arbitrage PRIVATE 
    ${CELLFRAME_TEST_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/../fixtures
    ${CMAKE_CURRENT_SOURCE_DIR}/../integration
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
add_test(NAME regression_arbitrage COMMAND test_bug_arbitrage)

# Set test properties
set_tests_properties(regression_arbitrage PROPERTIES
    TIMEOUT 120
    LABELS "regression;arbitrage;cli"
)

