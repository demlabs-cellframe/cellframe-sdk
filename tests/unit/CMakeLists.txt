# Unit Tests for Cellframe SDK

# UTXO Blocking Unit Tests
add_executable(utxo_blocking_unit_test
    utxo_blocking_unit_test.c
)

target_include_directories(utxo_blocking_unit_test PRIVATE 
    ${CELLFRAME_TEST_INCLUDES}
)

target_link_libraries(utxo_blocking_unit_test
    dap_test
    dap_core
    dap_crypto
    dap_chain_common
)

# Register with CTest
add_test(NAME utxo_blocking_unit COMMAND utxo_blocking_unit_test)

# Set test properties
set_tests_properties(utxo_blocking_unit PROPERTIES
    TIMEOUT 30
    LABELS "unit;utxo;blocking"
)

# DEX Basic Unit Tests
add_executable(dex_basic_unit_test
    dex_basic_unit_test.c
)

target_include_directories(dex_basic_unit_test PRIVATE 
    ${CELLFRAME_TEST_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/../fixtures
    ${CMAKE_CURRENT_SOURCE_DIR}/../../modules/service/dex/include
)

target_link_libraries(dex_basic_unit_test
    dap_test
    cellframe_test_fixtures
    dap_core
    dap_crypto
    dap_chain
    dap_chain_net
    dap_chain_common
    dap_chain_wallet
    dap_chain_net_srv
    dap_stream_ch_chain_net_srv
    dap_chain_cs_dag
    dap_chain_cs_dag_poa
)

# Register with CTest
add_test(NAME dex_basic_unit COMMAND dex_basic_unit_test)

# Set test properties
set_tests_properties(dex_basic_unit PROPERTIES
    TIMEOUT 60
    LABELS "unit;dex;trading"
)

message(STATUS "Unit tests configured: utxo_blocking_unit_test, dex_basic_unit_test")
