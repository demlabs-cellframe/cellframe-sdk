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
    TIMEOUT 120
    LABELS "unit;utxo;blocking"
)

# Service Payment Unit Tests (tx_cond_hash_prev state machine, state/substate enums)
add_executable(srv_pay_unit_test
    srv_pay_unit_test.c
)

target_include_directories(srv_pay_unit_test PRIVATE 
    ${CELLFRAME_TEST_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../modules/net/srv/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../modules/channel/chain-net-srv/include
)

target_link_libraries(srv_pay_unit_test
    dap_test
    dap_core
    dap_crypto
    dap_chain_common
)

add_test(NAME srv_pay_unit COMMAND srv_pay_unit_test)

set_tests_properties(srv_pay_unit PROPERTIES
    TIMEOUT 60
    LABELS "unit;srv_pay;vpn"
)

message(STATUS "Unit tests configured: utxo_blocking_unit_test, srv_pay_unit_test")
