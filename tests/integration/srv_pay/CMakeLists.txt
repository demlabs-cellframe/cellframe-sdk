# Service Payment Integration Tests
#
# Tests for VPN/service payment logic: conditional tx chain following,
# mempool operations, tx validation, and error handling.

cmake_minimum_required(VERSION 3.10)

add_executable(srv_pay_integration_test
    srv_pay_integration_test.c
)

target_include_directories(srv_pay_integration_test PRIVATE 
    ${CELLFRAME_TEST_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../fixtures
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../modules/mempool/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../modules/channel/chain-net-srv/include
)

target_link_libraries(srv_pay_integration_test
    dap_test
    cellframe_test_fixtures
    dap_core
    dap_crypto
    dap_chain
    dap_chain_net
    dap_chain_common
    dap_chain_wallet
    dap_chain_mempool
    dap_chain_cs_dag
    dap_chain_cs_dag_poa
    dap_chain_cs_esbocs
)

add_test(NAME srv_pay_integration COMMAND srv_pay_integration_test)

set_tests_properties(srv_pay_integration PROPERTIES
    TIMEOUT 120
    LABELS "integration;srv_pay;vpn;payment"
)

message(STATUS "Service payment integration tests configured")
