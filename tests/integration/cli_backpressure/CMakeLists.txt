# CLI Backpressure / Dead-Client Integration Tests
#
# Exercises the CLI/RPC backpressure gate and dead-client check through a
# real dap_cli_server_init()'d unix-socket server, complementing
# cellframe-sdk/tests/unit/cli_backpressure_unit_test.c which covers the
# same mechanisms' pure logic without a live socket.

cmake_minimum_required(VERSION 3.10)

add_executable(cli_backpressure_integration_test
    cli_backpressure_integration_test.c
)

target_include_directories(cli_backpressure_integration_test PRIVATE
    ${CELLFRAME_TEST_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../fixtures
)

target_link_libraries(cli_backpressure_integration_test
    dap_test
    cellframe_test_fixtures
    dap_core
    dap_cli_server
    pthread
)

add_test(NAME cli_backpressure_integration COMMAND cli_backpressure_integration_test)

set_tests_properties(cli_backpressure_integration PROPERTIES
    TIMEOUT 60
    LABELS "integration;cli;backpressure;rpc-overload"
)

message(STATUS "CLI backpressure/dead-client integration test configured")
