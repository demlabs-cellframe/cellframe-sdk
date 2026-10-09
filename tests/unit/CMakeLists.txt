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

# CLI Backpressure Unit Tests (RPC overload hardening, see
# cellframe_node_rpc_overload_research_2026_09 / hotfix-performance-Sept-2026-0)
add_executable(cli_backpressure_unit_test
    cli_backpressure_unit_test.c
)

target_include_directories(cli_backpressure_unit_test PRIVATE
    ${CELLFRAME_TEST_INCLUDES}
)

target_link_libraries(cli_backpressure_unit_test
    dap_test
    dap_core
    dap_cli_server
)

add_test(NAME cli_backpressure_unit COMMAND cli_backpressure_unit_test)

set_tests_properties(cli_backpressure_unit PROPERTIES
    TIMEOUT 60
    LABELS "unit;cli;backpressure;rpc-overload"
)

# Mempool Spent-Outs Index Unit Tests (Stage B1, RPC overload hardening, see
# cellframe_node_rpc_overload_research_2026_09 / hotfix-performance-Sept-2026-0)
add_executable(mempool_spent_index_unit_test
    mempool_spent_index_unit_test.c
)

target_include_directories(mempool_spent_index_unit_test PRIVATE
    ${CELLFRAME_TEST_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/../fixtures
)

target_link_libraries(mempool_spent_index_unit_test
    dap_test
    cellframe_test_fixtures
    dap_core
    dap_crypto
    dap_chain
    dap_chain_net
    dap_chain_common
    dap_chain_mempool
    dap_chain_cs_dag
    dap_chain_cs_dag_poa
    dap_chain_cs_none
)

add_test(NAME mempool_spent_index_unit COMMAND mempool_spent_index_unit_test)

set_tests_properties(mempool_spent_index_unit PROPERTIES
    TIMEOUT 120
    LABELS "unit;mempool;rpc-overload"
)

message(STATUS "Unit tests configured: utxo_blocking_unit_test, cli_backpressure_unit_test, mempool_spent_index_unit_test, dex_basic_unit_test")

# Standalone plain-HTTP JSON-RPC service ([rpc-server]): the access-control
# and command-index decisions, which are pure functions.
add_executable(rpc_service_unit_test
    rpc_service_unit_test.c
)

target_include_directories(rpc_service_unit_test PRIVATE
    ${CELLFRAME_TEST_INCLUDES}
)

target_link_libraries(rpc_service_unit_test
    dap_test
    dap_core
    dap_crypto
    dap_cli_server
    dap_json_rpc
)

add_test(NAME rpc_service_unit COMMAND rpc_service_unit_test)

set_tests_properties(rpc_service_unit PROPERTIES
    TIMEOUT 60
    LABELS "unit;rpc;rpc-server"
)

# Microbenchmark of the shared command executor (CLI-server stage): prints us/request,
# keeps a regression signal on the executor overhead. Not an assertion test.
add_executable(rpc_executor_bench
    rpc_executor_bench.c
)

target_include_directories(rpc_executor_bench PRIVATE
    ${CELLFRAME_TEST_INCLUDES}
)

target_link_libraries(rpc_executor_bench
    dap_test
    dap_core
    dap_cli_server
)

add_test(NAME rpc_executor_bench COMMAND rpc_executor_bench)

set_tests_properties(rpc_executor_bench PROPERTIES
    TIMEOUT 60
    LABELS "bench;rpc;executor"
)
