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

# Service-order signature verification (policy rule 0xD): the order body is
# node-local and its embedded signature is the only binding to its author.
add_executable(order_signature_unit_test
    order_signature_unit_test.c
)

target_include_directories(order_signature_unit_test PRIVATE
    ${CELLFRAME_TEST_INCLUDES}
)

target_link_libraries(order_signature_unit_test
    dap_test
    dap_core
    dap_crypto
    dap_chain_common
    dap_chain_net
)

add_test(NAME order_signature_unit COMMAND order_signature_unit_test)

set_tests_properties(order_signature_unit PROPERTIES
    TIMEOUT 60
    LABELS "unit;order;signature"
)

# Xchange service-fee contract: get_fee() must leave its out-parameters defined
# even when no fee is configured (a caller read the address unconditionally and
# compared uninitialized stack bytes - see xchange_fee_contract_test.c).
add_executable(xchange_fee_contract_test
    xchange_fee_contract_test.c
)

target_include_directories(xchange_fee_contract_test PRIVATE
    ${CELLFRAME_TEST_INCLUDES}
    ${CMAKE_SOURCE_DIR}/modules/service/xchange/include
)

target_link_libraries(xchange_fee_contract_test
    dap_test
    dap_core
    dap_chain_common
    dap_chain_net_srv_xchange
)

add_test(NAME xchange_fee_contract COMMAND xchange_fee_contract_test)

set_tests_properties(xchange_fee_contract PROPERTIES
    TIMEOUT 60
    LABELS "unit;xchange;regression"
)

# Chain-state KV: deleting a key and writing it again must not touch freed memory.
# The delete unlinked both uthash tables through one handle, so the by-name table
# kept a pointer to the freed entry and the next write to that name corrupted the
# heap (it crashed the DEX integration test - see chain_state_kv_uaf_test.c).
add_executable(chain_state_kv_uaf_test
    chain_state_kv_uaf_test.c
)

target_include_directories(chain_state_kv_uaf_test PRIVATE
    ${CELLFRAME_TEST_INCLUDES}
    ${CMAKE_SOURCE_DIR}/modules/chain/include
)

target_link_libraries(chain_state_kv_uaf_test
    dap_test
    dap_core
    dap_chain_common
    dap_chain
)

add_test(NAME chain_state_kv_uaf COMMAND chain_state_kv_uaf_test)

set_tests_properties(chain_state_kv_uaf PROPERTIES
    TIMEOUT 60
    LABELS "unit;state;regression"
)
