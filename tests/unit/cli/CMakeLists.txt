cmake_minimum_required(VERSION 3.10)

# ============================================================================
# CLI Output Unit Tests
# ============================================================================
# Tests for CLI command output formatting (JSON structure, field names, etc.)
#
# These tests verify that CLI commands produce correctly formatted output
# without requiring a running node or network connection.
#
# Uses DAP Mock Framework for function mocking via --wrap linker flag.
# ============================================================================

project(cellframe_sdk_cli_tests C)

message(STATUS "Configuring CLI output unit tests")

# Include DAP Mock AutoWrap module for linker wrapping
include(${CMAKE_SOURCE_DIR}/dap-sdk/module/test/mocks/DAPMockAutoWrap.cmake)

# Include directories
include_directories(
    # Cellframe SDK modules
    ${CMAKE_SOURCE_DIR}/modules/wallet/include
    ${CMAKE_SOURCE_DIR}/modules/wallet/cli
    ${CMAKE_SOURCE_DIR}/modules/ledger/include
    ${CMAKE_SOURCE_DIR}/modules/ledger/cli
    ${CMAKE_SOURCE_DIR}/modules/net/include
    ${CMAKE_SOURCE_DIR}/modules/common/include
    ${CMAKE_SOURCE_DIR}/modules/datum/include
    
    # DAP SDK core
    ${CMAKE_SOURCE_DIR}/dap-sdk/module/core/include
    ${CMAKE_SOURCE_DIR}/dap-sdk/module/json/include
    ${CMAKE_SOURCE_DIR}/dap-sdk/module/crypto/include
    
    # DAP SDK test framework (including mock)
    ${CMAKE_SOURCE_DIR}/dap-sdk/module/test
    ${CMAKE_SOURCE_DIR}/dap-sdk/module/test/include
    
    # DAP SDK CLI server
    ${CMAKE_SOURCE_DIR}/dap-sdk/module/net/server/cli_server/include
    
    # Test fixtures
    ${CMAKE_CURRENT_SOURCE_DIR}/../fixtures
    ${CMAKE_SOURCE_DIR}/dap-sdk/tests/fixtures
)

# Common test dependencies
set(CLI_TEST_LIBS
    dap_test
    dap_sdk
    cellframe_sdk
)

# ============================================================================
# DISABLED: CLI Mocked Tests (wallet, block, dag)
# ============================================================================
# These tests are temporarily disabled because linker --wrap cannot intercept
# internal library function calls. When the test calls a CLI command, the
# command internally calls functions like dap_chain_wallet_create_with_seed_multi
# or dap_chain_net_by_name directly within the cellframe_sdk library,
# bypassing the wrapper functions.
#
# To fix this properly, the SDK would need to be linked as OBJECT libraries
# instead of a SHARED library, or use function pointers for mockable functions.
#
# Disabled tests: cli_wallet_mocked, cli_block_mocked, cli_dag_mocked
# ============================================================================

# add_executable(test_cli_wallet_mocked
#     test_cli_wallet_mocked.c
# )
# target_include_directories(test_cli_wallet_mocked PRIVATE
#     ${CMAKE_CURRENT_BINARY_DIR}/mock_gen/test_cli_wallet_mocked
# )
# target_link_libraries(test_cli_wallet_mocked
#     ${CLI_TEST_LIBS}
# )
# dap_mock_autowrap(test_cli_wallet_mocked)
# add_test(NAME cli_wallet_mocked
#     COMMAND test_cli_wallet_mocked
#     WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
# )

# add_executable(test_cli_block_mocked
#     test_cli_block_mocked.c
# )
# target_include_directories(test_cli_block_mocked PRIVATE
#     ${CMAKE_CURRENT_BINARY_DIR}/mock_gen/test_cli_block_mocked
#     ${CMAKE_SOURCE_DIR}/modules/type/blocks/include
#     ${CMAKE_SOURCE_DIR}/modules/chain/include
# )
# target_link_libraries(test_cli_block_mocked
#     ${CLI_TEST_LIBS}
# )
# dap_mock_autowrap(test_cli_block_mocked)
# add_test(NAME cli_block_mocked
#     COMMAND test_cli_block_mocked
#     WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
# )

# add_executable(test_cli_dag_mocked
#     test_cli_dag_mocked.c
# )
# target_include_directories(test_cli_dag_mocked PRIVATE
#     ${CMAKE_CURRENT_BINARY_DIR}/mock_gen/test_cli_dag_mocked
#     ${CMAKE_SOURCE_DIR}/modules/type/dag/include
#     ${CMAKE_SOURCE_DIR}/modules/chain/include
# )
# target_link_libraries(test_cli_dag_mocked
#     ${CLI_TEST_LIBS}
# )
# dap_mock_autowrap(test_cli_dag_mocked)
# add_test(NAME cli_dag_mocked
#     COMMAND test_cli_dag_mocked
#     WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
# )

# ============================================================================
# DISABLED: Remaining CLI Mocked Tests
# ============================================================================
# Same issue as wallet/block/dag tests - linker --wrap cannot intercept
# internal library function calls.
#
# Disabled tests: cli_xchange_mocked, cli_stake_mocked, cli_token_mocked,
#                 cli_mempool_mocked, cli_ledger_mocked, cli_tx_history_mocked,
#                 cli_global_db_mocked
# ============================================================================

# add_executable(test_cli_xchange_mocked test_cli_xchange_mocked.c)
# target_include_directories(test_cli_xchange_mocked PRIVATE
#     ${CMAKE_CURRENT_BINARY_DIR}/mock_gen/test_cli_xchange_mocked
#     ${CMAKE_SOURCE_DIR}/modules/service/xchange/include
#     ${CMAKE_SOURCE_DIR}/modules/chain/include
#     ${CMAKE_SOURCE_DIR}/modules/wallet/include
# )
# target_link_libraries(test_cli_xchange_mocked ${CLI_TEST_LIBS})
# dap_mock_autowrap(test_cli_xchange_mocked)
# add_test(NAME cli_xchange_mocked COMMAND test_cli_xchange_mocked WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# add_executable(test_cli_stake_mocked test_cli_stake_mocked.c)
# target_include_directories(test_cli_stake_mocked PRIVATE
#     ${CMAKE_CURRENT_BINARY_DIR}/mock_gen/test_cli_stake_mocked
#     ${CMAKE_SOURCE_DIR}/modules/service/stake/include
#     ${CMAKE_SOURCE_DIR}/modules/net/srv/stake/include
#     ${CMAKE_SOURCE_DIR}/modules/chain/include
#     ${CMAKE_SOURCE_DIR}/modules/wallet/include
# )
# target_link_libraries(test_cli_stake_mocked ${CLI_TEST_LIBS})
# dap_mock_autowrap(test_cli_stake_mocked)
# add_test(NAME cli_stake_mocked COMMAND test_cli_stake_mocked WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# add_executable(test_cli_token_mocked test_cli_token_mocked.c)
# target_include_directories(test_cli_token_mocked PRIVATE
#     ${CMAKE_CURRENT_BINARY_DIR}/mock_gen/test_cli_token_mocked
#     ${CMAKE_SOURCE_DIR}/modules/ledger/include
#     ${CMAKE_SOURCE_DIR}/modules/ledger/cli/include
#     ${CMAKE_SOURCE_DIR}/modules/net/tx/include
#     ${CMAKE_SOURCE_DIR}/modules/chain/include
# )
# target_link_libraries(test_cli_token_mocked ${CLI_TEST_LIBS})
# dap_mock_autowrap(test_cli_token_mocked)
# add_test(NAME cli_token_mocked COMMAND test_cli_token_mocked WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# add_executable(test_cli_mempool_mocked test_cli_mempool_mocked.c)
# target_include_directories(test_cli_mempool_mocked PRIVATE
#     ${CMAKE_CURRENT_BINARY_DIR}/mock_gen/test_cli_mempool_mocked
#     ${CMAKE_SOURCE_DIR}/modules/mempool/include
#     ${CMAKE_SOURCE_DIR}/modules/chain/include
# )
# target_link_libraries(test_cli_mempool_mocked ${CLI_TEST_LIBS})
# dap_mock_autowrap(test_cli_mempool_mocked)
# add_test(NAME cli_mempool_mocked COMMAND test_cli_mempool_mocked WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# add_executable(test_cli_ledger_mocked test_cli_ledger_mocked.c)
# target_include_directories(test_cli_ledger_mocked PRIVATE
#     ${CMAKE_CURRENT_BINARY_DIR}/mock_gen/test_cli_ledger_mocked
#     ${CMAKE_SOURCE_DIR}/modules/ledger/include
#     ${CMAKE_SOURCE_DIR}/modules/ledger/cli/include
#     ${CMAKE_SOURCE_DIR}/modules/chain/include
# )
# target_link_libraries(test_cli_ledger_mocked ${CLI_TEST_LIBS})
# dap_mock_autowrap(test_cli_ledger_mocked)
# add_test(NAME cli_ledger_mocked COMMAND test_cli_ledger_mocked WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# add_executable(test_cli_tx_history_mocked test_cli_tx_history_mocked.c)
# target_include_directories(test_cli_tx_history_mocked PRIVATE
#     ${CMAKE_CURRENT_BINARY_DIR}/mock_gen/test_cli_tx_history_mocked
#     ${CMAKE_SOURCE_DIR}/modules/ledger/include
#     ${CMAKE_SOURCE_DIR}/modules/ledger/cli/include
#     ${CMAKE_SOURCE_DIR}/modules/chain/include
# )
# target_link_libraries(test_cli_tx_history_mocked ${CLI_TEST_LIBS})
# dap_mock_autowrap(test_cli_tx_history_mocked)
# add_test(NAME cli_tx_history_mocked COMMAND test_cli_tx_history_mocked WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# add_executable(test_cli_global_db_mocked test_cli_global_db_mocked.c)
# target_include_directories(test_cli_global_db_mocked PRIVATE
#     ${CMAKE_CURRENT_BINARY_DIR}/mock_gen/test_cli_global_db_mocked
#     ${CMAKE_SOURCE_DIR}/dap-sdk/module/global-db/include
#     ${CMAKE_SOURCE_DIR}/dap-sdk/module/global-db/cli/include
# )
# target_link_libraries(test_cli_global_db_mocked ${CLI_TEST_LIBS})
# dap_mock_autowrap(test_cli_global_db_mocked)
# add_test(NAME cli_global_db_mocked COMMAND test_cli_global_db_mocked WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# ============================================================================
# Future tests (uncomment when implemented):
# ============================================================================

# Test: Network CLI Output
# add_executable(test_cli_output_net
#     test_cli_output_net.c
# )
# target_link_libraries(test_cli_output_net ${CLI_TEST_LIBS})
# add_test(NAME cli_output_net COMMAND test_cli_output_net)

message(STATUS "CLI output unit tests configured (all mocked tests disabled due to linker wrap limitation)")
