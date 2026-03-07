# Unit tests for service modules
cmake_minimum_required(VERSION 3.10)

# ============================================================================
# DISABLED: test_voting_vote
# ============================================================================
# This test is temporarily disabled due to:
# 1. Linker --wrap limitation - cannot intercept internal library function calls
# 2. Buffer overflow in test case with very long question string
#
# The mocking framework requires the SDK to be linked as OBJECT libraries
# instead of SHARED library for --wrap to work correctly.
# ============================================================================

# project(test_voting_vote)
# include(${CMAKE_SOURCE_DIR}/dap-sdk/module/test/mocks/DAPMockAutoWrap.cmake)
# add_executable(${PROJECT_NAME}
#     test_voting_vote.c
#     $<TARGET_OBJECTS:unit_test_fixtures>
# )
# target_link_libraries(${PROJECT_NAME}
#     dap_test
#     dap_sdk
#     cellframe_sdk
#     dap_chain_net_srv_voting
# )
# dap_mock_autowrap(${PROJECT_NAME})
# target_link_options(${PROJECT_NAME} PRIVATE
#     "-Wl,--wrap=dap_ledger_calc_balance"
#     "-Wl,--wrap=dap_ledger_tx_find_by_hash"
# )
# add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
