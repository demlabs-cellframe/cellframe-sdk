# Unit tests for service modules
cmake_minimum_required(VERSION 3.10)

project(test_voting_vote)

# Include DAP Mock AutoWrap module
include(${CMAKE_SOURCE_DIR}/dap-sdk/module/test/mocks/DAPMockAutoWrap.cmake)

add_executable(${PROJECT_NAME}
    test_voting_vote.c
    $<TARGET_OBJECTS:unit_test_fixtures>
)

# Fixtures headers propagate via unit_test_fixtures OBJECT library
# All other includes propagate via linked modules below

# Link modules - includes propagate automatically
target_link_libraries(${PROJECT_NAME}
    dap_test                      # Test framework
    dap_sdk                       # DAP SDK
    cellframe_sdk                 # Cellframe SDK (provides all module headers)
    dap_chain_net_srv_voting      # Voting service module
)

# Manually add --wrap for ledger functions (avoid accessing uninit _internal in mock ledger)
target_link_options(${PROJECT_NAME} PRIVATE
    "-Wl,--wrap=dap_ledger_calc_balance"
    "-Wl,--wrap=dap_ledger_tx_find_by_hash"
)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
