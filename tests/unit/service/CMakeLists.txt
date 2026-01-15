# Unit tests for service modules
cmake_minimum_required(VERSION 3.10)

project(test_voting_vote)

# Include DAP Mock AutoWrap module
include(${CMAKE_SOURCE_DIR}/dap-sdk/module/test/mocks/DAPMockAutoWrap.cmake)

add_executable(${PROJECT_NAME}
    test_voting_vote.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/tests/fixtures  # ← Unit test fixtures
)

target_link_libraries(${PROJECT_NAME}
    cellframe_sdk
    dap_sdk
    dap_test
    dap_chain_net_srv_voting
    unit_test_fixtures  # ← Link unit test fixtures
)

# Auto-generate and apply --wrap flags from DAP_MOCK_DECLARE() calls
# NOTE: Disabled for now - this test uses integration-style testing with DAP SDK isolation
# dap_mock_autowrap(${PROJECT_NAME})

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
