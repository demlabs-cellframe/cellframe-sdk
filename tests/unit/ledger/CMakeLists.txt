cmake_minimum_required(VERSION 3.10)

project(test_ledger_tx_operations)

# Include DAP Mock AutoWrap module
include(${CMAKE_SOURCE_DIR}/dap-sdk/module/test/mocks/DAPMockAutoWrap.cmake)

add_executable(${PROJECT_NAME}
    test_ledger_tx_operations.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(${PROJECT_NAME}
    cellframe_sdk
    dap_sdk
    dap_test
    dap_chain_ledger  # Explicitly link for header propagation
)

# Auto-generate and apply --wrap flags from DAP_MOCK_DECLARE() and DAP_MOCK_CUSTOM() calls
dap_mock_autowrap(${PROJECT_NAME})

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
