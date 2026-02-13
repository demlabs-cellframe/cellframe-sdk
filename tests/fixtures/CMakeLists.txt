# Test Fixtures Libraries
cmake_minimum_required(VERSION 3.10)

# Include DAP Mock AutoWrap module (Cellframe SDK shim)
include(${CMAKE_SOURCE_DIR}/dap-sdk/module/test/mocks/DAPMockAutoWrap.cmake)

# Unit Test Fixtures (for unit tests with DAP SDK mocking)
project(unit_test_fixtures)

add_library(${PROJECT_NAME} OBJECT
    unit_test_fixtures.c
)

# Only expose fixture headers directory - all others propagate via modules
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link modules - includes propagate automatically
target_link_libraries(${PROJECT_NAME} PUBLIC
    dap_test        # Test framework (dap_mock) - separate from dap_sdk
    dap_sdk         # DAP SDK (core, crypto, common, etc.)
    cellframe_sdk   # Cellframe SDK (chain/ledger/net/consensus)
)

# Apply dap_mock auto-wrapping for DAP SDK functions
dap_mock_autowrap(${PROJECT_NAME})

# Integration Test Fixtures (for integration tests with full stack)
project(test_fixtures)

add_library(${PROJECT_NAME} OBJECT
    integration_test_fixtures.c
    test_fixtures.c
)

# Only expose fixture headers directory - all others propagate via modules
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link modules - includes propagate automatically
target_link_libraries(${PROJECT_NAME} PUBLIC
    dap_sdk         # DAP SDK (includes core, crypto, common, etc.)
    cellframe_sdk   # Cellframe SDK (includes chain/ledger/net/wallet/datum)
)
