cmake_minimum_required(VERSION 3.10)

project(test_ledger_tx_operations)

# Include test helpers and mock autowrap
include(${CMAKE_SOURCE_DIR}/tests/cmake/cellframe_test_helpers.cmake)
include(${CMAKE_SOURCE_DIR}/dap-sdk/module/test/mocks/DAPMockAutoWrap.cmake)

add_executable(${PROJECT_NAME}
    test_ledger_tx_operations.c
)

# Link with STATIC versions of modules
# This is REQUIRED for --wrap (Linux) and compile-time redirection (macOS) to work
cellframe_test_link_libraries(${PROJECT_NAME})

# Set additional includes for custom mock generation
set(ENV{DAP_MOCK_ADDITIONAL_INCLUDES} "#include \"dap_hash.h\"\n#include \"dap_chain_common.h\"\n#include \"dap_chain_datum.h\"\n#include \"dap_chain_datum_tx.h\"\n#include \"dap_chain_ledger.h\"")

# Auto-generate mock functions
# Linux: generates --wrap linker options
# macOS: generates DYLD_INSERT interpose dylib
dap_mock_autowrap(${PROJECT_NAME})

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})

# macOS: Configure DYLD_INSERT_LIBRARIES for test
dap_mock_setup_test_env(${PROJECT_NAME} ${PROJECT_NAME})
