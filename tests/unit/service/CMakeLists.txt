# Unit tests for service modules
cmake_minimum_required(VERSION 3.10)

project(test_voting_vote)

# Include test helpers and mock autowrap
include(${CMAKE_SOURCE_DIR}/tests/cmake/cellframe_test_helpers.cmake)
include(${CMAKE_SOURCE_DIR}/dap-sdk/module/test/mocks/DAPMockAutoWrap.cmake)

add_executable(${PROJECT_NAME}
    test_voting_vote.c
    $<TARGET_OBJECTS:unit_test_fixtures>
)

# Fixtures headers propagate via unit_test_fixtures OBJECT library

# Link with STATIC versions of modules
# This is REQUIRED for --wrap (Linux) and compile-time redirection (macOS) to work
cellframe_test_link_libraries(${PROJECT_NAME})

# Auto-generate mock functions
# Linux: generates --wrap linker options
# macOS: generates DYLD_INSERT interpose dylib
dap_mock_autowrap(${PROJECT_NAME})

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})

# macOS: Configure DYLD_INSERT_LIBRARIES for test
dap_mock_setup_test_env(${PROJECT_NAME} ${PROJECT_NAME})
