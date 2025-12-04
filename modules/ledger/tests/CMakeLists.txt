cmake_minimum_required(VERSION 3.10)

project(ledger-event-test)

# Source files
file(GLOB DAP_LEDGER_EVENT_TESTS_SRC *.c)

# Create test executable
add_executable(${PROJECT_NAME} ${DAP_LEDGER_EVENT_TESTS_SRC})

# Include directories
target_include_directories(${PROJECT_NAME} 
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

# Link libraries
target_link_libraries(${PROJECT_NAME} 
    PRIVATE 
        dap_test
        dap_sdk 
        cellframe_sdk
)

# Note: Mock framework linker options not needed for this test
# as we test ledger event functions in isolation without calling
# external service verification functions

# Platform-specific libraries
if(DARWIN)
    find_library(BZ2_LIBRARY bz2 REQUIRED)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${BZ2_LIBRARY})
endif()

# Add test to CTest
add_test(
    NAME ledger-event-test
    COMMAND ledger-event-test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Set test properties
set_tests_properties(ledger-event-test 
    PROPERTIES 
    ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib"
    TIMEOUT 60
)

