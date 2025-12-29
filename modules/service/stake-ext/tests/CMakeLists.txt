cmake_minimum_required(VERSION 3.10)

project(stake-ext-test)

# Step 2: Compile all test files but don't call test functions
file(GLOB DAP_STAKE_EXT_TESTS_HEADERS include/*.h)
file(GLOB DAP_STAKE_EXT_TESTS_SRC *.c)

add_executable(${PROJECT_NAME} ${DAP_STAKE_EXT_TESTS_SRC} ${DAP_STAKE_EXT_TESTS_HEADERS})

target_link_libraries(${PROJECT_NAME} 
    PRIVATE
        dap_chain_net_srv_stake_ext
        dap_chain_net_srv
        dap_chain_net
        dap_chain
        dap_chain_common
        dap_test
        dap_core
        dap_crypto
        dap_json-c
)

if (DARWIN)
    target_link_libraries(${PROJECT_NAME} bz2)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ../include)

add_test(
    NAME stake-ext-test
    COMMAND stake-ext-test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

set_tests_properties(stake-ext-test PROPERTIES
    TIMEOUT 60
    LABELS "unit;stake-ext"
    ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib"
)
