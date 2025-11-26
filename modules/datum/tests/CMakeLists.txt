cmake_minimum_required(VERSION 3.10)

project(datum-tests)

file(GLOB DAP_CHAIN_TESTS_HEADERS include/*.h)
file(GLOB DAP_CHAIN_TESTS_SRC *.c)

add_executable(${PROJECT_NAME} ${DAP_CHAIN_TESTS_SRC} ${DAP_CHAIN_TESTS_HEADERS})

# Use --start-group/--end-group to resolve circular dependencies between static libraries
# Explicitly link with DAP SDK modules that are referenced by cellframe_sdk
# but not properly resolved due to build architecture issues
target_link_libraries(${PROJECT_NAME} 
    dap_test
    -Wl,--start-group
    dap_sdk 
    cellframe_sdk
    dap_io
    dap_stream
    dap_stream_ch
    dap_session
    dap_http_server
    dap_client
    dap_sdk
    -Wl,--end-group
)

include_directories(../include)

if (DARWIN)
    target_link_libraries(${PROJECT_NAME} bz2)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC include)

add_test(
    NAME datum-tests
    COMMAND datum-tests
)
