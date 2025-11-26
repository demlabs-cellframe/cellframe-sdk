cmake_minimum_required(VERSION 3.10)

project(stake_ext-test)

file(GLOB DAP_STAKE_EXT_TESTS_HEADERS include/*.h)
file(GLOB DAP_STAKE_EXT_TESTS_SRC *.c)

add_executable(${PROJECT_NAME} ${DAP_STAKE_EXT_TESTS_SRC} ${DAP_STAKE_EXT_TESTS_HEADERS})

# Use --start-group/--end-group to resolve circular dependencies between static libraries
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

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ../include)

add_test(
    NAME stake_ext-test
    COMMAND stake_ext-test
)
