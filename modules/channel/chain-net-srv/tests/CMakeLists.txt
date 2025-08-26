cmake_minimum_required(VERSION 3.10)

project(dap_stream_ch_chain_net_srv_tests)

# Include headers from different test categories
file(GLOB DAP_BILLING_TESTS_HEADERS 
    include/*.h
    test_framework/*.h
)

# Source files for different test categories
file(GLOB DAP_BILLING_TESTS_SRC 
    *.c
    tests_fast/*.c
)

add_executable(${PROJECT_NAME} ${DAP_BILLING_TESTS_SRC} ${DAP_BILLING_TESTS_HEADERS})

# Link required libraries
target_link_libraries(${PROJECT_NAME} 
    dap_core 
    dap_stream_ch_chain_net_srv
    dap_chain
    dap_chain_net
)

if (DARWIN)
    target_link_libraries(${PROJECT_NAME} bz2)
endif()

# Include directories
target_include_directories(${PROJECT_NAME} PUBLIC 
    include
    test_framework
    ../include
    ../../../../dap-sdk/core/include
    ../../../../dap-sdk/test-framework
    ../../../../cellframe-sdk/modules/net/srv/include
)

# Add test to CTest
add_test(
    NAME dap_stream_ch_chain_net_srv_tests
    COMMAND dap_stream_ch_chain_net_srv_tests
)