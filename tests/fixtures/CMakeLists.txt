cmake_minimum_required(VERSION 3.10)
project(test_fixtures)

# Test fixtures as OBJECT library
file(GLOB FIXTURES_SRCS *.c)

add_library(${PROJECT_NAME} OBJECT ${FIXTURES_SRCS})

# Link modules - includes will propagate automatically
target_link_libraries(${PROJECT_NAME} PUBLIC
    dap_sdk
    dap_chain
    dap_chain_net
    dap_chain_ledger
    dap_common
)

# Only add current directory for our own headers
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
