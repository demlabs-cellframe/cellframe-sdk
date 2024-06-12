cmake_minimum_required(VERSION 3.10)

project(blocks-test)

file(GLOB DAP_CHAIN_TESTS_HEADERS include/*.h)
file(GLOB DAP_CHAIN_TESTS_SRC *.c)

add_executable(${PROJECT_NAME} ${DAP_CHAIN_TESTS_SRC} ${DAP_CHAIN_TESTS_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_test dap_core dap_chain dap_chain_cs_blocks )

if (DARWIN)
    target_link_libraries(${PROJECT_NAME} bz2)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC include)

add_test(
    NAME blocks-test
    COMMAND blocks-test
)
