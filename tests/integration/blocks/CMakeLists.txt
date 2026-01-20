cmake_minimum_required(VERSION 3.10)

project(blocks-test)

file(GLOB DAP_CHAIN_TESTS_HEADERS include/*.h)
file(GLOB DAP_CHAIN_TESTS_SRC *.c)

add_executable(${PROJECT_NAME} ${DAP_CHAIN_TESTS_SRC} ${DAP_CHAIN_TESTS_HEADERS})

# Only include local test headers - all module includes propagate via linking
target_include_directories(${PROJECT_NAME} PRIVATE 
    include
)

# Link modules - includes propagate automatically
target_link_libraries(${PROJECT_NAME} 
    dap_test        # Test framework
    dap_sdk         # DAP SDK
    cellframe_sdk   # Cellframe SDK (provides all module headers)
)

if (DARWIN)
    target_link_libraries(${PROJECT_NAME} bz2)
endif()

add_test(
    NAME blocks-test
    COMMAND blocks-test
)
