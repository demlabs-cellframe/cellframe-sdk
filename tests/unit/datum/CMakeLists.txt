cmake_minimum_required(VERSION 3.10)

project(datum-tests)

file(GLOB DAP_CHAIN_TESTS_HEADERS include/*.h)
file(GLOB DAP_CHAIN_TESTS_SRC *.c)

add_executable(${PROJECT_NAME} ${DAP_CHAIN_TESTS_SRC} ${DAP_CHAIN_TESTS_HEADERS})

# Only include local test headers - all module includes propagate via linking
target_include_directories(${PROJECT_NAME} PRIVATE 
    include
)

# Link modules - includes propagate automatically
# Note: Using --start-group to handle potential circular dependencies in legacy code
if(APPLE)
    target_link_libraries(${PROJECT_NAME} 
        dap_test
        dap_sdk 
        cellframe_sdk
    )
else()
    target_link_libraries(${PROJECT_NAME} 
        dap_test
        -Wl,--start-group
        dap_sdk 
        cellframe_sdk
        -Wl,--end-group
    )
endif()

if (DARWIN)
    target_link_libraries(${PROJECT_NAME} bz2)
endif()

add_test(
    NAME datum-tests
    COMMAND datum-tests
)
