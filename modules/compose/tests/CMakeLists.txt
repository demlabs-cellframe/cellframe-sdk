cmake_minimum_required(VERSION 3.10)

project(compose-test)

file(GLOB DAP_COMPOSE_TESTS_SRC *.c)

add_executable(${PROJECT_NAME} ${DAP_COMPOSE_TESTS_SRC})

# Include directories
target_include_directories(${PROJECT_NAME} 
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

# Link libraries
target_link_libraries(${PROJECT_NAME} 
    PRIVATE
        dap_test
        dap_core
        dap_crypto
        dap_compose
)

if(DARWIN)
    find_library(BZ2_LIBRARY bz2 REQUIRED)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${BZ2_LIBRARY})
endif()

# Add test
add_test(
    NAME compose-test
    COMMAND compose-test
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Set test properties
set_tests_properties(compose-test 
    PROPERTIES 
    ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib"
)
