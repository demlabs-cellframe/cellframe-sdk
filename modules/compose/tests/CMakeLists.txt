cmake_minimum_required(VERSION 3.10)

project(compose-test)

file(GLOB DAP_COMPOSE_TESTS_SRC *.c)

add_executable(${PROJECT_NAME} ${DAP_COMPOSE_TESTS_SRC} ${DAP_COMPOSE_TESTS_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_test dap_core dap_crypto dap_compose)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../dap-sdk/crypto/src/rand)

include_directories(../include)

if (DARWIN)
    target_link_libraries(${PROJECT_NAME} bz2)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC include)

add_test(
    NAME compose-test
    COMMAND compose-test
)
