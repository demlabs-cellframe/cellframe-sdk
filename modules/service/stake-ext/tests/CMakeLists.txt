cmake_minimum_required(VERSION 3.10)

project(stake_ext-test)

file(GLOB DAP_STAKE_EXT_TESTS_HEADERS include/*.h)
file(GLOB DAP_STAKE_EXT_TESTS_SRC *.c)

add_executable(${PROJECT_NAME} ${DAP_STAKE_EXT_TESTS_SRC} ${DAP_STAKE_EXT_TESTS_HEADERS})

target_link_libraries(${PROJECT_NAME} cellframe_sdk dap_sdk dap_test)

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ../include)

add_test(
    NAME stake_ext-test
    COMMAND stake_ext-test
)
