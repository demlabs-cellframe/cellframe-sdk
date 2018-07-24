cmake_minimum_required(VERSION 3.0)

project(crypto-test)

file(GLOB SRC *.h *.c)

add_executable(${PROJECT_NAME} ${SRC})

target_link_libraries(${PROJECT_NAME} dap_test dap_crypto -lm)

add_test(
    NAME crypto-test
    COMMAND crypto-test
)
