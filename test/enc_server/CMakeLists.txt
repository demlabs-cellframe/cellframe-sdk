cmake_minimum_required(VERSION 3.0)

project(enc_server_test)

file(GLOB SRC *.h *.c)

add_executable(${PROJECT_NAME} ${SRC})

target_link_libraries(${PROJECT_NAME} dap_test dap_core dap_enc_server)

add_test(
    NAME ${PROJECT_NAME}
    COMMAND ${PROJECT_NAME}
)
