cmake_minimum_required(VERSION 3.0)
project(udp-server-test)

set(CMAKE_C_STANDARD 11)

add_subdirectory(libdap-test)

file(GLOB SRC *.h *.c)

add_executable(${PROJECT_NAME} ${SRC})

target_link_libraries(${PROJECT_NAME} dap_test)

add_test(
    NAME udp-server-test
    COMMAND udp-server-test
)

