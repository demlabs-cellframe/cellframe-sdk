cmake_minimum_required(VERSION 3.0)
project(test)

set(CMAKE_C_STANDARD 11)

add_subdirectory(libdap-test)

add_subdirectory(enc_server)
add_subdirectory(http_server)

