project(libdap-server C)
cmake_minimum_required(VERSION 3.0)

add_subdirectory(http_server)
add_subdirectory(enc_server)
add_subdirectory(udp_server)
