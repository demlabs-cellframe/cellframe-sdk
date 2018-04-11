project(libdap-server C)
cmake_minimum_required(VERSION 2.8)

add_subdirectory(core_server)
add_subdirectory(http_server)
add_subdirectory(enc_server)
add_subdirectory(udp_server)

