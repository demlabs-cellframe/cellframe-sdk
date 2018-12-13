project(libdap-server C)
cmake_minimum_required(VERSION 3.0)

# dependencies #
add_subdirectory(libdap)
add_subdirectory(libdap-server-core)
################

#if(BUILD_LIB_DAP_SERVER_TESTS)
    enable_testing()
    add_subdirectory(test)
#endif()

add_subdirectory(http_server)
add_subdirectory(enc_server)
add_subdirectory(udp_server)
