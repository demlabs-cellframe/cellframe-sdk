project(libdap-server C)
cmake_minimum_required(VERSION 3.0)

# dependencies #
if(NOT ${SUBMODULES_NO_BUILD} MATCHES ON)
    add_subdirectory(libdap)
    add_subdirectory(libdap-server-core)
    add_subdirectory(libdap-server-udp)
endif()
################


if(BUILD_LIB_DAP_SERVER_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

add_subdirectory(http_server)
add_subdirectory(enc_server)
