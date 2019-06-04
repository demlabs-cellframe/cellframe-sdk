project(libdap-server C)
cmake_minimum_required(VERSION 3.0)

if(NOT (${SUBMODULES_NO_BUILD} MATCHES ON))
    add_subdirectory(libdap)
    add_subdirectory(libdap-crypto)
    add_subdirectory(libdap-server-core)
#    add_subdirectory(libdap-server-udp)
    enable_testing()
    add_subdirectory(test)
endif()

find_package(PkgConfig)
pkg_check_modules(PC_JSON-C REQUIRED json-c)

add_subdirectory(http_server)
add_subdirectory(enc_server)
