cmake_minimum_required(VERSION 3.0)
project(test)

set(CMAKE_C_STANDARD 11)

if(NOT SUBMODULES_NO_BUILD)
    add_subdirectory(libdap-test)
endif()

add_subdirectory(crypto)
add_subdirectory(cert)
