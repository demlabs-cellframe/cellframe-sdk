cmake_minimum_required(VERSION 3.0)
project(libdap C)

# fix implicit declaration warnings
add_definitions ("-D_GNU_SOURCE")

set(CMAKE_C_FLAGS "-std=c11 -Wall -Wextra")

if(UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif()

if(APPLE)
    set(DARWIN TRUE)
endif()

if(BUILD_DAP_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

add_subdirectory(core)
add_subdirectory(crypto)
