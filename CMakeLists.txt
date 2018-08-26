cmake_minimum_required(VERSION 3.0)
project(libdap C)

# fix implicit declaration warnings
add_definitions ("-D_GNU_SOURCE")

set(CMAKE_C_FLAGS "-std=c11 -Wall -Wextra")

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test/libdap-test/CMakeLists.txt")
    enable_testing()
    add_subdirectory(test)
endif()

add_subdirectory(core)
add_subdirectory(crypto)
