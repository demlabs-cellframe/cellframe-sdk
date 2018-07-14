cmake_minimum_required(VERSION 3.0)
project(libdap C)

# fix implicit declaration warnings
add_definitions ("-D_GNU_SOURCE")

set(CMAKE_C_FLAGS "-std=c11 -Wall -Wextra")

add_subdirectory(core)
add_subdirectory(crypto)
add_subdirectory(test EXCLUDE_FROM_ALL)
