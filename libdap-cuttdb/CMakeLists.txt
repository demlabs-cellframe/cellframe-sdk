cmake_minimum_required(VERSION 2.8)

project(dap_cuttdb)

add_definitions ("-D_GNU_SOURCE")
set(CMAKE_C_FLAGS "-std=gnu11 -Wall -Wextra -fPIC")

file(GLOB cuttdb_src src/*.c)
file(GLOB cuttdb_h src/*.h)

# the server part ain't ported, and thus not built, so are tests.
list(FILTER cuttdb_src EXCLUDE REGEX "ae.")
list(FILTER cuttdb_src EXCLUDE REGEX "server.")
list(FILTER cuttdb_src EXCLUDE REGEX "dump.")
list(FILTER cuttdb_src EXCLUDE REGEX "builddb.")
list(FILTER cuttdb_src EXCLUDE REGEX "test_mt.")

if(UNIX)
    list(FILTER cuttdb_src EXCLUDE REGEX "mman.")
    list(FILTER cuttdb_h EXCLUDE REGEX "mman.")
endif()

add_library(${PROJECT_NAME} STATIC ${cuttdb_h} ${cuttdb_src})

set_target_properties(dap_cuttdb PROPERTIES LINKER_LANGUAGE C)

target_link_libraries(${PROJECT_NAME} -lpthread)

target_include_directories(${PROJECT_NAME} INTERFACE src)
