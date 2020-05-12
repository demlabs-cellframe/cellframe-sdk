cmake_minimum_required(VERSION 3.1)

project(dap_cuttdb C)

add_definitions ("-D_GNU_SOURCE")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

file(GLOB cuttdb_src src/*.c)
file(GLOB cuttdb_h src/*.h)

# the server part ain't ported, and thus not built, so are tests.
list(FILTER cuttdb_src EXCLUDE REGEX "ae_")
list(FILTER cuttdb_h EXCLUDE REGEX "ae_")
list(FILTER cuttdb_src EXCLUDE REGEX "server.")
list(FILTER cuttdb_h EXCLUDE REGEX "server.")
list(FILTER cuttdb_src EXCLUDE REGEX "dump.")
list(FILTER cuttdb_h EXCLUDE REGEX "dump.")
list(FILTER cuttdb_src EXCLUDE REGEX "builddb.")
list(FILTER cuttdb_h EXCLUDE REGEX "builddb.")
list(FILTER cuttdb_src EXCLUDE REGEX "test_mt.")
list(FILTER cuttdb_h EXCLUDE REGEX "test_mt.")

if(UNIX)
   list(FILTER cuttdb_src EXCLUDE REGEX "mman.")
   list(FILTER cuttdb_h EXCLUDE REGEX "mman.")
endif()

add_library(${PROJECT_NAME} STATIC ${cuttdb_src} ${cuttdb_h})
set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE C)
set_target_properties(${PROJECT_NAME} PROPERTIES COMPILER_LANGUAGE C)

set_target_properties(dap_cuttdb PROPERTIES LINKER_LANGUAGE C)

target_link_libraries(${PROJECT_NAME})

target_include_directories(${PROJECT_NAME} INTERFACE src)
