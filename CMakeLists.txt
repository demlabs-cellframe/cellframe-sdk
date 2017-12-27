project(libdap C)
cmake_minimum_required(VERSION 2.8)

add_subdirectory(core)
add_subdirectory(crypt)
add_subdirectory(client)
add_subdirectory(http)

include_directories("${INCLUDE_DIRECTORIES} ${dapcrypt_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapcore_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${daphttp_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapclient_INCLUDE_DIRS}")
