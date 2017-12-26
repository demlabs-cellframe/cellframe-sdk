cmake_minimum_required(VERSION 2.8)
project (dapsession)
  
set(SESSION_SRCS stream_session.c)
include_directories("${INCLUDE_DIRECTORIES} ${dapcore_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapcrypt_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapauth_INCLUDE_DIRS}")
#include_directories("${INCLUDE_DIRECTORIES} ${dapstream_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapsession_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${daphttp_INCLUDE_DIRS}")
add_definitions ("${dapcore_DEFINITIONS}")
add_definitions ("${dapcrypt_DEFINITIONS}")
add_definitions ("${dapauth_DEFINITIONS}")
add_definitions ("${daphttp_DEFINITIONS}")
#add_definitions ("${dapstream_DEFINITIONS}")
add_definitions ("${dapsession_DEFINITIONS}")
add_library(${PROJECT_NAME} STATIC ${SESSION_SRCS})


set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
