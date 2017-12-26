cmake_minimum_required(VERSION 2.8)
project (dapserverenc)
  
set(SERVERENC_SRCS  enc_http.c  enc_ks.c )

include_directories("${INCLUDE_DIRECTORIES} ${dapcore_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapcrypt_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${daphttp_INCLUDE_DIRS}")

add_definitions ("${dapcore_DEFINITIONS}")
add_definitions ("${dapdb_DEFINITIONS}")
add_definitions ("${dapcrypt_DEFINITIONS}")
add_definitions ("${daphttp_DEFINITIONS}")

add_library(${PROJECT_NAME} STATIC ${AUTH_SRCS})
set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
