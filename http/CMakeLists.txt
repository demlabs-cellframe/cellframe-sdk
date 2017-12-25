cmake_minimum_required(VERSION 2.8)
project (daphttp)
  
set(HTTP_SRCS dap_http.c  dap_http_client.c  dap_http_folder.c  dap_http_header.c )

include_directories("${INCLUDE_DIRECTORIES} ${dapcore_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapcrypt_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapauth_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapdb_http_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${MONGO_INCLUDE_DIRS}")

add_definitions ("${dapcore_DEFINITIONS}")
add_definitions ("${dapauth_DEFINITIONS}")
add_definitions ("${dapcrypt_DEFINITIONS}")
add_definitions ("${dapdb_http_DEFINITIONS}")


add_library(${PROJECT_NAME} STATIC ${HTTP_SRCS})
set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)
set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
