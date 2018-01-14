cmake_minimum_required(VERSION 2.8)
project (dap_client)
  
set(CLIENT_SRCS dap_client.c dap_client_internal.c dap_client_remote.c)
 
add_library(${PROJECT_NAME} STATIC ${CLIENT_SRCS})

include_directories("${dap_core_INCLUDE_DIRS}")
include_directories("${dap_crypto_INCLUDE_DIRS}")
#include_directories("${dap_http_INCLUDE_DIRS}")
add_definitions ("${dap_core_DEFINITIONS}")
add_definitions ("${dap_crypto_DEFINITIONS}")
add_definitions ("${dap_http_DEFINITIONS}")

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
