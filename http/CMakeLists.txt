cmake_minimum_required(VERSION 2.8)
project (dap_http)
  
set(HTTP_SRCS dap_http_client.c dap_http_header.c)
 
add_library(${PROJECT_NAME} STATIC ${HTTP_SRCS})
include_directories("${dap_core_INCLUDE_DIRS}")
include_directories("${dap_client_INCLUDE_DIRS}")
add_definitions ("${dap_core_DEFINITIONS}")
add_definitions ("${dap_client_DEFINITIONS}")

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
