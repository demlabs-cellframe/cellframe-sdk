cmake_minimum_required(VERSION 2.8)
project (daphttp)
  
set(HTTP_SRCS dap_http_client.c dap_http_header.c)
 
add_library(${PROJECT_NAME} STATIC ${HTTP_SRCS})

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
