cmake_minimum_required(VERSION 2.8)
project (dapclient)
  
set(CLIENT_SRCS dap_client.c dap_client_internal.c)
 
add_library(${PROJECT_NAME} STATIC ${CLIENT_SRCS})

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
