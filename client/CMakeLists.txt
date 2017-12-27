cmake_minimum_required(VERSION 2.8)
project (dapclient)
  
set(CLIENT_SRCS dap_client_remote.c dap_client.c)
 
add_library(${PROJECT_NAME} STATIC ${CORE_SRCS})

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
