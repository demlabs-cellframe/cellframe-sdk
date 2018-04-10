cmake_minimum_required(VERSION 2.8)
project (dap_udp_server C)
  
set(DAP_UDP_SERVER_SRCS  dap_udp_server.c dap_udp_client.h dap_udp_client.c )


include_directories("${INCLUDE_DIRECTORIES} ${dap_core_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_crypto_INCLUDE_DIRS}")

add_definitions ("${dap_core_DEFINITIONS}")
add_definitions ("${dap_crypto_DEFINITIONS}")

add_library(${PROJECT_NAME} STATIC ${DAP_UDP_SERVER_SRCS})
set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)