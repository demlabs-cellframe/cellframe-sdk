cmake_minimum_required(VERSION 2.8)
project (dap_http_server C)
  
include_directories("${INCLUDE_DIRECTORIES} ${dap_core_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_http_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_crypto_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_enc_server_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_client_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_core_server_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_core_server_INCLUDE_DIRS}/client")
include_directories(http_client)

set(HTTP_SERVER_SRCS
    dap_http.c
    dap_http_folder.c
    dap_http_simple.c
    dap_http_simple.h
    http_client/dap_http_client.c
    http_client/dap_http_client_simple.c
    http_client/dap_http_header.c)

add_definitions ("${dap_core_DEFINITIONS}")
add_definitions ("${dap_http_DEFINITIONS}")
add_definitions ("${dap_crypto_DEFINITIONS}")
add_definitions ("${dap_enc_server_DEFINITIONS}")
add_definitions ("${dap_client_DEFINITIONS}")
add_definitions ("${dap_core_server_DEFINITIONS}")


add_library(${PROJECT_NAME} STATIC ${HTTP_SERVER_SRCS})

target_include_directories(dap_core_server INTERFACE . http_client)

target_link_libraries(dap_http_server dap_core)
target_link_libraries(dap_http_server dap_crypto)
target_link_libraries(dap_http_server dap_core_server)

#set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)
#set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
