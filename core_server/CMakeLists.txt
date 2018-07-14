cmake_minimum_required(VERSION 2.8)
project (dap_core_server C)

set(DAP_CORE_SERVER_SRCS
    dap_server.c
    client/dap_client.c
    client/dap_client_internal.c
    client/dap_client_remote.c)

include_directories(client)
include_directories("${INCLUDE_DIRECTORIES} ${dap_client_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_core_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_crypto_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_enc_server_INCLUDE_DIRS}")

add_definitions ("${dap_client_DEFINITIONS}")
add_definitions ("${dap_core_DEFINITIONS}")
add_definitions ("${dap_crypto_DEFINITIONS}")
add_definitions ("${dap_enc_server_DEFINITIONS}")

add_library(${PROJECT_NAME} STATIC ${DAP_CORE_SERVER_SRCS})

target_link_libraries(dap_core_server dap_core)
target_link_libraries(dap_core_server dap_crypto)

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
