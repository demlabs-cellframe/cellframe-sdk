cmake_minimum_required(VERSION 2.8)
project (dap_core_server C)

set(DAP_CORE_SERVER_SRCS
    dap_server.c
    dap_client/dap_client.c
    dap_client/dap_client_internal.c
    dap_client/dap_client_remote.c)

set(DAP_CORE_SERVER_HEADERS
    dap_server.h
    dap_client/dap_client.h
    dap_client/dap_client_internal.h
    dap_client/dap_client_remote.h)

include_directories(dap_client)

add_library(${PROJECT_NAME} STATIC ${DAP_CORE_SERVER_SRCS} ${DAP_CORE_SERVER_HEADERS})

target_include_directories(dap_core_server INTERFACE .)
target_include_directories(dap_core_server INTERFACE dap_client)

target_link_libraries(dap_core_server dap_core)
target_link_libraries(dap_core_server dap_crypto)
