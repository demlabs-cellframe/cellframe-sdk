cmake_minimum_required(VERSION 3.0)
project (dap_core_server C)

set(DAP_CORE_SERVER_SRCS
    dap_server.c
    dap_client/dap_client.c
    dap_client/dap_client_internal.c
    dap_client/dap_client_remote.c
    dap_client/sxmlc/sxmlc.c dap_client/sxmlc/sxmlsearch.c)

set(DAP_CORE_SERVER_HEADERS
    dap_server.h
    dap_client/dap_client.h
    dap_client/dap_client_internal.h
    dap_client/dap_client_remote.h
    dap_client/sxmlc/sxmlc.h dap_client/sxmlc/sxmlsearch.h)

include_directories(dap_client)

add_library(${PROJECT_NAME} STATIC ${DAP_CORE_SERVER_SRCS} ${DAP_CORE_SERVER_HEADERS})

target_include_directories(dap_core_server INTERFACE . dap_client)

target_link_libraries(dap_core_server ev curl dap_core dap_crypto dap_common)
