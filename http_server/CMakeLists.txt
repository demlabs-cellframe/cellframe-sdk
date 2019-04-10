cmake_minimum_required(VERSION 3.0)
project (dap_http_server C)

include_directories(http_client)

set(HTTP_SERVER_SRCS
    dap_http.c
    dap_http_folder.c
    dap_http_simple.c
    http_client/dap_http_client.c
    http_client/dap_http_client_simple.c
    http_client/dap_http_header.c
    http_client/dap_http_user_agent.c)

add_library(${PROJECT_NAME} STATIC ${HTTP_SERVER_SRCS})

target_include_directories(dap_http_server INTERFACE . http_client)

target_link_libraries(dap_http_server dap_core dap_crypto dap_core_server magic curl json-c)

