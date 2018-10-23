cmake_minimum_required(VERSION 2.8)
project (dap_client)

set(DAP_CLIENT_SRCS
        dap_client.c
        dap_client_pool.c
        )

set(DAP_CLIENT_HEADERS
    dap_client.h
    dap_client_pool.h

    )

add_library(${PROJECT_NAME} STATIC ${DAP_CLIENT_SRCS} ${DAP_CLIENT_HEADERS})

include_directories("${INCLUDE_DIRECTORIES} ${dap_core_server_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_server_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_server_udp_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_stream_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_session_INCLUDE_DIRS}")

target_link_libraries(${PROJECT_NAME} dap_core dap_server_core dap_server dap_server_udp dap_stream dap_session)
target_include_directories(dap_client INTERFACE .)


set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
