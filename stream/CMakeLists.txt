cmake_minimum_required(VERSION 2.8)
project (dap_stream)
  
set(STREAM_SRCS
    dap_stream.c
    dap_stream_ctl.c
    dap_stream_pkt.c )

add_library(${PROJECT_NAME} STATIC ${STREAM_SRCS})

target_link_libraries(dap_stream dap_core dap_udp_server dap_client
    dap_crypto dap_http_server dap_enc_server dap_session dap_stream_ch)

target_include_directories(dap_stream INTERFACE .)
set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
