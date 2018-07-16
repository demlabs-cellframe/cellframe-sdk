cmake_minimum_required(VERSION 2.8)
project (dap_stream)
  
set(STREAM_SRCS
    stream.c
    stream_ch.c
    stream_ch_pkt.c
    stream_ch_proc.c
    stream_ctl.c
    stream_pkt.c )

add_library(${PROJECT_NAME} STATIC ${STREAM_SRCS})

target_link_libraries(dap_stream dap_core dap_udp_server
    dap_crypto dap_http_server dap_enc_server dap_session)

target_include_directories(dap_stream INTERFACE .)
