cmake_minimum_required(VERSION 3.0)
project (dap_stream_ch_chain)
  
set(DAP_STREAM_CH_CHAIN_SRCS dap_stream_ch_chain.c dap_stream_ch_chain_pkt.c)

if(WIN32)
  include_directories(../3rdparty/wepoll/)
  include_directories(../3rdparty/uthash/src/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_STREAM_CH_CHAIN_SRCS})

target_link_libraries(dap_stream_ch_chain dap_core dap_crypto dap_chain dap_stream dap_stream_ch)

target_include_directories(dap_stream_ch_chain INTERFACE .)

