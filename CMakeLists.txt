cmake_minimum_required(VERSION 3.0)
project (dap_stream_ch_chain)
  
set(CH_CHAIN_SRCS dap_stream_ch_chain.c)

add_library(${PROJECT_NAME} STATIC ${CH_CHAIN_SRCS})

target_link_libraries(dap_stream_ch_chain dap_core dap_crypto dap_core_server dap_stream)

target_include_directories(dap_stream_ch_chain INTERFACE .)
