cmake_minimum_required(VERSION 3.0)
project (dap_stream_ch_chain_net)
  
set(DAP_STREAM_CH_CHAIN_NET_SRCS dap_stream_ch_chain_net.c)

add_library(${PROJECT_NAME} STATIC ${DAP_STREAM_CH_CHAIN_NET_SRCS})

target_link_libraries(dap_stream_ch_chain_net dap_core dap_crypto dap_core_server dap_stream dap_stream_ch dap_stream_ch_chain)

target_include_directories(dap_stream_ch_chain_net INTERFACE .)
