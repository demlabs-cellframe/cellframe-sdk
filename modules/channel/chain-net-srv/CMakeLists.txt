cmake_minimum_required(VERSION 3.0)
project (dap_stream_ch_chain_net_srv)

file(GLOB DAP_STREAM_CH_CHAIN_NET_SRV_SRCS *.c)
file(GLOB DAP_STREAM_CH_CHAIN_NET_SRV_HDRS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_STREAM_CH_CHAIN_NET_SRV_SRCS} ${DAP_STREAM_CH_CHAIN_NET_SRV_HDRS})

target_link_libraries(dap_stream_ch_chain_net_srv dap_core dap_crypto dap_chain_common dap_chain dap_chain_mempool dap_chain_net dap_chain_net_srv dap_server_core dap_stream dap_stream_ch dap_stream_ch_chain dap_stream_ch_chain_net)

target_include_directories(dap_stream_ch_chain_net_srv INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
