cmake_minimum_required(VERSION 2.8)
project (dap_chain_net_srv)

set(DAP_CHAIN_NET_SRV_SRCS *.c)

set(DAP_CHAIN_NET_SRV_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_SRCS} ${DAP_CHAIN_NET_SRV_HEADERS})

target_link_libraries(dap_chain_net_srv dap_core dap_crypto dap_chain dap_chain_crypto dap_chain_net dap_chain_wallet)

target_include_directories(dap_chain_net_srv INTERFACE .)
