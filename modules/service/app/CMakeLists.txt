cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_app)
  
file(GLOB DAP_CHAIN_NET_SRV_APP_SRCS  *.c)

file(GLOB DAP_CHAIN_NET_SRV_APP_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_APP_SRCS} ${DAP_CHAIN_NET_SRV_APP_HEADERS})

target_link_libraries(dap_chain_net_srv_app dap_core dap_crypto dap_chain dap_chain_net dap_chain_net_srv)
target_include_directories(dap_chain_net_srv_app INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
