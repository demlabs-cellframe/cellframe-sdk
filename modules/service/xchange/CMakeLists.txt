cmake_minimum_required(VERSION 3.0)
project (dap_chain_net_srv_xchange)
  
file(GLOB DAP_SRV_XCHANGE_SRCS *.c)

file(GLOB DAP_SRV_XCHANGE_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_SRV_XCHANGE_SRCS} ${DAP_SRV_XCHANGE_HEADERS})

target_include_directories(dap_chain_crypto INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_crypto dap_chain_net dap_chain_net_srv)
