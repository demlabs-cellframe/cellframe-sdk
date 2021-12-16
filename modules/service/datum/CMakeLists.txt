cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_datum)
  
file(GLOB DAP_CHAIN_NET_SRV_DATUM_SRCS *.c)

file(GLOB DAP_CHAIN_NET_SRV_DATUM_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_DATUM_SRCS} ${DAP_CHAIN_NET_SRV_DATUM_HEADERS})

target_link_libraries(dap_chain_net_srv_datum dap_chain_net_srv)
target_include_directories(dap_chain_net_srv_datum INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

