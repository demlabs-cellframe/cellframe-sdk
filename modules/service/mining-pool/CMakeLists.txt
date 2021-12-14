cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_datum_pool)
  
file(GLOB DAP_CHAIN_NET_SRV_DATUM_POOL_SRCS *.c)
file(GLOB DAP_CHAIN_NET_SRV_DATUM_POOL_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_DATUM_POOL_SRCS} ${DAP_CHAIN_NET_SRV_DATUM_POOL_HEADERS})

target_link_libraries(dap_chain_net_srv_datum_pool dap_chain_net_srv dap_chain_net_srv_datum)
target_include_directories(dap_chain_net_srv_datum_pool INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

