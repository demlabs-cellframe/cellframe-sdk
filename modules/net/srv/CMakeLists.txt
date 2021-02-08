cmake_minimum_required(VERSION 3.0)
project (dap_chain_net_srv)

file(GLOB DAP_CHAIN_NET_SRV_SRCS *.c libmaxminddb/*.c)

file(GLOB DAP_CHAIN_NET_SRV_HEADERS include/*.h libmaxminddb/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_SRCS} ${DAP_CHAIN_NET_SRV_HEADERS})

target_link_libraries(dap_chain_net_srv dap_core dap_crypto dap_chain dap_chain_net dap_chain_wallet)

target_include_directories(dap_chain_net_srv INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../3rdparty/uthash/src)
