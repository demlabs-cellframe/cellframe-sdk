cmake_minimum_required(VERSION 3.13)
project (dap_chain_net_srv)

file(GLOB DAP_CHAIN_NET_SRV_SRCS *.c)
file(GLOB DAP_CHAIN_NET_SRV_HEADERS *.h)
add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_SRCS} ${DAP_CHAIN_NET_SRV_HEADERS})

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../3rdparty/libmaxminddb ${CMAKE_CURRENT_BINARY_DIR}/../../../3rdparty/libmaxminddb)

target_link_libraries(${PROJECT_NAME} maxminddb dap_core dap_crypto dap_chain dap_chain_net dap_chain_wallet dap_stream_ch_chain_net_srv)

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../dap-sdk/3rdparty/uthash/src)
