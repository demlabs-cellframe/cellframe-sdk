cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv)

file(GLOB DAP_CHAIN_NET_SRV_SRCS *.c libmaxminddb/*.c)

file(GLOB DAP_CHAIN_NET_SRV_HEADERS include/*.h libmaxminddb/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_SRCS} ${DAP_CHAIN_NET_SRV_HEADERS})

set(NET_SRV_LIBS dap_chain_net_srv dap_core dap_crypto dap_chain dap_chain_net dap_chain_wallet)

if (CELLFRAME_MODULES MATCHES "modules-dynamic")
    set(NET_SRV_LIBS ${NET_SRV_LIBS} dap_modules_dynamic_cdb)
endif()

#if (CELLFRAME_MODULES MATCHES "srv-stake")
#    set(NET_SRV_LIBS ${NET_SRV_LIBS} dap_chain_net_srv_stake)
#endif()

target_link_libraries(${NET_SRV_LIBS})
target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../3rdparty/uthash/src)
