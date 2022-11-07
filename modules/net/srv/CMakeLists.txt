cmake_minimum_required(VERSION 3.13)
project (dap_chain_net_srv)

file(GLOB DAP_CHAIN_NET_SRV_SRCS *.c)
file(GLOB DAP_CHAIN_NET_SRV_HEADERS *.h)
add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_SRCS} ${DAP_CHAIN_NET_SRV_HEADERS})

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../3rdparty/libmaxminddb ${CMAKE_CURRENT_BINARY_DIR}/../../../3rdparty/libmaxminddb)

set(NET_SRV_LIBS maxminddb dap_core dap_crypto dap_chain dap_chain_net dap_chain_wallet)
if (CELLFRAME_MODULES MATCHES "modules-dynamic")
    set(NET_SRV_LIBS ${NET_SRV_LIBS} dap_modules_dynamic_cdb)
endif()
target_link_libraries(${PROJECT_NAME} ${NET_SRV_LIBS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../3rdparty/uthash/src)
