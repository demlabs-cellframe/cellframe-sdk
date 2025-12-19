cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv)

file(GLOB DAP_CHAIN_NET_SRV_SRCS *.c)
file(GLOB DAP_CHAIN_NET_SRV_HEADERS *.h include/*.h)
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_NET_SRV_SRCS} HEADERS ${DAP_CHAIN_NET_SRV_HEADERS})

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/libmaxminddb ${CMAKE_CURRENT_BINARY_DIR}/../../3rdparty/libmaxminddb)

# OBJECT library: net-srv is LOW-LEVEL service layer, should NOT depend on high-level net-tx
target_link_libraries(${PROJECT_NAME} maxminddb dap_core dap_crypto dap_common dap_chain dap_chain_ledger 
    dap_chain_mempool)
# REMOVED: dap_chain_net_tx - breaks cycle (high-level TX operations don't belong in low-level srv)

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../dap-sdk/3rdparty/uthash/src)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NET_SRV_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib/modules/net-srv/
        ARCHIVE DESTINATION lib/modules/net-srv/
        PUBLIC_HEADER DESTINATION include/modules/net-srv/
)
endif()
