cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv)

file(GLOB DAP_CHAIN_NET_SRV_SRCS *.c)
file(GLOB DAP_CHAIN_NET_SRV_HEADERS *.h include/*.h)
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_NET_SRV_SRCS} HEADERS ${DAP_CHAIN_NET_SRV_HEADERS})

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../../3rdparty/libmaxminddb ${CMAKE_CURRENT_BINARY_DIR}/../../../../3rdparty/libmaxminddb)

# OBJECT library: net-srv is high-level service, depends on net/ledger/mempool
target_link_libraries(${PROJECT_NAME} 
    maxminddb dap_core dap_crypto dap_common dap_chain dap_chain_datum
    dap_chain_net dap_chain_ledger dap_chain_mempool)
# REMOVED: dap_chain_datum_tx, dap_chain_tx_sign - these are now part of dap_chain_datum module
# Service layer can depend on all lower layers + TX API through dap_chain_datum
# These are unidirectional dependencies: srv → net, srv → ledger, srv → mempool
# No cycles because net/ledger/mempool don't depend on srv

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NET_SRV_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib/modules/net-srv/
        ARCHIVE DESTINATION lib/modules/net-srv/
        PUBLIC_HEADER DESTINATION include/modules/net-srv/
)
endif()
