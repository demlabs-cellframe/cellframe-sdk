cmake_minimum_required(VERSION 2.8)
project (dap_chain_net_srv_datum_pool)
  
set(DAP_CHAIN_NET_SRV_DATUM_POOL_SRCS 
	dap_chain_net_srv_datum_pool.c 
        )

set(DAP_CHAIN_NET_SRV_DATUM_POOL_HEADERS
        dap_chain_net_srv_datum_pool.h
    )

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_DATUM_POOL_SRCS} ${DAP_CHAIN_NET_SRV_DATUM_POOL_HEADERS})


target_link_libraries(dap_chain_net_srv_datum_pool dap_core dap_crypto dap_chain dap_chain_crypto dap_chain_net dap_chain_net_srv dap_chain_net_srv_datum )

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
