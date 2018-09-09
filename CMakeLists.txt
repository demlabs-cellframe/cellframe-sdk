cmake_minimum_required(VERSION 2.8)
project (dap_chain_net_srv)
  
set(DAP_CHAIN_NET_SRV_SRCS 
	dap_chain_net_srv.c 
	dap_chain_net_srv_pkt.c 
        )

set(DAP_CHAIN_NET_SRV_HEADERS
        dap_chain_net_srv.h
        dap_chain_net_srv_pkt.h
    )

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_SRCS} ${DAP_CHAIN_NET_SRV_HEADERS})


target_link_libraries(dap_chain_net_srv dap_core dap_crypto dap_chain dap_chain_crypto dap_chain_net )

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
