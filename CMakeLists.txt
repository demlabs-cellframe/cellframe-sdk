cmake_minimum_required(VERSION 2.8)
project (dap_chain_net_srv_app)
  
set(DAP_CHAIN_NET_SRV_APP_SRCS 
	dap_chain_net_srv_app.c 
        )

set(DAP_CHAIN_NET_SRV_APP_HEADERS
        dap_chain_net_srv_app.h
    )

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_APP_SRCS} ${DAP_CHAIN_NET_SRV_APP_HEADERS})


target_link_libraries(dap_chain_net_srv_app dap_core dap_crypto dap_chain dap_chain_crypto dap_chain_net dap_chain_net_srv )

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
