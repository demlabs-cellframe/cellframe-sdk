cmake_minimum_required(VERSION 2.8)
project (dap_chain_net)
  
set(DAP_CHAIN_NET_SRCS 
	dap_chain_net.c 
        dap_chain_node.c
        dap_chain_node_ctl.c
        )

set(DAP_CHAIN_NET_HEADERS
        dap_chain_net.h
        dap_chain_node.h
        dap_chain_node_ctl.h
    )

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRCS} ${DAP_CHAIN_NET_HEADERS})


target_link_libraries(dap_chain_net dap_core dap_crypto dap_chain dap_chain_crypto )
target_include_directories(dap_chain_net INTERFACE .)

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
