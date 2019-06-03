cmake_minimum_required(VERSION 3.0)
project (dap_chain_net)
  
set(DAP_CHAIN_NET_SRCS 
	dap_chain_net.c 
        dap_chain_node.c
        dap_chain_node_cli.c
        dap_chain_node_cli_cmd.c
        dap_chain_node_client.c
        dap_chain_node_remote.c
        )

set(DAP_CHAIN_NET_HEADERS
        dap_chain_net.h
        dap_chain_node.h
        dap_chain_node_cli.h
        dap_chain_node_cli_cmd.h
        dap_chain_node_client.h
        dap_chain_node_remote.h
    )

set(IPUTILS_INCLUDE_DIRS
     iputils/traceroute/
    )

file(GLOB IPUTILS_SRCS iputils/*.c iputils/traceroute/*.c)
file(GLOB IPUTILS_HEADERS iputils/*.h ${IPUTILS_INCLUDE_DIRS}*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRCS} ${DAP_CHAIN_NET_HEADERS} ${IPUTILS_SRCS} ${IPUTILS_HEADERS})
target_link_libraries(dap_chain_net dap_core dap_crypto dap_client  dap_core_server dap_stream_ch_chain dap_stream_ch_chain_net dap_chain dap_chain_crypto dap_chain_wallet dap_chain_net_srv dap_chain_mempool dap_chain_global_db -lresolv)
target_include_directories(dap_chain_net INTERFACE . PUBLIC ${IPUTILS_INCLUDE_DIRS})

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
