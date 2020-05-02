cmake_minimum_required(VERSION 3.0)
project (dap_chain_net)
  

set(DAP_CHAIN_NET_SRCS 
		dap_chain_net.c 
		dap_chain_net_remote.c
		dap_chain_net_bugreport.c
        dap_chain_node.c
        dap_chain_node_cli.c
        dap_chain_node_cli_cmd.c
        dap_chain_node_cli_cmd_tx.c
        dap_chain_node_client.c
        dap_chain_node_remote.c
        dap_chain_node_ping.c
        )

set(DAP_CHAIN_NET_HEADERS
        dap_chain_net.h
		dap_chain_net_remote.h
		dap_chain_net_bugreport.h
        dap_chain_node.h
        dap_chain_node_cli.h
        dap_chain_node_cli_cmd.h
        dap_chain_node_cli_cmd_tx.h
        dap_chain_node_client.h
        dap_chain_node_remote.h
        dap_chain_node_ping.h
    )

#if (ANDROID)
#    set(DAP_CHAIN_NET_HEADERS ${DAP_CHAIN_NET_HEADERS}
#        android/ifaddrs-android.h
#    )
#endif()

set(IPUTILS_INCLUDE_DIRS
     iputils/traceroute/
    )

if(NOT (WIN32))
  file(GLOB IPUTILS_SRCS iputils/*.c iputils/traceroute/*.c)
  file(GLOB IPUTILS_HEADERS iputils/*.h ${IPUTILS_INCLUDE_DIRS}*.h)
endif()

if(WIN32)
  add_definitions ("-DUNDEBUG")
  add_definitions ("-DNDEBUG")
  add_definitions ("-DWIN32")
  add_definitions ("-D_WINDOWS")
  add_definitions ("-D__WINDOWS__")
  add_definitions ("-D_CRT_SECURE_NO_WARNINGS")
  add_definitions ("-D_POSIX")
  add_definitions ("-D_POSIX_")
  add_definitions ("-D_POSIX_THREAD_SAFE_FUNCTIONS")
  add_compile_definitions(_GNU_SOURCE)
  include_directories(../3rdparty/wepoll/)
  include_directories(../3rdparty/uthash/src/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRCS} ${DAP_CHAIN_NET_HEADERS} ${IPUTILS_SRCS} ${IPUTILS_HEADERS})

if(WIN32)
  target_link_libraries(dap_chain_net dap_core dap_crypto dap_client dap_stream_ch_chain dap_stream_ch_chain_net dap_chain dap_chain_crypto dap_chain_wallet dap_chain_net_srv dap_chain_mempool dap_chain_global_db )
endif()

if(UNIX)
    target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_client dap_stream_ch_chain dap_stream_ch_chain_net dap_chain
      dap_chain_crypto dap_chain_wallet dap_chain_net_srv dap_chain_net_srv_vpn dap_chain_mempool dap_chain_global_db
      resolv
      )
endif()

target_include_directories(${PROJECT_NAME} INTERFACE . )

if (!WIN32)
    target_include_directories(${PROJECT_NAME} PUBLIC ${IPUTILS_INCLUDE_DIRS})
endif()


set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
