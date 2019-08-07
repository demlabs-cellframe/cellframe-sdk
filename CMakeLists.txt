cmake_minimum_required(VERSION 3.0)
project (dap_chain_net)
  
set(DAP_CHAIN_NET_SRCS 
  dap_chain_net.c 
        dap_chain_node.c
        dap_chain_node_cli.c
        dap_chain_node_cli_cmd.c
        dap_chain_node_cli_cmd_tx.c
        dap_chain_node_client.c
        dap_chain_node_remote.c
        )

set(DAP_CHAIN_NET_HEADERS
        dap_chain_net.h
        dap_chain_node.h
        dap_chain_node_cli.h
        dap_chain_node_cli_cmd.h
        dap_chain_node_cli_cmd_tx.h
        dap_chain_node_client.h
        dap_chain_node_remote.h
    )

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
  add_definitions ("-DCURL_STATICLIB")
  add_definitions ("-DLIBSSH2_OPENSSL")
  add_definitions ("-DNGHTTP2_STATICLIB")
  add_definitions ("-D_POSIX")
  add_definitions ("-D_POSIX_")
  add_definitions ("-D_POSIX_THREAD_SAFE_FUNCTIONS")
  add_definitions ("-DNODE_NETNAME=\"kelvin\"")
  include_directories(../libdap/src/win32/)
  include_directories(../3rdparty/libmemcached/)
  include_directories(../3rdparty/libmemcached/win32/)
  include_directories(../3rdparty/wepoll/include/)
  include_directories(../3rdparty/uthash/src/)
  include_directories(../3rdparty/libjson-c/)
  include_directories(../3rdparty/libmagic/src/)
  include_directories(../3rdparty/curl/include/)
  include_directories(../3rdparty/libsqlite3/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRCS} ${DAP_CHAIN_NET_HEADERS} ${IPUTILS_SRCS} ${IPUTILS_HEADERS})

if(WIN32)
  target_link_libraries(dap_chain_net dap_core dap_crypto dap_client dap_stream_ch_chain dap_stream_ch_chain_net dap_chain dap_chain_gdb dap_chain_crypto dap_chain_wallet dap_chain_net_srv dap_chain_mempool dap_chain_global_db )
endif()

if(UNIX)
  target_link_libraries(dap_chain_net dap_core dap_crypto dap_client dap_stream_ch_chain dap_chain_gdb dap_stream_ch_chain_net dap_chain dap_chain_crypto dap_chain_wallet dap_chain_net_srv dap_chain_mempool dap_chain_global_db -lresolv)
endif()

target_include_directories(dap_chain_net INTERFACE . PUBLIC ${IPUTILS_INCLUDE_DIRS})

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
