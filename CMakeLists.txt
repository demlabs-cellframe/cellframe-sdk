cmake_minimum_required(VERSION 2.8)
project (dap_chain_net_srv_vpn)
  
set(DAP_CHAIN_NET_SRV_VPN_SRCS 
	dap_chain_net_srv_vpn.c
    dap_chain_net_srv_vpn_cdb.c
    dap_chain_net_srv_vpn_cdb_server_list.c
	dap_chain_net_vpn_client.c
	dap_chain_net_vpn_client_tun.c
        )

set(DAP_CHAIN_NET_SRV_VPN_HEADERS
	dap_chain_net_srv_vpn.h
    dap_chain_net_srv_vpn_cdb.h
    dap_chain_net_srv_vpn_cdb_server_list.h
	dap_chain_net_vpn_client.h
	dap_chain_net_vpn_client_tun.h
    )

if(WIN32)
  include_directories(../libdap/src/win32/)
  include_directories(../3rdparty/wepoll/include/)
  include_directories(../3rdparty/uthash/src/)
  include_directories(../3rdparty/libjson-c/)
  include_directories(../3rdparty/libmagic/src/)
  include_directories(../3rdparty/curl/include/)
  include_directories(../3rdparty/libsqlite3/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_VPN_SRCS} ${DAP_CHAIN_NET_SRV_VPN_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_crypto dap_chain_net dap_chain_net_srv)

if(NOT ANDROID)
    target_link_libraries(${PROJECT_NAME} dap_server_http_db_auth dap_server_http_db)
endif()

target_include_directories(${PROJECT_NAME} INTERFACE .)

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
