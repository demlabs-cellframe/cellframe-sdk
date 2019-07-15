cmake_minimum_required(VERSION 2.8)
project (dap_chain_net_srv_vpn)
  
set(DAP_CHAIN_NET_SRV_VPN_SRCS 
  dap_chain_net_srv_vpn.c 
        )

set(DAP_CHAIN_NET_SRV_VPN_HEADERS
        dap_chain_net_srv_vpn.h
    )

if(WIN32)
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

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_VPN_SRCS} ${DAP_CHAIN_NET_SRV_VPN_HEADERS})

target_link_libraries(dap_chain_net_srv_vpn dap_core dap_crypto dap_chain dap_chain_crypto dap_chain_net dap_chain_net_srv)
target_include_directories(dap_chain_net_srv_vpn INTERFACE .)

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
