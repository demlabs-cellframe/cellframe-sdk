cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_vpn)
  

# Server sources
if(WIN32)
  file(GLOB DAP_CHAIN_NET_SRV_VPN_SRCS *common.c)
  file(GLOB DAP_CHAIN_NET_SRV_VPN_HEADERS include/*common.h)
  include_directories(../../../os/win32/)
  include_directories(../3rdparty/wepoll/include/)
  include_directories(../3rdparty/uthash/src/)
  include_directories(../../dap-sdk/3rdparty/json-c/)
else()
  file(GLOB DAP_CHAIN_NET_SRV_VPN_SRCS *.c)
  file(GLOB DAP_CHAIN_NET_SRV_VPN_HEADERS include/*.h)
endif()

# VPN Client sources (platform-independent)
file(GLOB DAP_CHAIN_NET_VPN_CLIENT_SRCS client/*.c)
file(GLOB DAP_CHAIN_NET_VPN_CLIENT_HEADERS 
  client/include/*.h 
  client/platform/platform.h
  client/platform/network.h
)
# Exclude internal headers from public API
list(FILTER DAP_CHAIN_NET_VPN_CLIENT_HEADERS EXCLUDE REGEX ".*_internal\\.h$")

# Platform-specific VPN Client sources
# CMake selects only the implementation for the current platform
if(WIN32)
  list(APPEND DAP_CHAIN_NET_VPN_CLIENT_SRCS 
    client/platform/windows/network.c
    client/platform/windows/platform.c
  )
elseif(APPLE)
  list(APPEND DAP_CHAIN_NET_VPN_CLIENT_SRCS 
    client/platform/unix/network_common.c
    client/platform/darwin/network.c
    client/platform/darwin/platform.c
  )
elseif(CMAKE_SYSTEM_NAME MATCHES "Linux")
  list(APPEND DAP_CHAIN_NET_VPN_CLIENT_SRCS 
    client/platform/unix/network_common.c
    client/platform/linux/network.c
    client/platform/linux/platform.c
  )
elseif(CMAKE_SYSTEM_NAME MATCHES "BSD")
  list(APPEND DAP_CHAIN_NET_VPN_CLIENT_SRCS 
    client/platform/unix/network_common.c
    client/platform/bsd/network.c
    client/platform/bsd/platform.c
  )
else()
  message(FATAL_ERROR "Unsupported platform for VPN client")
endif()

# Combine server and client sources
list(APPEND DAP_CHAIN_NET_SRV_VPN_SRCS ${DAP_CHAIN_NET_VPN_CLIENT_SRCS})
list(APPEND DAP_CHAIN_NET_SRV_VPN_HEADERS ${DAP_CHAIN_NET_VPN_CLIENT_HEADERS})

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_VPN_SRCS} ${DAP_CHAIN_NET_SRV_VPN_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_stream dap_stream_ch_chain_net_srv dap_chain dap_chain_crypto dap_chain_net dap_chain_net_srv)
add_definitions("-DDAP_TUN_IN_WORKER")

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC client/include)  # VPN Client headers

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NET_SRV_VPN_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/service/vpn/
        ARCHIVE DESTINATION lib/modules/service/vpn/
        PUBLIC_HEADER DESTINATION include/modules/service/vpn/
)
endif()
