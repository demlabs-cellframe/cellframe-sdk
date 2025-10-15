cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_vpn)
  

file(GLOB DAP_CHAIN_NET_SRV_VPN_SRCS *.c)
file(GLOB DAP_CHAIN_NET_SRV_VPN_HEADERS include/*.h)

cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_NET_SRV_VPN_SRCS} HEADERS ${DAP_CHAIN_NET_SRV_VPN_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_stream dap_chain dap_chain_net dap_chain_net_srv)
add_definitions("-DDAP_TUN_IN_WORKER")

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NET_SRV_VPN_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/service/vpn/
        ARCHIVE DESTINATION lib/modules/service/vpn/
        PUBLIC_HEADER DESTINATION include/modules/service/vpn/
)
endif()
