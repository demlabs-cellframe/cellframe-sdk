cmake_minimum_required(VERSION 2.8)
project (dap_udp_server C)
  
set(DAP_UDP_SERVER_SRCS  dap_udp_server.c dap_udp_client.h dap_udp_client.c)

add_library(${PROJECT_NAME} STATIC ${DAP_UDP_SERVER_SRCS})

target_link_libraries(dap_udp_server dap_core dap_core_server)

target_include_directories(dap_udp_server INTERFACE .)
