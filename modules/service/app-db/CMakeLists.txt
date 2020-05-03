cmake_minimum_required(VERSION 2.8)
project (dap_chain_net_srv_app_db)
  
set(DAP_CHAIN_NET_SRV_APP_DB_SRCS *.c)

set(DAP_CHAIN_NET_SRV_APP_DB_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_APP_DB_SRCS} ${DAP_CHAIN_NET_SRV_APP_DB_HEADERS})

target_link_libraries(dap_chain_net_srv_app_db dap_chain_net_srv dap_chain_net_srv_app)
target_include_directories(dap_chain_net_srv_app_db INTERFACE .)

