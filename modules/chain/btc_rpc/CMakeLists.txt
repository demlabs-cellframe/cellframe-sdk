project(dap_chain_btc_rpc C)
cmake_minimum_required(VERSION 3.10)

add_definitions ("-D_GNU_SOURCE")
add_definitions("-Dfpic")

file(GLOB BTC_RPC_HEADERS include/*.h)
file(GLOB BTC_RPC_SRCS *.c)

include_directories(${PROJECT_NAME} include/)

add_library(${PROJECT_NAME} STATIC ${BTC_RPC_HEADERS} ${BTC_RPC_SRCS})
target_include_directories(${PROJECT_NAME} INTERFACE . include/)
target_include_directories(${PROJECT_NAME} PUBLIC include)

target_link_libraries(${PROJECT_NAME} dap_core dap_json_rpc)
#target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_server_core dap_http_server dap_client json-c )
#target_link_libraries(${PROJECT_NAME} dap_core)# dap_http_server json-c)
