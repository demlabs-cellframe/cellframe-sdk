cmake_minimum_required(VERSION 3.10)
project(dap_json_rpc_chain_common)

file(GLOB DAP_JSON_RPC_CHAIN_COMMON_HEADERS include/*.h)
file(GLOB DAP_JSON_RPC_CHAIN_COMMON_SRCS *.c)

add_library(${PROJECT_NAME}  STATIC ${DAP_JSON_RPC_CHAIN_COMMON_SRCS} ${DAP_JSON_RPC_CHAIN_COMMON_HEADERS})

target_link_libraries(dap_json_rpc_chain_common dap_core dap_crypto dap_chain_common dap_json-c dap_json_rpc_core dap_json_rpc_crypto)
target_include_directories(dap_json_rpc_chain_common PUBLIC include/)
