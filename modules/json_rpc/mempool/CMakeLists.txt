cmake_minimum_required(VERSION 3.10)
project (dap_json_rpc_chain_mempool)


file(GLOB DAP_JSON_RPC_CHAIN_MEMPOOL_HEADERS include/*.h)
file(GLOB DAP_JSON_RPC_CHAIN_MEMPOOL_SRCS  *.c)

add_library(${PROJECT_NAME}  STATIC ${DAP_JSON_RPC_CHAIN_MEMPOOL_SRCS} ${DAP_JSON_RPC_CHAIN_MEMPOOL_HEADERS})

target_link_libraries(dap_json_rpc_chain_mempool dap_http_server dap_client dap_chain_net dap_global_db dap_core dap_chain_cs_blocks dap_chain_mempool dap_json_rpc_core dap_chain_btc_rpc)
target_include_directories(dap_json_rpc_chain_mempool PUBLIC include/ )
