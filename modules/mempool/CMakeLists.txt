cmake_minimum_required(VERSION 3.10)
project (dap_chain_mempool)

file(GLOB DAP_CHAIN_MEMPOOL_SRC *.c)
file(GLOB DAP_CHAIN_MEMPOOL_HDR include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_MEMPOOL_SRC} ${DAP_CHAIN_MEMPOOL_HDR})

target_link_libraries(${PROJECT_NAME} dap_http_server dap_client dap_chain_net dap_global_db dap_core dap_json_rpc dap_chain_cs_blocks)
target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../dap-sdk/3rdparty/json-c)
