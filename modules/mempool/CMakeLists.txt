cmake_minimum_required(VERSION 3.10)
project (dap_chain_mempool)

file(GLOB DAP_CHAIN_MEMPOOL_SRC *.c)
file(GLOB DAP_CHAIN_MEMPOOL_HDR include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_MEMPOOL_SRC} ${DAP_CHAIN_MEMPOOL_HDR})

target_link_libraries(${PROJECT_NAME} dap_http_server dap_client dap_chain_net dap_chain_global_db dap_core)
target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
