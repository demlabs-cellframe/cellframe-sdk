cmake_minimum_required(VERSION 2.8)
project (dap_chain_mempool)

file(GLOB DAP_CHAIN_MEMPOOL_SRC *.c)
file(GLOB DAP_CHAIN_MEMPOOL_HDR include/*.h)

if(WIN32)
  include_directories(../../../3rdparty/wepoll/)
  include_directories(../../../3rdparty/uthash/src/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_MEMPOOL_SRC} ${DAP_CHAIN_MEMPOOL_HDR})

target_link_libraries(dap_chain_mempool dap_http_server dap_client dap_chain_net dap_chain_global_db dap_core)
target_include_directories(dap_chain_mempool INTERFACE .)
