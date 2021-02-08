cmake_minimum_required(VERSION 3.0)
project (dap_chain_cs_none)
  
file(GLOB DAP_CHAIN_CS_NO_CONSENSUS_SRC *.c)
file(GLOB DAP_CHAIN_CS_NO_CONSENSUS_HDR include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_CS_NO_CONSENSUS_SRC} ${DAP_CHAIN_CS_NO_CONSENSUS_HDR})

target_link_libraries(${PROJECT_NAME} dap_core dap_chain dap_chain_global_db dap_chain_mempool dap_chain_net)
target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
