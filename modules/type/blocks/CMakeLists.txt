cmake_minimum_required(VERSION 3.10)
project (dap_chain_cs_blocks)
  
file(GLOB DAP_CHAIN_BLOCK_SRCS *.c)
file(GLOB DAP_CHAIN_BLOCK_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_BLOCK_SRCS} ${DAP_CHAIN_BLOCK_HEADERS})


target_link_libraries(dap_chain_cs_blocks dap_core dap_crypto dap_chain )
target_include_directories(dap_chain_cs_blocks INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
