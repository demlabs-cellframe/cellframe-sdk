cmake_minimum_required(VERSION 2.8)
project (dap_chain_cs_block)
  
file(GLOB DAP_CHAIN_BLOCK_SRCS *.c)
file(GLOB DAP_CHAIN_BLOCK_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_BLOCK_SRCS} ${DAP_CHAIN_BLOCK_HEADERS})


target_link_libraries(dap_chain_cs_block dap_core dap_crypto dap_chain )
target_include_directories(dap_chain_cs_block INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
