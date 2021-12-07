cmake_minimum_required(VERSION 3.0)
project (dap_chain_cs_block_pow)
  
file(GLOB DAP_CHAIN_BLOCK_CS_POW_SRCS *.c)
file(GLOB DAP_CHAIN_BLOCK_CS_POW_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_BLOCK_CS_POW_SRCS} ${DAP_CHAIN_BLOCK_CS_POW_HEADERS})


target_link_libraries(dap_chain_cs_block_pow dap_core dap_crypto dap_chain dap_chain_cs_block )
target_include_directories(dap_chain_block_cs_pow INTERFACE .)

