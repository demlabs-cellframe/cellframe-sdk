cmake_minimum_required(VERSION 2.8)
project (dap_chain_cs_block_poa)
  
set(DAP_CHAIN_BLOCK_CS_POA_SRCS *.c)
set(DAP_CHAIN_BLOCK_CS_POA_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_BLOCK_CS_POA_SRCS} ${DAP_CHAIN_BLOCK_CS_POA_HEADERS})
add_definitions ("-DDAP_CHAIN_BLOCK_CS_POA")


target_link_libraries(dap_chain_cs_block_poa dap_core dap_crypto dap_chain dap_chain_crypto dap_chain_cs_block )
target_include_directories(dap_chain_cs_block_poa INTERFACE .)

