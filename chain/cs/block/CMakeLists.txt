cmake_minimum_required(VERSION 2.8)
project (dap_chain_cs_block)
  
set(DAP_CHAIN_BLOCK_SRCS 
	dap_chain_block.c 
	dap_chain_cs_blocks.c
        dap_chain_block_cache.c
        )

set(DAP_CHAIN_BLOCK_HEADERS
    dap_chain_block.h
    dap_chain_cs_blocks.h
    dap_chain_block_cache.h
    )

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_BLOCK_SRCS} ${DAP_CHAIN_BLOCK_HEADERS})


target_link_libraries(dap_chain_cs_block dap_core dap_crypto dap_chain dap_chain_crypto )
target_include_directories(dap_chain_cs_block INTERFACE .)

