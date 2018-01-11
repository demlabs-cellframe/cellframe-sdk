cmake_minimum_required(VERSION 2.8)
project (libdap-chain)
  
set(DAP_CHAIN_SRCS 
	dap_chain_common.c
	dap_chain_block.c 
	dap_chain_block_section.c 
	dap_chain_block_roots.c
	dap_chain.c
	dap_chain_coin.c  
	dap_chain_srv.c  
	dap_chain_tx.c)

set(DAP_CHAIN_HEADERS
	dap_chain_block.h
	dap_chain_block_section.h
	dap_chain_block_roots.h
	dap_chain.h
	dap_chain_common.h
	dap_chain_coin.h
	dap_chain_srv.h
	dap_chain_tx.h
    )

include_directories("${dap_core_INCLUDE_DIRS}")
add_definitions ("${dap_core_DEFINITIONS}")

include_directories("${dap_crypto_INCLUDE_DIRS}")
add_definitions ("${dap_crypto_DEFINITIONS}")

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_SRCS} ${DAP_CHAIN_HEADERS})

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
