cmake_minimum_required(VERSION 2.8)
project (dap-chain)
  
set(DAP_CHAIN_SRCS 
	dap_chain_common.c
        dap_chain_mine.c
	dap_chain_block.c 
        dap_chain_block_cache.c
        dap_chain_block_txs.c
	dap_chain_section.c 
	dap_chain_section_roots.c
        dap_chain_section_tx.c
        dap_chain_section_coin.c
        dap_chain.c
        dap_chain_ops.c
        dap_chain_coin.c
	dap_chain_srv.c  
        dap_hash.c
        dap_hash_fusion.c
        dap_hash_keccak.c
        dap_hash_slow.c
        dap_chain_wallet.c
        )

set(DAP_CHAIN_HEADERS
        dap_chain_ops.h
        dap_chain.h
        dap_chain_mine.h
        dap_chain_mine_task.h
        dap_chain_block.h
        dap_chain_block_cache.h
        dap_chain_internal.h
        dap_chain_common.h
	dap_chain_coin.h
	dap_chain_srv.h
	dap_chain_section.h
	dap_chain_section_roots.h
	dap_chain_section_tx.h
        dap_chain_section_tx_in.h
        dap_chain_section_tx_out.h
        dap_chain_section_tx_pkey.h
        dap_chain_section_tx_sig.h
        dap_hash.h
        dap_hash_fusion.h
        dap_hash_keccak.h
        dap_hash_slow.h
        dap_chain_wallet.h
        dap_chain_wallet_internal.h
    )

add_subdirectory(monero_crypto)

include_directories("${monero_crypto_INCLUDE_DIRS}")
add_definitions ("${monero_crypto_DEFINITIONS}")

include_directories("${dap_core_INCLUDE_DIRS}")
include_directories("${dap_crypto_INCLUDE_DIRS}")

add_definitions ("${dap_core_DEFINITIONS}")
add_definitions ("${dap_crypto_DEFINITIONS}")



add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_SRCS} ${DAP_CHAIN_HEADERS})

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
