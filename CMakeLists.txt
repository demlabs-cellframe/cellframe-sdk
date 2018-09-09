cmake_minimum_required(VERSION 2.8)
project (dap_chain_wallet)
  
set(DAP_CHAIN_WALLET_SRCS 
	dap_chain_wallet.c 
	dap_chain_coin.c 
        )

set(DAP_CHAIN_WALLET_HEADERS
        dap_chain_coin.h
        dap_chain_wallet.h
        dap_chain_wallet_internal.h
    )

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_WALLET_SRCS} ${DAP_CHAIN_WALLET_HEADERS})


target_link_libraries(dap_chain_wallet dap_core dap_crypto dap_chain dap_chain_crypto )

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
