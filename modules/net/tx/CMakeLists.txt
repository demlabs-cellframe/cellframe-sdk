cmake_minimum_required(VERSION 3.10)
project(dap_chain_net_tx)  # CORRECT module name!

file(GLOB DAP_CHAIN_NET_TX_SRCS *.c)
file(GLOB DAP_CHAIN_NET_TX_HEADERS include/*.h wallet-tx/include/*.h)

# This module contains:
# - Token CLI (token_cli.c)
# - Wallet TX builders using Plugin API (dap_chain_wallet_tx.c)
# - Network TX utilities (dap_chain_net_tx.c)

cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_NET_TX_SRCS} HEADERS ${DAP_CHAIN_NET_TX_HEADERS})

target_link_libraries(${PROJECT_NAME} 
    dap_core dap_crypto dap_common dap_chain_datum dap_chain
    dap_chain_tx_compose  # TX Compose API
    dap_chain_ledger      # Uses ledger for signing via dap_ledger_sign_data
    dap_chain_wallet      # Uses wallet types
    dap_chain_wallet_cache  # For token_cli.c
    dap_chain_wallet_shared # For dap_chain_net_tx.c
    dap_chain_mempool     # For token_cli.c
    dap_chain_net_srv     # For net_srv.h
    dap_chain_type_blocks) # For type_blocks.h

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} INTERFACE include)
target_include_directories(${PROJECT_NAME} INTERFACE wallet-tx/include)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC wallet-tx/include)
# Include ledger CLI headers for com_token
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../ledger/cli/include)
# NOTE: All other includes propagated through dependencies!

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NET_TX_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/net/tx/
        ARCHIVE DESTINATION lib/modules/net/tx/
        PUBLIC_HEADER DESTINATION include/modules/net/tx/
)
endif()
