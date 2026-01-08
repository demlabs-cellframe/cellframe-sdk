cmake_minimum_required(VERSION 3.10)
project(dap_chain_wallet_tx)

file(GLOB DAP_CHAIN_WALLET_TX_SRCS *.c)
file(GLOB DAP_CHAIN_WALLET_TX_HEADERS include/*.h wallet-tx/include/*.h)

cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_WALLET_TX_SRCS} HEADERS ${DAP_CHAIN_WALLET_TX_HEADERS})

target_link_libraries(${PROJECT_NAME} 
    dap_core dap_crypto dap_common dap_chain_datum dap_chain
    dap_chain_tx_compose  # TX Compose API
    dap_chain_ledger      # Uses ledger for signing via dap_ledger_sign_data
    dap_chain_wallet      # Uses wallet types
    dap_chain_mempool)    # For token_cli.c
target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC wallet-tx/include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_WALLET_TX_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/net/tx/wallet-tx/
        ARCHIVE DESTINATION lib/modules/net/tx/wallet-tx/
        PUBLIC_HEADER DESTINATION include/modules/net/tx/wallet-tx/
)
endif()

