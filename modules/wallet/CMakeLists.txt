cmake_minimum_required(VERSION 3.10)
project (dap_chain_wallet)

# PURE wallet sources - only key management and signing
file(GLOB DAP_CHAIN_WALLET_SRCS 
    dap_chain_wallet.c 
    dap_chain_wallet_ops.c 
    dap_chain_coin.c
    dap_chain_wallet_cli_error_codes.c
    ../../3rdparty/crc32c_adler/crc32c_adler.c)

file(GLOB DAP_CHAIN_WALLET_HEADERS include/*.h)
include_directories(../../3rdparty/crc32c_adler)

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_WALLET_SRCS} HEADERS ${DAP_CHAIN_WALLET_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_common dap_chain_datum dap_chain dap_chain_wallet_cache)
# REMOVED ALL UPPER LAYER DEPENDENCIES:
# - dap_chain_tx_compose - TX creation moved to wallet-tx module
# - dap_chain_net - wallet doesn't need network layer
# - dap_chain_mempool - moved to wallet-shared module
# - dap_chain_ledger - moved to wallet-cache, wallet-shared, wallet-tx modules
# Wallet is PURE: only keys, addresses, and signing

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

# Add CLI subdirectory
add_subdirectory(cli)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_WALLET_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/wallet/
        ARCHIVE DESTINATION lib/modules/wallet/
        PUBLIC_HEADER DESTINATION include/modules/wallet/
)
endif()
