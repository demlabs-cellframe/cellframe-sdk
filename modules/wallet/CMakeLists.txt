cmake_minimum_required(VERSION 3.10)
project (dap_chain_wallet)

file(GLOB DAP_CHAIN_WALLET_SRCS *.c ../../3rdparty/crc32c_adler/crc32c_adler.c)
file(GLOB DAP_CHAIN_WALLET_HEADERS include/*.h)
include_directories(../../3rdparty/crc32c_adler)

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_WALLET_SRCS} HEADERS ${DAP_CHAIN_WALLET_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_common dap_chain_datum dap_chain_tx_compose dap_chain 
    dap_chain_net dap_chain_mempool dap_chain_ledger)
# REMOVED: dap_cli_error_codes - error codes are now in respective CLI modules (wallet CLI, ledger CLI, etc.)
# datum/tx - TX Compose API для регистрации builders
# ledger - для dap_ledger_sign_data() и dap_chain_utxo.h
target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
# NO manual cmd includes - proper layering (wallet is low-level, cmd is high-level)


if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_WALLET_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/wallet/
        ARCHIVE DESTINATION lib/modules/wallet/
        PUBLIC_HEADER DESTINATION include/modules/wallet/
)
endif()
