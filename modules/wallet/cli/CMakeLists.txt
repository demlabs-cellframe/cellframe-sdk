cmake_minimum_required(VERSION 3.10)
project(dap_chain_wallet_cli)

file(GLOB DAP_CHAIN_WALLET_CLI_SRCS *.c)
file(GLOB DAP_CHAIN_WALLET_CLI_HEADERS *.h)

cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_WALLET_CLI_SRCS} HEADERS ${DAP_CHAIN_WALLET_CLI_HEADERS})

target_link_libraries(${PROJECT_NAME} 
    dap_core dap_crypto dap_common dap_chain
    dap_chain_wallet        # Uses wallet API
    dap_chain_wallet_shared # Uses wallet shared module (propagates includes)
    dap_chain_ledger        # Uses ledger for balance display
    dap_chain_net           # Uses net for network operations
    dap_cli_server)         # CLI framework

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC .)
# NOTE: All other includes propagated through dependencies!

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_WALLET_CLI_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/wallet/cli/
        ARCHIVE DESTINATION lib/modules/wallet/cli/
        PUBLIC_HEADER DESTINATION include/modules/wallet/cli/
)
endif()

