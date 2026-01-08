cmake_minimum_required(VERSION 3.10)
project(dap_chain_wallet_shared)

file(GLOB DAP_CHAIN_WALLET_SHARED_SRCS *.c)
file(GLOB DAP_CHAIN_WALLET_SHARED_HEADERS include/*.h)

cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_WALLET_SHARED_SRCS} HEADERS ${DAP_CHAIN_WALLET_SHARED_HEADERS})

target_link_libraries(${PROJECT_NAME} 
    dap_core dap_crypto dap_common dap_chain
    dap_chain_ledger    # Uses ledger for TX tracking
    dap_chain_mempool   # Uses mempool for TX status and notify
    dap_chain_wallet    # Uses wallet types
    dap_chain_wallet_cache)  # Uses cache for address lookups

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} INTERFACE include)
target_include_directories(${PROJECT_NAME} PUBLIC include)
# NOTE: All other includes propagated through dependencies!

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_WALLET_SHARED_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/wallet-shared/
        ARCHIVE DESTINATION lib/modules/wallet-shared/
        PUBLIC_HEADER DESTINATION include/modules/wallet-shared/
)
endif()

