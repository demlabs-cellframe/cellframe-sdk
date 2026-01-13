cmake_minimum_required(VERSION 3.10)
project(dap_chain_wallet_cache)

file(GLOB DAP_CHAIN_WALLET_CACHE_SRCS *.c)
file(GLOB DAP_CHAIN_WALLET_CACHE_HEADERS include/*.h)

cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_WALLET_CACHE_SRCS} HEADERS ${DAP_CHAIN_WALLET_CACHE_HEADERS})

target_link_libraries(${PROJECT_NAME} 
    dap_core dap_crypto dap_common dap_chain
    dap_chain_ledger    # Uses ledger for address lookups
    dap_chain_wallet    # Uses wallet types
    dap_chain_mempool   # For mempool_check functions
    dap_chain_net)      # TODO: Remove when s_wallet_opened_callback refactored!
    # NOTE: dap_chain_net kept TEMPORARILY for legacy callbacks iteration
    # Net module should call dap_chain_wallet_cache_register_chain() instead!

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
# NOTE: All other includes propagated through dependencies!

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_WALLET_CACHE_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/wallet-cache/
        ARCHIVE DESTINATION lib/modules/wallet-cache/
        PUBLIC_HEADER DESTINATION include/modules/wallet-cache/
)
endif()

