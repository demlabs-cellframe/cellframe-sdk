cmake_minimum_required(VERSION 3.10)
project(dap_chain_net_tx)

file(GLOB DAP_CHAIN_NET_TX_SRCS *.c)
file(GLOB DAP_CHAIN_NET_TX_HEADERS include/*.h)

message("[+] Module 'net-tx' (high-level TX operations with wallet integration)")

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_NET_TX_SRCS} HEADERS ${DAP_CHAIN_NET_TX_HEADERS})

# High-level module: net-tx is TX composition layer (NO stake - breaks cycle)
target_link_libraries(${PROJECT_NAME} 
    dap_core dap_crypto
    dap_chain dap_chain_datum dap_chain_ledger
    dap_chain_net dap_chain_wallet dap_chain_mempool
    dap_chain_type_blocks dap_chain_net_srv
)
# NO dap_chain_net_srv_stake - breaks net-tx ↔ stake cycle

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
# Stake headers for TYPES ONLY (header-only, NOT link - breaks cycle)
# This is acceptable: net-tx needs stake TYPES, stake needs net-tx SYMBOLS (one-way linker dependency)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/modules/service/stake/include)

if (INSTALL_SDK)
    set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NET_TX_HEADERS}")
    INSTALL(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib/modules/net-tx/
        ARCHIVE DESTINATION lib/modules/net-tx/
        PUBLIC_HEADER DESTINATION include/modules/net-tx/
    )
endif()
