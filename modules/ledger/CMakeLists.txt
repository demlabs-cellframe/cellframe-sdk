cmake_minimum_required(VERSION 3.10)

project (dap_chain_ledger)

# Add CLI subdirectory FIRST (creates OBJECT library)
add_subdirectory(cli)

# Ledger source files - EXCLUDING old CLI and decree (decree -> governance module)
file(GLOB DAP_CHAIN_LEDGER_SRCS 
    dap_chain_ledger.c
    dap_chain_ledger_callbacks.c
    dap_chain_ledger_tx.c
    dap_chain_ledger_anchor.c
    dap_chain_ledger_event.c
    dap_chain_ledger_token.c
    dap_chain_ledger_json.c
    # dap_chain_ledger_decree.c  # DISABLED - moved to governance module
    dap_chain_ledger_cli_error_codes.c
    # OLD CLI dap_chain_ledger_cli.c is DISABLED - using new modular CLI in cli/ subdirectory
)
file(GLOB DAP_CHAIN_LEDGER_HEADERS include/*.h)

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_LEDGER_SRCS} HEADERS ${DAP_CHAIN_LEDGER_HEADERS})

# OBJECT library: ledger
target_link_libraries(${PROJECT_NAME} 
    dap_core dap_crypto dap_notify_srv dap_chain dap_global_db dap_json_rpc dap_common
    dap_http_server dap_chain_datum dap_cli_server dap_chain_net_core
    dap_chain_tx_compose
    dap_chain_ledger_cli
    dap_chain_wallet dap_timer)  # Wallet is LOWER than ledger (crypto + keys only, no ledger deps)
# REMOVED dap_chain_mempool - creates CYCLE (mempool depends on ledger already)
# Mempool will register callbacks in ledger if needed
target_include_directories(${PROJECT_NAME} INTERFACE . )
target_include_directories(${PROJECT_NAME} PUBLIC include)

# Add tests subdirectory if testing is enabled
if(BUILD_CELLFRAME_SDK_TESTS)
    message("[+] Adding ledger tests subdirectory")
else()
    message("[-] Ledger tests disabled (BUILD_CELLFRAME_SDK_TESTS=${BUILD_CELLFRAME_SDK_TESTS})")
endif()

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_LEDGER_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/ledger/
        ARCHIVE DESTINATION lib/modules/ledger/
        PUBLIC_HEADER DESTINATION include/modules/ledger/
)
endif() 
