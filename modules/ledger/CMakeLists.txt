cmake_minimum_required(VERSION 3.10)

project (dap_chain_ledger)

# Add CLI subdirectory FIRST (creates OBJECT library)
add_subdirectory(cli)

# Ledger source files - EXCLUDING old CLI and decree (decree -> future governance module)
file(GLOB DAP_CHAIN_LEDGER_SRCS 
    dap_chain_ledger.c
    dap_chain_ledger_tx.c  
    # dap_chain_ledger_decree.c  # DISABLED - requires decree datum and should be in governance module
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
    dap_chain_datum_tx dap_chain_tx_sign dap_chain_tx_compose
    dap_chain_ledger_cli)  # New modular CLI
# Ledger is LOW-LEVEL independent module - NO dependencies on higher layers
# REMOVED dap_chain_wallet - creates cycle (wallet ↔ ledger) - use callbacks
# REMOVED dap_chain_mempool - creates cycle (mempool ↔ ledger) - use callbacks
# REMOVED dap_chain_net - creates cycle (net depends on ledger) - ledger is independent
# REMOVED dap_chain_net_tx - creates cycle (net-tx ↔ ledger) - use callbacks
# REMOVED blocks includes - creates cycle (blocks → ledger, ledger → blocks)
# REMOVED esbocs includes - creates cycle (esbocs → ledger, ledger → esbocs)
target_include_directories(${PROJECT_NAME} INTERFACE . )
target_include_directories(${PROJECT_NAME} PUBLIC include)
# Ledger uses ONLY: callbacks, forward declarations, and types passed as parameters
# NO PRIVATE includes to higher-level modules - ledger is foundation layer

# Add tests subdirectory if testing is enabled
if(BUILD_CELLFRAME_SDK_TESTS)
    message("[+] Adding ledger tests subdirectory")
    add_subdirectory(tests)
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
