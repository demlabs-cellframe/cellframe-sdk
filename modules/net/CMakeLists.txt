cmake_minimum_required(VERSION 3.10)

# Main net module
project (dap_chain_net)

# Core submodule MUST be first (contains network registry)
add_subdirectory(core)
add_subdirectory(decree)

# Main net sources (after core)
file(GLOB DAP_CHAIN_NET_SRCS *.c)
file(GLOB DAP_CHAIN_NET_HEADERS include/*.h)

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_NET_SRCS} HEADERS ${DAP_CHAIN_NET_HEADERS})

# OBJECT library: net depends on net/core + rpc (in common) + ledger + mempool
target_link_libraries(${PROJECT_NAME} 
    dap_core dap_crypto dap_client dap_link_manager dap_dns_server
    dap_io dap_notify_srv dap_global_db dap_json_rpc dap_cli_server dap_chain_net_core
    dap_chain dap_chain_datum dap_chain_cs dap_common dap_chain_ledger dap_chain_mempool)
# REMOVED: dap_chain_rpc - RPC callbacks are now in dap_common module
# NO dap_chain_net_srv - creates cycle (srv depends on net for high-level operations)
# Net CLI needs srv HEADERS but not linking (to avoid cycle)
target_include_directories(${PROJECT_NAME} PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/srv/base/include
    ${CMAKE_CURRENT_SOURCE_DIR}/tx/include)
# NO dap_chain_net_tx - would create cycle (net-tx depends on net)
# dap_chain_ledger - normal dependency: net (high) → ledger (mid-level)
# dap_chain_net_srv - unidirectional: net (high) → srv (lower), NO CYCLE
target_include_directories(${PROJECT_NAME} INTERFACE . )
target_include_directories(${PROJECT_NAME} PUBLIC include)

# Submodules (after main net)
add_subdirectory(tx)       # High-level TX operations
add_subdirectory(srv)      # Network services (has own submodules)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NET_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/net/
        ARCHIVE DESTINATION lib/modules/net/
        PUBLIC_HEADER DESTINATION include/modules/net/
)
endif()

