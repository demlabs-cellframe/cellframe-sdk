cmake_minimum_required(VERSION 3.10)
project(dap_chain_node_cli_cmd)

file(GLOB DAP_CHAIN_NODE_CLI_CMD_SRCS *.c)
file(GLOB DAP_CHAIN_NODE_CLI_CMD_HEADERS include/*.h)

message("[+] Module 'node-cli-cmd' (high-level CLI commands)")

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_NODE_CLI_CMD_SRCS} HEADERS ${DAP_CHAIN_NODE_CLI_CMD_HEADERS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

# High-level module - can depend on everything (no cycles because nothing depends on it)
target_link_libraries(${PROJECT_NAME} 
    dap_core 
    dap_crypto 
    dap_client 
    dap_io 
    dap_notify_srv 
    dap_cli_server 
    dap_global_db
    dap_json_rpc
    dap_chain 
    dap_chain_datum
    dap_chain_wallet
    dap_chain_net 
    dap_chain_ledger 
    dap_chain_net_srv 
    dap_chain_mempool 
    dap_chain_cs
    dap_chain_type_blocks
    dap_chain_cs_esbocs
    dap_chain_net_srv_stake
    dap_chain_net_srv_xchange
)

if(LINUX)
    target_link_libraries(${PROJECT_NAME} resolv)
endif()

if(INSTALL_SDK)
    set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NODE_CLI_CMD_HEADERS}")
    INSTALL(TARGETS ${PROJECT_NAME}
            LIBRARY DESTINATION lib/modules/node-cli-cmd/
            ARCHIVE DESTINATION lib/modules/node-cli-cmd/
            PUBLIC_HEADER DESTINATION include/modules/node-cli-cmd/
    )
endif()

