cmake_minimum_required(VERSION 3.10)
project(dap_chain_ledger_cli)

# CLI module files
file(GLOB LEDGER_CLI_SRCS 
    *.c
)
file(GLOB LEDGER_CLI_HEADERS include/*.h)

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${LEDGER_CLI_SRCS} HEADERS ${LEDGER_CLI_HEADERS})

target_include_directories(${PROJECT_NAME} PUBLIC include/)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include/)

# Dependencies - ONLY low-level modules, NO wallet/net/mempool!
target_link_libraries(${PROJECT_NAME}
    dap_core
    dap_chain
    dap_chain_tx_compose  # NEW TX Compose API
    dap_cli_server
    dap_json_rpc
)

# CLI accesses wallet/net/mempool ONLY via ledger callbacks - zero cycles!





