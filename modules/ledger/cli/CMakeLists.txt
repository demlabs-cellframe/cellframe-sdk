cmake_minimum_required(VERSION 3.10)
project(dap_chain_ledger_cli)

# CLI module files
file(GLOB LEDGER_CLI_SRCS *.c)
file(GLOB LEDGER_CLI_HEADERS include/*.h)

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${LEDGER_CLI_SRCS} HEADERS ${LEDGER_CLI_HEADERS})

target_include_directories(${PROJECT_NAME} PUBLIC include/)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include/)

# Dependencies
target_link_libraries(${PROJECT_NAME}
    dap_core
    dap_chain
    dap_cli_server
    dap_json_rpc
)



