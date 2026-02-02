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

# Include mempool headers for emission-based TX (no link dep - resolved at final link)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../mempool/include/)
# Include net headers for dap_chain_net_get_default_chain_by_chain_type
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../net/include/)
# Include DAG type headers for event/datum extraction
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../type/dag/include/)
# Include common headers for datum hash calculation
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../common/include/)

# Dependencies - ONLY low-level modules, NO wallet/net/mempool link deps!
target_link_libraries(${PROJECT_NAME}
    dap_core
    dap_chain
    dap_chain_tx_compose  # NEW TX Compose API
    dap_cli_server
    dap_json_rpc
)

# CLI accesses mempool via extern declarations - resolved at final cellframe_sdk link





