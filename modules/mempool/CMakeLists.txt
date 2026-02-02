cmake_minimum_required(VERSION 3.10)
project (dap_chain_mempool)

file(GLOB DAP_CHAIN_MEMPOOL_SRC *.c)
file(GLOB DAP_CHAIN_MEMPOOL_HDR include/*.h)

cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_MEMPOOL_SRC} HEADERS ${DAP_CHAIN_MEMPOOL_HDR})

# Mid-level module: mempool depends ONLY on lower layers (ledger, net_core)
# TODO: Remove direct calls to wallet/net_tx functions, use callbacks instead
target_link_libraries(${PROJECT_NAME} 
    dap_http_server dap_client dap_global_db dap_core dap_json_rpc dap_cli_server
    dap_chain dap_chain_datum dap_common dap_chain_net_core dap_chain_ledger)
# REMOVED dap_chain_net - creates cycle (net ↔ mempool)
# TEMPORARY: mempool still uses dap_chain_wallet_get_list_tx_outs_with_val and dap_chain_net_tx_get_fee
# These create cycles and must be replaced with callbacks
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../net/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../wallet/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../wallet-cache/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../net/tx/include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_MEMPOOL_HDR}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/mempool/
        ARCHIVE DESTINATION lib/modules/mempool/
        PUBLIC_HEADER DESTINATION include/modules/mempool/
        )
endif()