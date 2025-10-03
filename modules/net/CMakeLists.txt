cmake_minimum_required(VERSION 3.10)

project (dap_chain_net)

file(GLOB DAP_CHAIN_NET_SRCS *.c)
file(GLOB DAP_CHAIN_NET_HEADERS include/*.h)

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_NET_SRCS} HEADERS ${DAP_CHAIN_NET_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_client dap_dns_server dap_io dap_notify_srv dap_global_db dap_json_rpc
                                        dap_chain dap_chain_datum dap_chain_wallet dap_chain_ledger dap_chain_cs 
                                        dap_chain_type_blocks dap_chain_cs_esbocs dap_chain_net_srv dap_chain_node_cli_cmd)

target_include_directories(${PROJECT_NAME} INTERFACE . )
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../dap-sdk/3rdparty/uthash/src)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NET_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/net/
        ARCHIVE DESTINATION lib/modules/net/
        PUBLIC_HEADER DESTINATION include/modules/net/
)
endif()
