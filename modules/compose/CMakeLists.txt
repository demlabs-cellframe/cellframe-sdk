
cmake_minimum_required(VERSION 3.10)
project (dap_compose)
  
file(GLOB DAP_CHAIN_COMPOSE_SRCS  *.c)
file(GLOB DAP_CHAIN_COMPOSE_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_COMPOSE_SRCS} ${DAP_CHAIN_COMPOSE_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_client dap_io dap_notify_srv dap_cli_server dap_chain dap_chain_wallet
                                                dap_chain_net_srv dap_chain_net_srv_voting dap_chain_mempool dap_global_db dap_chain_net_srv_xchange dap_chain_cs_none
                                                dap_stream_ch_chain_net dap_chain_cs_esbocs dap_json_rpc )
target_include_directories(${PROJECT_NAME} PUBLIC include/ )
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../dap-sdk/3rdparty/json-c)


if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_COMPOSE_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/compose/
        ARCHIVE DESTINATION lib/modules/compose/
        PUBLIC_HEADER DESTINATION include/modules/compose/
)
endif()
