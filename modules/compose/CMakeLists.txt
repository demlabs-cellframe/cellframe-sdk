cmake_minimum_required(VERSION 3.10)
project (dap_compose)
  
file(GLOB DAP_CHAIN_COMPOSE_SRCS  *.c)
file(GLOB DAP_CHAIN_COMPOSE_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_COMPOSE_SRCS} ${DAP_CHAIN_COMPOSE_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_cli_server dap_chain_net dap_chain_net_srv dap_enc_server dap_json_rpc dap_chain_net_srv_xchange dap_chain_net_srv_voting dap_app_cli dap_cli_server)
target_include_directories(${PROJECT_NAME} PUBLIC include/ )
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../dap-sdk/3rdparty/json-c)

if(BUILD_CELLFRAME_SDK_TESTS)
    add_subdirectory(tests)
endif()

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_COMPOSE_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/compose/
        ARCHIVE DESTINATION lib/modules/compose/
        PUBLIC_HEADER DESTINATION include/modules/compose/
)
endif()
