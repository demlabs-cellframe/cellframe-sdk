cmake_minimum_required(VERSION 3.10)
project (dap_compose)
  
file(GLOB DAP_CHAIN_COMPOSE_SRCS  *.c)
file(GLOB DAP_CHAIN_COMPOSE_HEADERS include/*.h)

message("[+] Module 'compose'")
# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_COMPOSE_SRCS} HEADERS ${DAP_CHAIN_COMPOSE_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_sdk dap_app_cli dap_chain_net dap_client_http dap_chain_net_srv_stake_ext)
target_include_directories(${PROJECT_NAME} PUBLIC include/ )
target_compile_definitions(${PROJECT_NAME} PRIVATE _GNU_SOURCE)

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
