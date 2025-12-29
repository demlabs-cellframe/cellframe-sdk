cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_core)

file(GLOB DAP_CHAIN_NET_CORE_SRCS *.c)
file(GLOB DAP_CHAIN_NET_CORE_HEADERS include/*.h)

cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_NET_CORE_SRCS} HEADERS ${DAP_CHAIN_NET_CORE_HEADERS})

# Low-level network utilities - depends on common and chain (NOT net!)
target_link_libraries(${PROJECT_NAME} 
    dap_core dap_cli_server dap_json_rpc dap_chain dap_common)

target_include_directories(${PROJECT_NAME} PUBLIC include)

if (INSTALL_SDK)
    set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NET_CORE_HEADERS}")
    INSTALL(TARGETS ${PROJECT_NAME}
            LIBRARY DESTINATION lib/modules/net-core/
            ARCHIVE DESTINATION lib/modules/net-core/
            PUBLIC_HEADER DESTINATION include/modules/net-core/
    )
endif()

