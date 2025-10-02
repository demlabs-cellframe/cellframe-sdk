cmake_minimum_required(VERSION 3.10)
project (dap_chain_node_cli)
  

# Basic CLI infrastructure + command registration
# Command implementations in node-cli-cmd module
set(DAP_CHAIN_NODE_CLI_SRCS 
    dap_chain_node_cli.c
)
file(GLOB DAP_CHAIN_NODE_CLI_HEADERS include/*.h)

#if (ANDROID)
#    set(DAP_CHAIN_NODE_CLI_HEADERS ${DAP_CHAIN_NODE_CLI_HEADERS}
#        android/ifaddrs-android.h
#    )
#endif()

set(IPUTILS_INCLUDE_DIRS
     ../../3rdparty/iputils/traceroute/
    )

if(LINUX)
    file(GLOB IPUTILS_SRCS ../../3rdparty/iputils/*.c ../../3rdparty/iputils/traceroute/*.c)
    file(GLOB IPUTILS_HEADERS ../../3rdparty/iputils/*.h ${IPUTILS_INCLUDE_DIRS}*.h)
    set_source_files_properties(../../3rdparty/iputils/traceroute/clif.c PROPERTIES COMPILE_FLAGS -Wno-stringop-truncation)
endif()

if(WIN32)
  add_compile_definitions(_GNU_SOURCE)
endif()

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_NODE_CLI_SRCS} ${IPUTILS_SRCS} HEADERS ${DAP_CHAIN_NODE_CLI_HEADERS} ${IPUTILS_HEADERS})

# Minimal dependencies - commands implemented in high-level node-cli-cmd module
target_link_libraries(${PROJECT_NAME} dap_core dap_cli_server dap_chain dap_chain_datum dap_chain_wallet 
                                        dap_chain_net dap_chain_ledger dap_chain_net_srv dap_chain_mempool dap_global_db dap_json_rpc)
if(LINUX)
    target_link_libraries(${PROJECT_NAME} resolv)
endif()

target_include_directories(${PROJECT_NAME} INTERFACE . )
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../dap-sdk/3rdparty/uthash/src)

if (!WIN32)
    target_include_directories(${PROJECT_NAME} PUBLIC ${IPUTILS_INCLUDE_DIRS})
endif()

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NODE_CLI_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/node-cli/
        ARCHIVE DESTINATION lib/modules/node-cli/
        PUBLIC_HEADER DESTINATION include/modules/node-cli/
)
endif()
