cmake_minimum_required(VERSION 3.10)
project (dap_chain_node)
  

file(GLOB DAP_CHAIN_NODE_SRCS *.c)

file(GLOB DAP_CHAIN_NODE_HEADERS include/*.h)

#if (ANDROID)
#    set(DAP_CHAIN_NODE_HEADERS ${DAP_CHAIN_NODE_HEADERS}
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

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NODE_SRCS} ${DAP_CHAIN_NODE_HEADERS} ${IPUTILS_SRCS} ${IPUTILS_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_client dap_io dap_notify_srv dap_cli_server dap_chain dap_chain_wallet
                                        dap_chain_mempool dap_global_db dap_chain_cs_esbocs dap_json_rpc)
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
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NODE_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/node/
        ARCHIVE DESTINATION lib/modules/node/
        PUBLIC_HEADER DESTINATION include/modules/node/
)
endif()
