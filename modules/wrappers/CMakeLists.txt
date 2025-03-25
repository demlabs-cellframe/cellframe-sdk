cmake_minimum_required(VERSION 3.10)
project (dap_jni_wrappers)
  
find_package (Java REQUIRED)
find_package (JNI REQUIRED)
include (UseJava)

file(GLOB DAP_JNI_WRAPPERS_SRCS *.c)

file(GLOB DAP_JNI_WRAPPERS_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_JNI_WRAPPERS_SRCS} ${DAP_JNI_WRAPPERS_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_client dap_io dap_notify_srv dap_cli_server dap_chain dap_chain_wallet
                                        dap_chain_net_srv dap_chain_net_srv_voting dap_chain_mempool dap_global_db dap_chain_net_srv_xchange dap_chain_cs_none
                                        dap_stream_ch_chain_net dap_chain_cs_esbocs dap_json_rpc )
if(LINUX)
    target_link_libraries(${PROJECT_NAME} resolv)
endif()

target_include_directories(${PROJECT_NAME} INTERFACE . )
target_include_directories(${PROJECT_NAME} PUBLIC include)
include_directories(${JNI_INCLUDE_DIRS})

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NET_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/net/
        ARCHIVE DESTINATION lib/modules/net/
        PUBLIC_HEADER DESTINATION include/modules/net/
)
endif()
