project(cellframe-sdk C)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_STANDARD 11)
set(CELLFRAME_SDK_NATIVE_VERSION "2.0-1")
include(cmake/OS_Detection.cmake)
add_definitions ("-DCELLFRAME_SDK_VERSION=\"${CELLFRAME_SDK_NATIVE_VERSION}\"")

add_subdirectory(dap-sdk)
add_subdirectory(3rdparty/monero_crypto)
add_subdirectory(3rdparty/cuttdb)
add_subdirectory(modules/)

add_library(${PROJECT_NAME} STATIC cellframe-sdk.c)

set(CELLFRAME_LIBS dap_core dap_crypto dap_crypto dap_server_core dap_enc_server dap_udp_server dap_session
            dap_enc_server dap_stream dap_stream_ch_chain dap_stream_ch_chain_net
            dap_stream_ch_chain_net_srv dap_chain dap_chain_crypto dap_client
            dap_chain_cs_dag dap_chain_cs_dag_poa dap_chain_cs_dag_pos
            dap_chain_net dap_chain_net_srv
            dap_chain_net_srv_vpn dap_chain_net_srv_app  dap_chain_net_srv_app_db
            dap_chain_net_srv_datum  dap_chain_net_srv_datum_pool
            dap_chain_wallet dap_chain_global_db dap_chain_mempool dap_chain_cs_none m magic pthread)

if (WIN32)
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} KERNEL32 USER32 SHELL32 WINMM GDI32 ADVAPI32
					 Ole32 Version Imm32 OleAut32 ws2_32 ntdll psapi 
					 Shlwapi Bcrypt Crypt32 Secur32 userenv )
endif()

target_link_libraries(${PROJECT_NAME} ${CELLFRAME_LIBS})
#if(BUILD_DAP_TESTS)
#    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/test/main_test.py
#            DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)
#    enable_testing()
    #add_subdirectory(test)
#endif()
