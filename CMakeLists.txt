project(cellframe-sdk C)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_STANDARD 11)
set(CELLFRAME_SDK_NATIVE_VERSION "1.4-0")
include(cmake/OS_Detection.cmake)
add_definitions ("-DCELLFRAME_SDK_VERSION=\"${CELLFRAME_SDK_NATIVE_VERSION}\"")

add_subdirectory(libdap)
add_subdirectory(libdap-app-cli)
add_subdirectory(libdap-crypto)
add_subdirectory(libdap-chain)
add_subdirectory(libdap-chain-common)
add_subdirectory(libdap-chain-crypto)
add_subdirectory(libdap-chain-wallet)
add_subdirectory(libdap-chain-mempool)
add_subdirectory(libdap-chain-net)
add_subdirectory(libdap-server-core)
add_subdirectory(libdap-chain-global-db)
add_subdirectory(libdap-client)
add_subdirectory(libdap-server)
add_subdirectory(libdap-stream)
add_subdirectory(libdap-stream-ch)
add_subdirectory(libdap-stream-ch-chain-net)
add_subdirectory(libdap-stream-ch-chain)
add_subdirectory(libdap-server-udp)
add_subdirectory(libdap-chain-net-srv)
add_subdirectory(libdap-chain-net-srv-app)
add_subdirectory(libdap-chain-net-srv-app-db)
add_subdirectory(libdap-chain-net-srv-datum)
add_subdirectory(libdap-chain-net-srv-datum-pool)
if(NOT (WIN32))
  add_subdirectory(libdap-chain-net-srv-vpn)
endif()

add_subdirectory(libdap-chain-gdb)
add_subdirectory(libdap-stream-ch-chain-net-srv)
add_subdirectory(libdap-chain-cs-dag)
add_subdirectory(libdap-chain-cs-dag-poa)
add_subdirectory(libdap-chain-cs-dag-pos)

add_library(${PROJECT_NAME} STATIC cellframe-sdk.c)

if(NOT (WIN32))
    target_link_libraries(${PROJECT_NAME}  dap_core dap_crypto dap_crypto dap_server_core dap_enc_server dap_udp_server dap_session
            dap_enc_server dap_stream dap_stream_ch_chain dap_stream_ch_chain_net
            dap_stream_ch_chain_net_srv dap_chain dap_chain_crypto dap_client
            dap_chain_cs_dag dap_chain_cs_dag_poa dap_chain_cs_dag_pos
            dap_chain_net dap_chain_net_srv
            dap_chain_net_srv_vpn dap_chain_net_srv_app  dap_chain_net_srv_app_db
            dap_chain_net_srv_datum  dap_chain_net_srv_datum_pool
            dap_chain_wallet dap_chain_global_db dap_chain_mempool dap_chain_gdb m magic
            )
else()
    target_link_libraries(${PROJECT_NAME}  dap_core dap_crypto dap_crypto dap_server_core dap_enc_server dap_udp_server dap_session
        dap_enc_server dap_stream dap_stream_ch_chain dap_stream_ch_chain_net
        dap_stream_ch_chain_net_srv dap_chain dap_chain_crypto dap_client
        dap_chain_cs_dag dap_chain_cs_dag_poa dap_chain_cs_dag_pos
        dap_chain_net dap_chain_net_srv
        dap_chain_net_srv_app  dap_chain_net_srv_app_db
        dap_chain_net_srv_datum  dap_chain_net_srv_datum_pool
        dap_chain_wallet dap_chain_global_db dap_chain_mempool dap_chain_gdb
        )
endif()
#target_link_libraries(${PROJECT_NAME} dap_core dap_crypto)

#target_include_directories(${PROJECT_NAME} INTERFACE include/)


#file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/src/libdapConnector.py
#        DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)

#file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/test/main_test.py
#            DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)

#if(BUILD_DAP_TESTS)
#    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/test/main_test.py
#            DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)
#    enable_testing()
    #add_subdirectory(test)
#endif()
