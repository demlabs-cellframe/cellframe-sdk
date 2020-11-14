project(cellframe-sdk C)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_STANDARD 11)
set(CELLFRAME_SDK_NATIVE_VERSION "2.7-4")
add_definitions ("-DCELLFRAME_SDK_VERSION=\"${CELLFRAME_SDK_NATIVE_VERSION}\"")


if (BUILD_TESTS)
    SET(DAPSDK_MODULES "")
    SET(DAPSDK_MODULES "${DAPSDK_MODULES} core crypto")
    SET(DAPSDK_MODULES "${DAPSDK_MODULES} network-core network-client network-server")
    include(cmake/OS_Detection.cmake)
    add_subdirectory(dap-sdk)
endif()

add_subdirectory(3rdparty/monero_crypto)
add_subdirectory(3rdparty/cuttdb)
add_subdirectory(modules/)

add_library(${PROJECT_NAME} STATIC cellframe-sdk.c)

# init libs
set(CELLFRAME_LIBS "")

# Core libs from dap-sdk
if (CELLFRAME_MODULES MATCHES "core")
    message("[+] Module 'core'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_core dap_crypto m pthread)
endif()

# General chain libs
if (CELLFRAME_MODULES MATCHES "chains")
    message("[+] Module 'chains'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_common dap_chain dap_chain_global_db dap_chain_wallet)
endif()

# Networking
if (CELLFRAME_MODULES MATCHES "network")
    message("[+] Module 'network'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_server_core dap_json_rpc dap_enc_server dap_http_server dap_session
	dap_stream dap_stream_ch dap_client dap_stream_ch_chain dap_stream_ch_chain_net dap_chain_net dap_chain_mempool magic)
endif()

# Chain net services
if (CELLFRAME_MODULES MATCHES "srv-" )
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv dap_stream_ch_chain_net_srv)
endif()

# DAG based consensus(es)
if (CELLFRAME_MODULES MATCHES "cs-dag-" )
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_cs_dag)
endif()

# PoA consensus for DAG
if (CELLFRAME_MODULES MATCHES "cs-dag-poa")
    message("[+] Module 'cs-dag-poa'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_cs_dag_poa)
endif()

# PoS consensus for DAG
if (CELLFRAME_MODULES MATCHES "cs-dag-pos")
    message("[+] Module 'cs-dag-pos'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_cs_dag_pos)
endif()

# No-consensus
if (CELLFRAME_MODULES MATCHES "cs-none")
    message("[+] Module 'cs-none'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_cs_none)
endif()

# Enable service Application
if (CELLFRAME_MODULES MATCHES "srv-app")
    message("[+] Module 'srv-app'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_app )
endif()

# Enable service Application DB
if (CELLFRAME_MODULES MATCHES "srv-app-db")
    message("[+] Module 'srv-app-db'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_app_db )
endif()

# Enable service datum process
if (CELLFRAME_MODULES MATCHES "srv-datum")
    message("[+] Module 'srv-datum'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_datum )
endif()

# Enable service VPN
if (CELLFRAME_MODULES MATCHES "srv-vpn")
    message("[+] Module 'srv-vpn'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_vpn )
endif()

# Enable service eXchange
if (CELLFRAME_MODULES MATCHES "srv-xchange")
    message("[+] Module 'srv-xchange'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_xchange )
endif()

# Enable service of delegated stake
if (CELLFRAME_MODULES MATCHES "srv-stake")
    message("[+] Module 'srv-stake'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_stake )
endif()

# Enable bridge with BTC-like networks
if (CELLFRAME_MODULES MATCHES "bridge-btc")
    message("[+] Module 'bridge-btc'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_bridge_btc )
endif()

# Enable service for dynamic modules
if (CELLFRAME_MODULES MATCHES "modules-dynamic")
    message("[+] Module 'dap_modules_dynamic_cdb'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_modules_dynamic_cdb )
endif()

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
