project(cellframe-sdk C)
cmake_minimum_required(VERSION 3.10)

include (cmake/OS_Detection.cmake)
set(CMAKE_C_STANDARD 11)
set(CELLFRAME_SDK_NATIVE_VERSION "3.0-18")
add_definitions ("-DCELLFRAME_SDK_VERSION=\"${CELLFRAME_SDK_NATIVE_VERSION}\"")
set(DAPSDK_MODULES "")

if(NOT DEFINED CELLFRAME_MODULES)
    set(BUILD_CRYPTO_TESTS ON)
    include (cmake/OS_Detection.cmake)
    if (WIN32)
        set(CELLFRAME_MODULES "core chains mining network srv cs-dag-poa cs-block-poa cs-dag-pos cs-block-pos cs-none srv-app srv-app-db srv-datum srv-stake srv-xchange")
    elseif(BSD)
        set(CELLFRAME_MODULES "core chains mining network srv cs-dag-poa cs-block-poa cs-dag-pos cs-block-pos cs-none srv-app srv-app-db srv-datum srv-stake srv-xchange")
    elseif(DARWIN)
        set(CELLFRAME_MODULES "core chains mining network srv cs-dag-poa cs-block-poa cs-dag-pos cs-block-pos cs-none srv-app srv-app-db srv-datum srv-stake srv-xchange")
    elseif(ANDROID)
        set(CELLFRAME_MODULES "core chains mining network srv cs-dag-poa cs-block-poa cs-dag-pos cs-block-pos cs-none srv-app srv-app-db srv-datum srv-stake srv-xchange")
    elseif(LINUX)
        set(CELLFRAME_MODULES "core chains mining network srv cs-dag-poa cs-block-poa cs-dag-pos cs-block-pos cs-none srv-app srv-app-db srv-datum srv-stake srv-xchange modules-dynamic srv-vpn")
    endif()
endif()

message("Cellframe modules: ${CELLFRAME_MODULES}")

if (CELLFRAME_MODULES MATCHES "modules-dynamic")
    add_definitions("-DDAP_MODULES_DYNAMIC")
endif()

if (CELLFRAME_MODULES MATCHES "srv-stake")
     add_definitions("-DDAP_SRV_STAKE_USED")
endif()

if (CELLFRAME_MODULES MATCHES "core")
    SET(DAPSDK_MODULES "${DAPSDK_MODULES} core crypto")
endif()


if (CELLFRAME_MODULES MATCHES "network")
    set(DAPSDK_MODULES "${DAPSDK_MODULES} network-core network-client network-server")
endif()

if (CELLFRAME_MODULES MATCHES "dap-sdk-net-client")
    set(DAPSDK_MODULES "core crypto network-core network-client network-server")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_core dap_crypto dap_server_core dap_server dap_client m pthread)
    if (SUPPORT_PYTHON_PLUGINS)
        set(CELLFRAME_MODULES "${CELLFRAME_MODULES} core chains network cs-none srv-")
    endif()
endif()

if (BUILD_CRYPTO_TESTS)
    if ( NOT(DAPSDK_MODULES MATCHES "core"))
	SET(DAPSDK_MODULES "${DAPSDK_MODULES} core")
    endif()
    if ( NOT(DAPSDK_MODULES MATCHES "crypto"))
	SET(DAPSDK_MODULES "${DAPSDK_MODULES} crypto")
    endif()
    set(BUILD_TESTS ON)
endif()

if( DARWIN)
    add_subdirectory(3rdparty/json-c-darwin)
    add_subdirectory(3rdparty/libmagic-darwin)
    include_directories(3rdparty/json-c-darwin)
endif()
if (ANDROID)
    add_subdirectory(3rdparty/libmagic)
    add_subdirectory(3rdparty/json-c)
    include_directories(cellframe-sdk/3rdparty/)
endif()


add_subdirectory(dap-sdk)
add_subdirectory(3rdparty/monero_crypto)
add_subdirectory(3rdparty/cuttdb)
if(DAPSDK_MODULES MATCHES "ssl-support")
    add_subdirectory(3rdparty/wolfssl)
endif()

add_subdirectory(modules/)

add_library(${PROJECT_NAME} STATIC cellframe-sdk.c)

# init libs
set(CELLFRAME_LIBS "")

# Core libs from dap-sdk
if (CELLFRAME_MODULES MATCHES "core")
    message("[+] Module 'core'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_core dap_app_cli dap_crypto m pthread)
endif()

# General chain libs
if (CELLFRAME_MODULES MATCHES "chains")
    message("[+] Module 'chains'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_common dap_chain dap_chain_global_db dap_chain_wallet)
endif()

# Networking
if (CELLFRAME_MODULES MATCHES "network")
    message("[+] Module 'network'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_server_core dap_json_rpc dap_enc_server dap_notify_srv dap_http_server dap_session
        dap_stream dap_stream_ch dap_client dap_stream_ch_chain dap_stream_ch_chain_net dap_chain_net dap_chain_net_srv dap_chain_mempool magic)
endif()

# Chain net services
if (CELLFRAME_MODULES MATCHES "srv-" )
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_stream_ch_chain_net_srv)
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

# Blocks based consensus(es)
if (CELLFRAME_MODULES MATCHES "cs-block-" )
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_cs_dag)
endif()

# PoA consensus for blocks
if (CELLFRAME_MODULES MATCHES "cs-block-poa")
    message("[+] Module 'cs-block-poa'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_cs_block_poa)
endif()

# PoS consensus for blocks
if (CELLFRAME_MODULES MATCHES "cs-block-pos")
    message("[+] Module 'cs-block-pos'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_cs_block_pos)
endif()

# PoW consensus for blocks
if (CELLFRAME_MODULES MATCHES "cs-block-pow")
    message("[+] Module 'cs-block-pow'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_cs_block_pos)
endif()


# No-consensus
if (CELLFRAME_MODULES MATCHES "cs-none")
    message("[+] Module 'cs-none'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_cs_none)
endif()

# Enable service Application
if (CELLFRAME_MODULES MATCHES "srv-app")
    message("[+] Module 'srv-app'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_app)
endif()

# Enable service Application DB
if (CELLFRAME_MODULES MATCHES "srv-app-db")
    message("[+] Module 'srv-app-db'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_app_db)
endif()

# Enable service datum process
if (CELLFRAME_MODULES MATCHES "srv-datum")
    message("[+] Module 'srv-datum'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_datum)
endif()

# Enable service VPN
if (CELLFRAME_MODULES MATCHES "srv-vpn")
    message("[+] Module 'srv-vpn'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_vpn)
endif()

# Enable service eXchange
if (CELLFRAME_MODULES MATCHES "srv-xchange")
    message("[+] Module 'srv-xchange'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_xchange)
endif()

# Enable service of delegated stake
if (CELLFRAME_MODULES MATCHES "srv-stake")
    message("[+] Module 'srv-stake'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_stake)
endif()

# Enable service for dynamic modules
if (CELLFRAME_MODULES MATCHES "modules-dynamic")
    message("[+] Module 'dap_modules_dynamic_cdb'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_modules_dynamic_cdb)
endif()

if (WIN32)
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} KERNEL32 USER32 SHELL32 WINMM GDI32 ADVAPI32
					 Ole32 Version Imm32 OleAut32 ws2_32 ntdll psapi 
                                         Shlwapi Bcrypt Crypt32 Secur32 userenv mqrt)
endif()

if (DARWIN)
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} bz2)
endif()

target_link_libraries(${PROJECT_NAME} ${CELLFRAME_LIBS})
#if(BUILD_DAP_TESTS)
#    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/test/main_test.py
#            DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)
#    enable_testing()
    #add_subdirectory(test)
#endif()
