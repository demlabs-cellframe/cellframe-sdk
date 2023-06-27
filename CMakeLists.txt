project(cellframe-sdk C)
include(ExternalProject)
cmake_minimum_required(VERSION 3.10)

set(CMAKE_C_STANDARD 11)
set(CELLFRAME_SDK_NATIVE_VERSION "3.1-223")

add_definitions ("-DCELLFRAME_SDK_VERSION=\"${CELLFRAME_SDK_NATIVE_VERSION}\"")

set(BUILD_CRYPTO_TESTS ON)

set(DAPSDK_MODULES "")

if(NOT DEFINED CELLFRAME_MODULES)
    include (cmake/OS_Detection.cmake)
    set(CELLFRAME_MODULES "core chains mining network srv cs-dag-poa cs-block-poa cs-dag-pos cs-block-pos cs-block-ton cs-none srv-app srv-app-db srv-datum srv-stake-pos-delegate srv-stake-lock srv-xchange")

    if(LINUX)
        set(CELLFRAME_MODULES "${CELLFRAME_MODULES} modules-dynamic srv-vpn")
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
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_core dap_crypto dap_server_core dap_server dap_client m)
    if(NOT ANDROID)
        set(CELLFRAME_LIBS ${CELLFRAME_LIBS} pthread)
    endif()
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

if(BUILD_TESTS)
    include(cmake/OS_Detection.cmake)
endif()

    add_subdirectory(3rdparty/crc32c_adler)		# https://github.com/fonic/crc32c_adler


if(DARWIN)
    add_subdirectory(3rdparty/libmagic-darwin)
elseif(ANDROID)
    include_directories(cellframe-sdk/3rdparty/)
endif()

if (BUILD_WITH_ZIP)
    add_subdirectory(3rdparty/libzip)
    include_directories(3rdparty/libzip/lib)
endif()

add_subdirectory(dap-sdk)
add_subdirectory(3rdparty/monero_crypto)
add_subdirectory(3rdparty/json-c EXCLUDE_FROM_ALL)

set(JSON-C-CONFIG_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/json-c/
    -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_CURRENT_BINARY_DIR}/deps/
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME})

##TODO: customize for universal platforms
if(ANDROID AND "${CMAKE_HOST_SYSTEM}" MATCHES ".*Windows.*")
    set(JSON-C-CONFIG_COMMAND ${CMAKE_COMMAND} ${JSON-C-CONFIG_COMMAND}
        -DANDROID_NATIVE_API_LEVEL=29
        -DANDROID_ABI=arm64-v8a
        -DANDROID_PLATFORM=${ANDROID_PLATFORM}
        -DCMAKE_TOOLCHAIN_FILE=D:/android-sdk/ndk/21.4.7075529/build/cmake/android.toolchain.cmake
        -DCMAKE_MAKE_PROGRAM=D:/android-sdk/cmake/3.22.1/bin/ninja.exe
        -G=Ninja)
elseif(ANDROID)
    set(JSON-C-CONFIG_COMMAND ${CMAKE_COMMAND} -E env PATH=$ENV{PATH}
        ${CMAKE_COMMAND} ${JSON-C-CONFIG_COMMAND}
        -DANDROID_NATIVE_API_LEVEL=${ANDROID_NATIVE_API_LEVEL}
        -DANDROID_ABI=${ANDROID_ABI}
        -DANDROID_PLATFORM=${ANDROID_PLATFORM}
        -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE})
else()
    set(JSON-C-CONFIG_COMMAND ${CMAKE_COMMAND} -E env PATH=$ENV{PATH} ${CMAKE_COMMAND} ${JSON-C-CONFIG_COMMAND})
endif()

message("json-c build cmd ${JSON-C-CONFIG_COMMAND}")

ExternalProject_Add(dap_json-c_dep
                    SOURCE_DIR ${PROJECT_SOURCE_DIR}/3rdparty/json-c/
                    CONFIGURE_COMMAND ${JSON-C-CONFIG_COMMAND})

if (BUILD_WITH_GDB_DRIVER_CUTTDB)
    add_subdirectory(3rdparty/cuttdb)
endif()

if (BUILD_WITH_GDB_DRIVER_MDBX)
    set(SAVED_CMAKE_MESSAGE_LOG_LEVEL ${CMAKE_MESSAGE_LOG_LEVEL})
    set(CMAKE_MESSAGE_LOG_LEVEL WARNING)
    add_subdirectory(3rdparty/libmdbx EXCLUDE_FROM_ALL)
    set(CMAKE_MESSAGE_LOG_LEVEL ${SAVED_CMAKE_MESSAGE_LOG_LEVEL})
endif()

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
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_core dap_app_cli dap_crypto m)
    if(NOT ANDROID)
        set(CELLFRAME_LIBS ${CELLFRAME_LIBS} pthread)
    endif()

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
        dap_stream dap_stream_ch dap_client dap_stream_ch_chain dap_stream_ch_chain_net dap_chain_net dap_chain_net_srv dap_stream_ch_chain_voting dap_chain_mempool)
    if(NOT ANDROID)
        set(CELLFRAME_LIBS ${CELLFRAME_LIBS} magic)
    endif()
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

# TON consensus for blocks
if (CELLFRAME_MODULES MATCHES "cs-block-ton")
    message("[+] Module 'cs-block-ton'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_cs_block_ton)
endif()

# PoW consensus for blocks
if (CELLFRAME_MODULES MATCHES "cs-block-pow")
    message("[+] Module 'cs-block-pow'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_cs_block_pow)
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



# Enable service of stake token
if (CELLFRAME_MODULES MATCHES "srv-stake-lock")
    message("[+] Module 'srv-stake-lock'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_stake_lock)
endif()

# Enable service for dynamic modules
if (CELLFRAME_MODULES MATCHES "modules-dynamic")
    message("[+] Module 'dap_modules_dynamic_cdb'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_modules_dynamic_cdb)
endif()

# Enable service of delegated stake
if (CELLFRAME_MODULES MATCHES "srv-stake-pos-delegate")
    message("[+] Module 'srv-stake-pos-delegate'")
    #add TARGET_FILE for proper symbols resolving
    #pos_delegate depends on symbols from this libs
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_stake_pos_delegate $<TARGET_FILE:dap_chain_cs_dag_poa> $<TARGET_FILE:dap_chain_cs_block_poa> $<TARGET_FILE:dap_chain_cs_dag> $<TARGET_FILE:dap_chain_cs_blocks>)
endif()

if (WIN32)
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} kernel32 user32 shell32 winmm gdi32 advapi32
                                         ole32 version imm32 oleaut32 ws2_32 ntdll psapi
                                         shlwapi bcrypt crypt32 secur32 userenv #mqrt
                                         )
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
