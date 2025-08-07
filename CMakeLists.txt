cmake_minimum_required(VERSION 3.10)
project(cellframe-sdk C)

set(CMAKE_C_STANDARD 11)
set(CELLFRAME_SDK_NATIVE_VERSION "3.4-0")

add_definitions ("-DCELLFRAME_SDK_VERSION=\"${CELLFRAME_SDK_NATIVE_VERSION}\"")

if (INSTALL_SDK)
    set(INSTALL_DAP_SDK ON)
else()
    install(CODE "MESSAGE(\"No installation targets defined, using dummy install\")")
endif()

# problem in /usr/include/linux/netlink.h:99:24: note: expanded from macro 'NLMSG_OK' (nlh)->nlmsg_len <= (len)
if(CMAKE_C_COMPILER MATCHES "clang")
    add_compile_options(-Wno-sign-compare)
endif()

if(NOT DEFINED CELLFRAME_MODULES)
    # Check for external shared DAP SDK first
    if(DAP_SDK_PATH AND DAP_SDK_TARGET_NAME)
        message("[+] Cellframe SDK: Using shared DAP SDK from ${DAP_SDK_PATH}")
        
        # Include external DAP SDK OS detection
        include(${DAP_SDK_PATH}/cmake/OS_Detection.cmake)
        
        # CRITICAL: Add include directories for external DAP SDK headers
        include_directories(
            ${DAP_SDK_PATH}/core/include
            ${DAP_SDK_PATH}/crypto/include  
            ${DAP_SDK_PATH}/plugin/include
            ${DAP_SDK_PATH}/io/include
            ${DAP_SDK_PATH}/net/server/cli_server/include
            ${DAP_SDK_PATH}/global-db/include
            ${DAP_SDK_PATH}/3rdparty/uthash/src
            ${DAP_SDK_PATH}/3rdparty/json-c
        )
        
        # No need to add dap-sdk subdirectory - using external target ${DAP_SDK_TARGET_NAME}
        set(CELLFRAME_EXTERNAL_DAP_SDK ON)
        message("[+] Cellframe SDK: ✅ Using shared DAP SDK, no duplication")
        message("[+] Cellframe SDK: ✅ Added external DAP SDK include paths")
        
    else()
        message("[+] Cellframe SDK: Using INTERNAL dap-sdk (fallback mode)")
        
        # Legacy mode - use internal dap-sdk
        include (dap-sdk/cmake/OS_Detection.cmake)
        add_subdirectory(dap-sdk)
        set(CELLFRAME_EXTERNAL_DAP_SDK OFF)
        message("[+] Cellframe SDK: ⚠️ Internal DAP SDK mode")
    endif()

    set(CELLFRAME_MODULES "core chains mining network cs-dag-poa cs-esbocs cs-none srv-stake srv-voting srv-bridge srv-xchange")

    if(LINUX OR DARWIN)
        set(CELLFRAME_MODULES "${CELLFRAME_MODULES} srv-vpn")
    endif()

    if(BUILD_CELLFRAME_SDK_TESTS)
        set(DAPSDK_MODULES "test-framework")
    endif()

    set(CELLFRAME_SDK_STANDALONE_BUILD ON)
endif()

message("Cellframe modules: ${CELLFRAME_MODULES}")

if (CELLFRAME_MODULES MATCHES "srv-stake")
     add_definitions("-DDAP_SRV_STAKE_USED")
endif()

option(DAP_INT128_SUPPORT "Use 128-bit varaibles, if supported" ON) # Enabled by default

if(NOT DAP_INT128_SUPPORT)
    message("[!] INT128 DISABLED")
    add_definitions(-DDAP_DISABLE_INT128)
else()
    #    message("[!] INT128 ENABLED")
    #    add_definitions(-DDAP_DISABLE_INT128=FALSE)
endif(NOT DAP_INT128_SUPPORT)

if (BUILD_CELLFRAME_SDK_TESTS)
    enable_testing()
    add_definitions("-DDAP_LEDGER_TEST")
    add_definitions("-DDAP_CHAIN_BLOCKS_TEST")
endif()

if (BUILD_WITH_ZIP)
    add_subdirectory(3rdparty/libzip)
    include_directories(3rdparty/libzip/lib)
endif()

add_subdirectory(3rdparty/monero_crypto)

add_subdirectory(modules/)


add_library(${PROJECT_NAME} STATIC cellframe-sdk.c)

# init libs
set(CELLFRAME_LIBS "")

# Core libs from dap-sdk 
if (CELLFRAME_MODULES MATCHES "core")
    message("[+] Module 'core'")
    
    if(CELLFRAME_EXTERNAL_DAP_SDK AND DAP_SDK_TARGET_NAME)
        # Use external shared DAP SDK target
        set(CELLFRAME_LIBS ${CELLFRAME_LIBS} ${DAP_SDK_TARGET_NAME} m)
        message("[+] Core: Using shared DAP SDK target: ${DAP_SDK_TARGET_NAME}")
    else()
        # Legacy: Use individual DAP SDK libraries
        set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_core dap_app_cli dap_plugin dap_crypto m)
        message("[+] Core: Using individual DAP SDK libraries (legacy mode)")
    endif()
endif()

# General chain libs
if (CELLFRAME_MODULES MATCHES "chains")
    message("[+] Module 'chains'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_common dap_chain dap_global_db dap_chain_wallet)
endif()

# Networking
if (CELLFRAME_MODULES MATCHES "network")
    message("[+] Module 'network'")
    
    if(NOT CELLFRAME_EXTERNAL_DAP_SDK)
        # Legacy: Add individual DAP SDK network libraries
        set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_io dap_json_rpc dap_enc_server dap_notify_srv dap_http_server dap_session
            dap_stream dap_stream_ch dap_client dap_cli_server dap_stream_ch_chain_net dap_chain_net dap_chain_net_srv dap_chain_mempool)
        message("[+] Network: Adding individual DAP SDK network libraries (legacy mode)")
    else()
        # External shared DAP SDK already includes all network libs
        message("[+] Network: All network libraries included in shared DAP SDK")
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
if (CELLFRAME_MODULES MATCHES "cs-block-" OR CELLFRAME_MODULES MATCHES "cs-esbocs")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_cs_blocks)
endif()

# ESBOCS consensus for blocks
if (CELLFRAME_MODULES MATCHES "cs-esbocs")
    message("[+] Module 'cs-esbocs'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_cs_esbocs)
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
if (CELLFRAME_MODULES MATCHES "srv-stake")
    message("[+] Module 'srv-stake'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_stake)
endif()


# Enable service bridge
if (CELLFRAME_MODULES MATCHES "srv-bridge")
    message("[+] Module 'srv-bridge'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_bridge)
endif()

# Enable service voting
if (CELLFRAME_MODULES MATCHES "srv-voting")
    message("[+] Module 'srv-voting'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_voting)
endif()

# Enable service TX multisign with consensus
if (CELLFRAME_MODULES MATCHES "srv-emit-delegate")
    message("[+] Module 'srv-emit-delegate'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_emit_delegate)
endif()

# Enable service for dynamic modules
if (CELLFRAME_MODULES MATCHES "modules-dynamic")
    message("[+] Module 'dap_modules_dynamic_cdb'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_modules_dynamic_cdb)
endif()

if (WIN32)
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} kernel32 user32 shell32 winmm gdi32 advapi32
					 ole32 version imm32 oleaut32 ws2_32 ntdll psapi
                                         shlwapi bcrypt crypt32 secur32 userenv) #mqrt)
endif()

if (DARWIN)
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} bz2)
endif()

target_link_libraries(${PROJECT_NAME} ${CELLFRAME_LIBS})

# For .so
#target_link_libraries(${PROJECT_NAME} -Wl,--whole-archive ${CELLFRAME_LIBS} -Wl,--no-whole-archive)


# Option to enable full cppcheck analysis
option(ENABLE_CPPCHECK_ANALYSIS "Enable full cppcheck static analysis" OFF)

# Cpp check
if(ENABLE_CPPCHECK_ANALYSIS)
    find_program(CPPCHECK cppcheck)
    if(CPPCHECK)
        message(STATUS "Found cppcheck: ${CPPCHECK}")
        add_custom_target(cppcheck_analysis
            COMMAND ${CPPCHECK}
                --std=c11
                --enable=warning,style,performance,portability
                --quiet
                --xml
                ${CMAKE_SOURCE_DIR}/cmake
                ${CMAKE_SOURCE_DIR}/modules
                ${CMAKE_SOURCE_DIR}/os
                ${CMAKE_SOURCE_DIR}/prod_build
                2> ${CMAKE_BINARY_DIR}/cppcheck_report.xml
            COMMAND cppcheck-htmlreport
                --file ${CMAKE_BINARY_DIR}/cppcheck_report.xml
                --report-dir ${CMAKE_BINARY_DIR}/cppcheck_html_report
                --source-dir ${CMAKE_SOURCE_DIR}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            COMMENT "Running full cppcheck static analysis and generating HTML report in ${CMAKE_BINARY_DIR}/cppcheck_html_report"
        )
    else()
        message(WARNING "cppcheck not found, cppcheck_analysis target unavailable")
    endif()
endif()

# =========================================
# INSTALL CONFIGURATION - CELLFRAME SDK
# =========================================
# Install shared library (only for external DAP SDK builds)
if(CELLFRAME_EXTERNAL_DAP_SDK)
    install(TARGETS cellframe-sdk
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        COMPONENT cellframe_sdk_runtime
    )
    
    # Install headers for development
    install(DIRECTORY 
        modules/common/include/
        modules/chain/include/
        modules/net/include/
        modules/wallet/include/
        modules/core/include/
        modules/consensus/
        modules/service/
        modules/type/
        DESTINATION include/cellframe-sdk
        COMPONENT cellframe_sdk_dev
        FILES_MATCHING PATTERN "*.h"
    )
    
    # Install pkg-config file
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cellframe-sdk.pc.in"
        "${CMAKE_CURRENT_BINARY_DIR}/cellframe-sdk.pc"
        @ONLY
    )
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/cellframe-sdk.pc"
        DESTINATION lib/pkgconfig
        COMPONENT cellframe_sdk_dev
    )
    
    # =========================================
    # PACKAGING SUPPORT (CPack) - CELLFRAME SDK
    # =========================================
    # Package configuration
    set(CPACK_PACKAGE_NAME "libcellframe-sdk")
    set(CPACK_PACKAGE_VERSION "1.0.0")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Cellframe SDK - Blockchain Platform SDK")
    set(CPACK_PACKAGE_VENDOR "Demlabs")
    set(CPACK_PACKAGE_CONTACT "support@demlabs.net")
    
    # Multi-component packaging
    set(CPACK_COMPONENTS_ALL cellframe_sdk_runtime cellframe_sdk_dev)
    
    # Component descriptions
    set(CPACK_COMPONENT_CELLFRAME_SDK_RUNTIME_DISPLAY_NAME "Cellframe SDK Runtime Library")
    set(CPACK_COMPONENT_CELLFRAME_SDK_RUNTIME_DESCRIPTION "Shared library for Cellframe SDK")
    set(CPACK_COMPONENT_CELLFRAME_SDK_RUNTIME_REQUIRED ON)
    
    set(CPACK_COMPONENT_CELLFRAME_SDK_DEV_DISPLAY_NAME "Cellframe SDK Development")
    set(CPACK_COMPONENT_CELLFRAME_SDK_DEV_DESCRIPTION "Headers and development files for Cellframe SDK")
    set(CPACK_COMPONENT_CELLFRAME_SDK_DEV_DEPENDS cellframe_sdk_runtime)
    
    # Debian package configuration  
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libdap-sdk (>= 3.0.0)")
    set(CPACK_DEBIAN_PACKAGE_SECTION "libs")
    set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Demlabs <support@demlabs.net>")
    
    # Package generators
    set(CPACK_GENERATOR "DEB;TGZ")
    include(CPack)
    
    message("[+] Cellframe SDK: CPack packaging enabled for shared library")
else()
    message("[+] Cellframe SDK: No packaging for embedded build mode")
endif()
