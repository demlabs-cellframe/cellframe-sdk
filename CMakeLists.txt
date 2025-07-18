cmake_minimum_required(VERSION 3.10)
project(cellframe-sdk C)

set(CMAKE_C_STANDARD 11)
set(CELLFRAME_SDK_NATIVE_VERSION "4.0.0")

# =========================================
# UNIVERSAL BUILD SYSTEM - CELLFRAME SDK
# =========================================
# Cellframe SDK always builds its modules as STATIC internally,
# then combines them into one big STATIC or SHARED library

# Default: BUILD_SHARED=ON (final library is shared)
# Override: BUILD_SHARED=OFF (final library is static)
option(BUILD_SHARED "Build final Cellframe SDK library as shared (default)" ON)

# Internal modules are ALWAYS static
set(CELLFRAME_INTERNAL_LIB_TYPE STATIC)

if(BUILD_SHARED)
    message("[+] Cellframe SDK: Building final library as SHARED (modules: static internally)")
    set(CELLFRAME_FINAL_LIB_TYPE SHARED)
    set(CELLFRAME_BUILD_MODE "shared")
else()
    message("[+] Cellframe SDK: Building final library as STATIC (modules: static internally)")
    set(CELLFRAME_FINAL_LIB_TYPE STATIC)
    set(CELLFRAME_BUILD_MODE "static")
endif()

# Export build mode for consumers
set(CELLFRAME_SDK_BUILD_MODE ${CELLFRAME_BUILD_MODE} CACHE STRING "Cellframe SDK final library mode (shared/static)")
set(CELLFRAME_SDK_INTERNAL_MODE "static" CACHE STRING "Cellframe SDK internal modules mode (always static)")

add_definitions ("-DCELLFRAME_SDK_VERSION=\"${CELLFRAME_SDK_NATIVE_VERSION}\"")

# =========================================
# INTERNAL MODULE CREATION MACRO
# =========================================
# Creates internal static modules (always static)
# Usage: cellframe_add_library(target_name sources... HEADERS headers...)
macro(cellframe_add_library TARGET_NAME)
    cmake_parse_arguments(CELLFRAME_LIB "" "" "HEADERS" ${ARGN})
    
    # Always create modules as STATIC with original name
    add_library(${TARGET_NAME} STATIC ${CELLFRAME_LIB_UNPARSED_ARGUMENTS} ${CELLFRAME_LIB_HEADERS})
    
    # Track modules for final library creation
    if(NOT DEFINED CELLFRAME_INTERNAL_MODULES)
        set(CELLFRAME_INTERNAL_MODULES "")
    endif()
    list(APPEND CELLFRAME_INTERNAL_MODULES ${TARGET_NAME})
    set(CELLFRAME_INTERNAL_MODULES ${CELLFRAME_INTERNAL_MODULES} CACHE INTERNAL "List of Cellframe internal modules")
    
    message("[+] Cellframe Internal Module: ${TARGET_NAME} (static)")
endmacro()

# =========================================
# FINAL LIBRARY CREATION (will be called at the end)
# =========================================
# Creates final combined Cellframe SDK library 
macro(cellframe_create_final_library)
    if(DEFINED CELLFRAME_INTERNAL_MODULES)
        message("[+] Creating final Cellframe SDK library: cellframe_sdk (${CELLFRAME_BUILD_MODE})")
        message("[+] Internal modules to combine: ${CELLFRAME_INTERNAL_MODULES}")
        
        # Create final library that combines all internal modules
        add_library(cellframe_sdk ${CELLFRAME_FINAL_LIB_TYPE})
        
        # Set properties for final library
        if(BUILD_SHARED)
            set_target_properties(cellframe_sdk PROPERTIES
                POSITION_INDEPENDENT_CODE ON
                VERSION ${CELLFRAME_SDK_NATIVE_VERSION}
                SOVERSION 4
            )
            target_compile_definitions(cellframe_sdk PRIVATE CELLFRAME_BUILDING_LIB)
            target_compile_definitions(cellframe_sdk INTERFACE CELLFRAME_USING_SHARED)
        else()
            target_compile_definitions(cellframe_sdk INTERFACE CELLFRAME_USING_STATIC)
        endif()
        
        # Link all internal static modules into final library
        target_link_libraries(cellframe_sdk PUBLIC ${CELLFRAME_INTERNAL_MODULES})
        
        # Also inherit include directories from internal modules
        foreach(module ${CELLFRAME_INTERNAL_MODULES})
            get_target_property(module_includes ${module} INTERFACE_INCLUDE_DIRECTORIES)
            if(module_includes)
                target_include_directories(cellframe_sdk PUBLIC ${module_includes})
            endif()
        endforeach()
        
        message("[+] Final Cellframe SDK Library: cellframe_sdk created successfully")
    endif()
endmacro()

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
    include (dap-sdk/cmake/OS_Detection.cmake)

    set(CELLFRAME_MODULES "core chains ledger node network cs-dag-poa cs-esbocs cs-none srv-stake srv-voting srv-bridge srv-xchange compose")

    if(LINUX OR DARWIN)
        set(CELLFRAME_MODULES "${CELLFRAME_MODULES} srv-vpn")
    endif()

    if(BUILD_CELLFRAME_SDK_TESTS)
        set(DAPSDK_MODULES "test-framework")
    endif()

    add_subdirectory(dap-sdk)

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
    add_definitions("-DDAP_CHAIN_TX_COMPOSE_TEST")
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
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_core dap_app_cli dap_plugin dap_crypto m)
endif()

# General chain libs
if (CELLFRAME_MODULES MATCHES "chains")
    message("[+] Module 'chains'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_datum dap_chain_ledger dap_chain dap_global_db dap_chain_wallet)
endif()

if (CELLFRAME_MODULES MATCHES "ledger")
    message("[+] Module 'ledger'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_ledger)
endif()

# Networking
if (CELLFRAME_MODULES MATCHES "network")
    message("[+] Module 'network'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_io dap_json_rpc dap_enc_server dap_notify_srv dap_http_server dap_session
        dap_stream dap_stream_ch dap_client dap_cli_server dap_chain_net dap_chain_net_srv dap_chain_mempool)
endif()

# Chain net services
if (CELLFRAME_MODULES MATCHES "srv-" )
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv)
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
# CREATE FINAL CELLFRAME SDK LIBRARY
# =========================================
# Combine all internal static modules into one final library
cellframe_create_final_library()
