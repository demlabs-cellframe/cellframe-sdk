cmake_minimum_required(VERSION 3.12)
project(cellframe-sdk C)

set(CMAKE_C_STANDARD 11)
set(CELLFRAME_SDK_NATIVE_VERSION "4.0.0")


# =========================================
# INCLUDE CELLFRAME LIBRARY HELPERS (use DAP SDK system)
# =========================================
# Universal library creation helpers (shared with DAP SDK)
include(dap-sdk/cmake/LibraryHelpers.cmake)

# CMake 3.12+ supports OBJECT libraries natively - no need for ObjectLibraryHelpers override

# =========================================
# BUILD OPTIONS
# =========================================
option(BUILD_SHARED "Build final Cellframe SDK library as shared (default)" ON)
option(INSTALL_CELLFRAME_SDK "Install Cellframe SDK library and headers (disable when used as subproject)" ON)

if(BUILD_SHARED)
    message("[+] Cellframe SDK: Building final library as SHARED (modules: OBJECT internally)")
    set(CELLFRAME_BUILD_MODE "shared")
else()
    message("[+] Cellframe SDK: Building final library as STATIC (modules: OBJECT internally)")
    set(CELLFRAME_BUILD_MODE "static")
endif()

# Set module type for all Cellframe modules (OBJECT for proper symbol export)
set(CELLFRAME_MODULE_TYPE "OBJECT" CACHE STRING "Type for Cellframe internal modules (OBJECT)")
message(STATUS "[Cellframe] Module type: ${CELLFRAME_MODULE_TYPE}")

add_definitions ("-DCELLFRAME_SDK_VERSION=\"${CELLFRAME_SDK_NATIVE_VERSION}\"")

# Option to build Cellframe SDK tests (can be overridden from command line)
option(BUILD_CELLFRAME_SDK_TESTS "Build Cellframe SDK tests" OFF)
option(BUILD_PERFORMANCE_TESTS "Build performance tests (TPS, load testing)" OFF)





# Configure DAP SDK modules
# Default modules are set in dap-sdk/CMakeLists.txt: crypto plugin io network-* global-db
if(BUILD_CELLFRAME_SDK_TESTS)
    # Add test-framework to default modules, don't replace them
    if(NOT DEFINED DAPSDK_MODULES OR DAPSDK_MODULES STREQUAL "")
        set(DAPSDK_MODULES "crypto plugin io network-core network-server network-client network-link_manager global-db test-framework")
    else()
        set(DAPSDK_MODULES "${DAPSDK_MODULES} test-framework")
    endif()
endif()

# =========================================
# UNIVERSAL LIBRARY HELPERS
# =========================================
# Include universal library helpers (shared with DAP SDK)
# Note: ObjectLibraryHelpers.cmake is already included by DAP SDK
# and will automatically propagate INTERFACE_INCLUDE_DIRECTORIES for OBJECT libraries
include(${CMAKE_CURRENT_SOURCE_DIR}/dap-sdk/cmake/LibraryHelpers.cmake)

# =========================================
# INTERNAL MODULE CREATION MACRO
# =========================================
# ⚠️ TEMPORARY FIX (Phase 5.2): Creates STATIC libraries instead of OBJECT
# This is a TEMPORARY solution to bypass CMake OBJECT_LIBRARY cycle restrictions.
# MANDATORY: Phase 5.3 architectural refactoring REQUIRED after this.
# See: MANDATORY_NEXT_STEP.md for details.
#
# Creates internal static modules (temporary workaround for circular dependencies)
# Usage: cellframe_add_library(target_name sources... HEADERS headers...)
macro(cellframe_add_library TARGET_NAME)
    cmake_parse_arguments(CF_MOD "" "" "HEADERS" ${ARGN})
    
    # Create OBJECT library using universal helper (same as DAP SDK)
    create_object_library(${TARGET_NAME} CELLFRAME_INTERNAL_MODULES ${CF_MOD_UNPARSED_ARGUMENTS} HEADERS ${CF_MOD_HEADERS})
    
    # Enable position independent code for potential shared library
    set_property(TARGET ${TARGET_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)
    
    # Track module in the internal modules list
    if(NOT DEFINED CELLFRAME_INTERNAL_MODULES)
        set(CELLFRAME_INTERNAL_MODULES "" CACHE INTERNAL "List of internal modules")
    endif()
    list(APPEND CELLFRAME_INTERNAL_MODULES ${TARGET_NAME})
    set(CELLFRAME_INTERNAL_MODULES ${CELLFRAME_INTERNAL_MODULES} CACHE INTERNAL "List of internal modules")
    
    message("[+] Cellframe Internal Module: ${TARGET_NAME} (OBJECT)")
endmacro()

# =========================================
# FINAL LIBRARY CREATION (will be called at the end)
# =========================================
# ⚠️ TEMPORARY FIX (Phase 5.2): Modified to work with STATIC internal modules
# Previously collected OBJECT files, now links STATIC libraries
# See: MANDATORY_NEXT_STEP.md for architectural refactoring requirements
#
# Creates final combined Cellframe SDK library 
macro(cellframe_create_final_library)
    if(DEFINED CELLFRAME_INTERNAL_MODULES)
        message("[+] Creating final Cellframe SDK library: cellframe_sdk (${CELLFRAME_BUILD_MODE})")
    
    # Collect all external STATIC libraries and DAP SDK
    set(CELLFRAME_LINK_LIBS "")
    
    # Add external Cellframe STATIC libraries (consensus types, services, etc)
    if(DEFINED CELLFRAME_LIBS)
        list(APPEND CELLFRAME_LINK_LIBS ${CELLFRAME_LIBS})
    endif()
    
    # Add DAP SDK (built-in by default)
    if(CELLFRAME_USING_EXTERNAL_DAP_SDK)
        list(APPEND CELLFRAME_LINK_LIBS dap_sdk)
        message(STATUS "[Cellframe] Using external DAP SDK")
    else()
        list(APPEND CELLFRAME_LINK_LIBS dap_sdk)
        message(STATUS "[Cellframe] Using built-in DAP SDK")
    endif()
    
    # Create final library using universal helper (same as DAP SDK)
    create_final_shared_library(
        LIBRARY_NAME "cellframe_sdk"
        MODULE_LIST_VAR CELLFRAME_INTERNAL_MODULES
        VERSION ${CELLFRAME_SDK_NATIVE_VERSION}
        VERSION_MAJOR 4
        ADDITIONAL_SOURCES cellframe-sdk.c
        LINK_LIBRARIES ${CELLFRAME_LINK_LIBS}
    )
    
    message(STATUS "[Cellframe] Final library cellframe_sdk created successfully")
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



# =========================================
# DAP SDK INTEGRATION - CONDITIONAL
# =========================================
# IMPORTANT: Check if DAP SDK is already configured at parent level
# This MUST be checked REGARDLESS of CELLFRAME_MODULES to avoid symbol duplication
if(NOT TARGET dap_sdk)
    # DAP SDK not found - include our own copy
    message("[+] Cellframe SDK: Using embedded DAP SDK")

    # =========================================
    # DAP_TPL CENTRALIZED PATH
    # =========================================
    # Set centralized dap_tpl location for both Cellframe SDK and DAP SDK
    set(DAP_TPL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tools/dap_tpl" CACHE PATH "Path to dap_tpl templating engine")
    message(STATUS "[Cellframe] Using centralized dap_tpl from: ${DAP_TPL_DIR}")

    # Verify dap_tpl exists
    if(NOT EXISTS "${DAP_TPL_DIR}/dap_tpl.sh")
        message(FATAL_ERROR "dap_tpl.sh not found at ${DAP_TPL_DIR}/dap_tpl.sh. Please ensure tools/dap_tpl is present.")
    endif()


    include (dap-sdk/cmake/OS_Detection.cmake)
    add_subdirectory(dap-sdk)
    set(CELLFRAME_USING_EXTERNAL_DAP_SDK OFF)
else()
    # DAP SDK already available from parent - use it
    message("[+] Cellframe SDK: Using external DAP SDK (target: dap_sdk)")
    message("[+] Cellframe SDK: No DAP SDK duplication - using shared instance")
    # Set the flag to indicate we're using external DAP SDK
    set(CELLFRAME_USING_EXTERNAL_DAP_SDK ON)
endif()

if(NOT DEFINED CELLFRAME_MODULES)
    set(CELLFRAME_MODULES "core chains ledger node network cs-dag-poa cs-esbocs cs-none srv-stake srv-voting srv-bridge srv-xchange srv-stake-ext compose")

    # VPN module moved to separate plugin repository
    # if(LINUX OR DARWIN)
    #     set(CELLFRAME_MODULES "${CELLFRAME_MODULES} srv-vpn")
    # endif()

    set(CELLFRAME_SDK_STANDALONE_BUILD ON)
endif()

message("Cellframe modules: ${CELLFRAME_MODULES}")

# srv-stake enabled
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

# monero_crypto removed - not needed

add_subdirectory(modules/)


# NOTE: Final library will be created by cellframe_create_final_library() macro
# add_library(${PROJECT_NAME} STATIC cellframe-sdk.c)

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
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_datum dap_chain_tx_compose dap_chain_ledger dap_chain dap_global_db dap_chain_wallet)
    # dap_chain_tx_compose - TX Compose Plugin API from modules/datum/tx
endif()

if (CELLFRAME_MODULES MATCHES "ledger")
    message("[+] Module 'ledger'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_ledger)
endif()

# Networking
if (CELLFRAME_MODULES MATCHES "network")
    message("[+] Module 'network'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_io dap_json_rpc dap_enc_server dap_notify_srv dap_http_server dap_session
        dap_stream dap_stream_ch dap_client dap_cli_server dap_chain_net dap_chain_net_decree dap_chain_net_srv dap_chain_mempool)
        # REMOVED: dap_chain_node_cli_cmd - module was refactored and split
        # dap_chain_net_decree - network decree handlers
endif()

# Compose
if (CELLFRAME_MODULES MATCHES "compose")
    message("[+] Module 'compose'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_json_rpc dap_enc_server dap_notify_srv dap_http_server dap_session
        # REMOVED: dap_compose - module was replaced with dap_chain_tx_compose
        dap_stream dap_stream_ch dap_client dap_cli_server dap_chain_net dap_chain_net_srv dap_chain_mempool)
endif()

# Chain net services
if (CELLFRAME_MODULES MATCHES "srv-" )
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv)
endif()

# DAG based consensus(es)
if (CELLFRAME_MODULES MATCHES "cs-dag-" )
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_type_dag)
endif()

# PoA consensus for DAG
if (CELLFRAME_MODULES MATCHES "cs-dag-poa")
    message("[+] Module 'cs-dag-poa'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_type_dag_poa)
endif()

# PoS consensus for DAG
if (CELLFRAME_MODULES MATCHES "cs-dag-pos")
    message("[+] Module 'cs-dag-pos'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_type_dag_pos)
endif()

# Block-based consensus(es) - ALWAYS include blocks (used by mempool, tests, etc)
message("[+] Module 'dap_chain_type_blocks'")
set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_type_blocks)

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
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_type_none)
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

# VPN module moved to separate plugin repository
# if (CELLFRAME_MODULES MATCHES "srv-vpn")
#     message("[+] Module 'srv-vpn'")
#     set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_vpn)
# endif()

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

# Enable service stake-ext
if (CELLFRAME_MODULES MATCHES "srv-stake-ext")
    message("[+] Module 'srv-stake-ext'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_stake_ext)
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

# NOTE: Linking is now handled in cellframe_create_final_library() macro
# target_link_libraries(${PROJECT_NAME} ${CELLFRAME_LIBS})

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

# =========================================
# INSTALL TARGETS
# =========================================
# Only install when INSTALL_CELLFRAME_SDK is enabled
# Can be disabled by parent project (e.g., cellframe-node) by setting INSTALL_CELLFRAME_SDK to OFF
if(INSTALL_CELLFRAME_SDK)
    message(STATUS "[Cellframe-SDK] Installation enabled")
    
    # Install library
    install(TARGETS cellframe_sdk
            LIBRARY DESTINATION lib
            ARCHIVE DESTINATION lib)

    # Install headers
    install(DIRECTORY modules/
            DESTINATION include/cellframe-sdk
            FILES_MATCHING PATTERN "*.h")

    # Install DAP SDK headers (only if using embedded DAP SDK)
    if(NOT CELLFRAME_USING_EXTERNAL_DAP_SDK)
        install(DIRECTORY dap-sdk/module/core/include/
                DESTINATION include/dap-sdk/core
                FILES_MATCHING PATTERN "*.h")

        install(DIRECTORY dap-sdk/module/crypto/include/
                DESTINATION include/dap-sdk/crypto
                FILES_MATCHING PATTERN "*.h")
    endif()
else()
    message(STATUS "[Cellframe-SDK] Installation disabled (build-time dependency only)")
endif()

# =========================================
# TESTS
# =========================================
if(BUILD_CELLFRAME_SDK_TESTS OR BUILD_DAP_SDK_TESTS)
    message(STATUS "=== Enabling Cellframe SDK Tests ===")
    add_subdirectory(tests)
endif()

# Performance tests (optional, not run by default)
if(BUILD_PERFORMANCE_TESTS)
    add_subdirectory(tests/performance)
endif()
