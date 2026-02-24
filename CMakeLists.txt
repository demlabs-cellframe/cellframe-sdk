cmake_minimum_required(VERSION 3.10)
project(cellframe-sdk C)

set(CMAKE_C_STANDARD 11)
set(CELLFRAME_SDK_NATIVE_VERSION "3.5-0")

add_definitions ("-DCELLFRAME_SDK_VERSION=\"${CELLFRAME_SDK_NATIVE_VERSION}\"")

# dap_tpl for mock framework: use dap-sdk's full version (has build_engine.sh + mocking support)
if(NOT DEFINED DAP_TPL_DIR AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/dap_tpl/dap_tpl.sh")
    set(DAP_TPL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tools/dap_tpl" CACHE PATH "Path to dap_tpl template engine")
    message(STATUS "[+] dap_tpl: ${DAP_TPL_DIR}")
endif()

if (INSTALL_SDK)
    set(INSTALL_DAP_SDK ON)
else()
    install(CODE "MESSAGE(\"No installation targets defined, using dummy install\")")
endif()

# Include LibraryHelpers for object library creation
# This must be included early to override target_link_libraries
include(cmake/LibraryHelpers.cmake)

# problem in /usr/include/linux/netlink.h:99:24: note: expanded from macro 'NLMSG_OK' (nlh)->nlmsg_len <= (len)
if(CMAKE_C_COMPILER MATCHES "clang")
    add_compile_options(-Wno-sign-compare)
endif()

if(NOT DEFINED CELLFRAME_MODULES)
    include (dap-sdk/cmake/OS_Detection.cmake)

    set(CELLFRAME_MODULES "core chains mining network cs-dag-poa cs-esbocs cs-none srv-stake srv-voting srv-bridge srv-xchange srv-dex compose")

    if(LINUX OR DARWIN)
        set(CELLFRAME_MODULES "${CELLFRAME_MODULES} srv-vpn")
    endif()

    if(BUILD_CELLFRAME_SDK_TESTS)
        set(DAPSDK_MODULES "test-framework")
        set(BUILD_DAP_SDK_TESTS ON)
    endif()

    add_subdirectory(dap-sdk)

    set(CELLFRAME_SDK_STANDALONE_BUILD ON)
endif()

message("Cellframe modules: ${CELLFRAME_MODULES}")

# Module-specific definitions
# These definitions are set globally but could be moved to specific modules if needed
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
    add_subdirectory(tests)
endif()

if (BUILD_WITH_ZIP)
    add_subdirectory(3rdparty/libzip)
    include_directories(3rdparty/libzip/lib)
endif()

add_subdirectory(3rdparty/monero_crypto)

add_subdirectory(modules/)

# Post-process all OBJECT libraries to propagate include directories
# This must be done AFTER all modules are created and configured
# This ensures transitive dependencies are propagated
post_process_object_libraries()

# Create final library from OBJECT modules
# Check if we have any OBJECT modules registered
if(DEFINED CELLFRAME_INTERNAL_MODULES AND CELLFRAME_INTERNAL_MODULES)
    # Use OBJECT modules if available
    message(STATUS "[Cellframe SDK] Using OBJECT libraries: ${CELLFRAME_INTERNAL_MODULES}")
    
    # Collect all object files from OBJECT modules
    set(ALL_OBJECTS "")
    foreach(MODULE ${CELLFRAME_INTERNAL_MODULES})
        if(TARGET ${MODULE})
            list(APPEND ALL_OBJECTS $<TARGET_OBJECTS:${MODULE}>)
        endif()
    endforeach()
    
    # Create STATIC library from OBJECT modules + main source file
    add_library(${PROJECT_NAME} STATIC cellframe-sdk.c ${ALL_OBJECTS})
    
    # Propagate include directories from all modules
    foreach(MODULE ${CELLFRAME_INTERNAL_MODULES})
        if(TARGET ${MODULE})
            get_target_property(MODULE_INTERFACE_INCLUDES ${MODULE} INTERFACE_INCLUDE_DIRECTORIES)
            if(MODULE_INTERFACE_INCLUDES)
                target_include_directories(${PROJECT_NAME} PUBLIC ${MODULE_INTERFACE_INCLUDES})
            endif()
            
            get_target_property(MODULE_INCLUDES ${MODULE} INCLUDE_DIRECTORIES)
            if(MODULE_INCLUDES)
                target_include_directories(${PROJECT_NAME} PUBLIC ${MODULE_INCLUDES})
            endif()
        endif()
    endforeach()
    
    # Collect and link external libraries from modules
    collect_external_libraries_from_modules("${CELLFRAME_INTERNAL_MODULES}" ALL_EXTERNAL_LIBS)
    if(ALL_EXTERNAL_LIBS)
        target_link_libraries(${PROJECT_NAME} PRIVATE ${ALL_EXTERNAL_LIBS})
    endif()
else()
    # Fallback to old STATIC library approach for backward compatibility
    message(STATUS "[Cellframe SDK] Using legacy STATIC library approach")
    add_library(${PROJECT_NAME} STATIC cellframe-sdk.c)
endif()

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
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_common dap_chain dap_global_db dap_chain_wallet)
endif()

# Networking
if (CELLFRAME_MODULES MATCHES "network")
    message("[+] Module 'network'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_io dap_json_rpc dap_enc_server dap_notify_srv dap_http_server dap_session
        dap_stream dap_stream_ch dap_client dap_cli_server dap_stream_ch_chain_net dap_chain_net dap_chain_net_srv dap_chain_mempool)
endif()

# Compose
if (CELLFRAME_MODULES MATCHES "compose")
    message("[+] Module 'compose'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_compose dap_json_rpc dap_enc_server dap_notify_srv dap_http_server dap_session
        dap_stream dap_stream_ch dap_client dap_cli_server dap_stream_ch_chain_net dap_chain_net dap_chain_net_srv dap_chain_mempool)
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

# Enable service DEX v2
if (CELLFRAME_MODULES MATCHES "srv-dex")
    message("[+] Module 'srv-dex'")
    set(CELLFRAME_LIBS ${CELLFRAME_LIBS} dap_chain_net_srv_dex)
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

# Link libraries
# For OBJECT modules, external libraries are already linked via collect_external_libraries_from_modules
# For legacy approach, link CELLFRAME_LIBS as before
if(NOT DEFINED CELLFRAME_INTERNAL_MODULES OR NOT CELLFRAME_INTERNAL_MODULES)
    target_link_libraries(${PROJECT_NAME} ${CELLFRAME_LIBS})
else()
    # Still need to link DAP SDK modules and system libraries
    # DAP SDK modules are OBJECT libraries, so we need to link them explicitly
    # System libraries will be linked here
    if(CELLFRAME_LIBS)
        # Filter out OBJECT libraries, keep only external/system libraries
        set(EXTERNAL_LIBS "")
        foreach(LIB ${CELLFRAME_LIBS})
            if(TARGET ${LIB})
                get_target_property(LIB_TYPE ${LIB} TYPE)
                if(NOT LIB_TYPE STREQUAL "OBJECT_LIBRARY")
                    list(APPEND EXTERNAL_LIBS ${LIB})
                endif()
            else()
                # Not a target, assume it's a system library
                list(APPEND EXTERNAL_LIBS ${LIB})
            endif()
        endforeach()
        if(EXTERNAL_LIBS)
            target_link_libraries(${PROJECT_NAME} PUBLIC ${EXTERNAL_LIBS})
        endif()
    endif()
    
    # Link DAP SDK modules if they are OBJECT libraries
    # They should be linked via dap_link_all_sdk_modules
    if(CELLFRAME_MODULES MATCHES "core")
        # Link all DAP SDK modules that are needed
        dap_link_all_sdk_modules(${PROJECT_NAME} DAP_INTERNAL_MODULES)
    endif()
endif()

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
