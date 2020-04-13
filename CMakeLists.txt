project(cellframe-sdk C)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_STANDARD 11)
set(CELLFRAME_SDK_NATIVE_VERSION "1.2-1")
include(cmake/OS_Detection.cmake)
add_definitions ("-DCELLFRAME_SDK_VERSION=\"${CELLFRAME_SDK_NATIVE_VERSION}\"")

if((CMAKE_BUILD_TYPE STREQUAL "Debug") OR (DAP_DEBUG))
    message("Debug build")
    SET(DAP_DEBUG ON)
else()
    message("Release build")
    SET(DAP_RELEASE ON)
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL "8")
  set(DEFAULT_BUILD_64 ON)
else()
  set(DEFAULT_BUILD_64 OFF)
endif()
option(BUILD_64 "Build for 64-bit? 'OFF' builds for 32-bit." ${DEFAULT_BUILD_64})

if(BUILD_64)
  set(ARCH_WIDTH "64")
else()
  set(ARCH_WIDTH "32")
endif()
message(STATUS "Building for a ${ARCH_WIDTH}-bit system")

if(UNIX)
    add_definitions ("-DDAP_OS_LINUX -DDAP_OS_UNIX")
    # add_definitions ("-DDAP_LOG_MT")
    if(DAP_DEBUG)
      set(_CCOPT "-DDAP_DEBUG -Wall -Wno-unused-function -Wno-implicit-fallthrough -Wno-unused-variable -Wno-unused-parameter -Wno-unused-but-set-variable -pg -g3 -ggdb -fno-eliminate-unused-debug-symbols")
      set(_LOPT "-pg")
      SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -pg")
    else()
    set(_CCOPT "-Wno-unused-function -Wno-implicit-fallthrough -Wno-unused-variable -Wno-unused-parameter -Wno-unused-but-set-variable -O3 -fPIC -fno-ident -ffast-math -ftree-vectorize -fno-asynchronous-unwind-tables -ffunction-sections -Wl,--gc-sections -Wl,--strip-all -std=gnu11")
    endif()

    if (ANDROID)
        set(_CCOPT "${_CCOPT} -fforce-enable-int128 -std=gnu11")
        add_definitions ("-DDAP_OS_ANDROID")
    endif()

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_CCOPT}")
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} ${_LOPT}")

    if (ANDROID)
      add_subdirectory(lib/json-c)
      add_subdirectory(lib/sqlite3)
      #add_subdirectory(lib/libev)
      include_directories(lib/)
    else()
    endif(ANDROID)
endif()

if(WIN32)
add_definitions("-DHAVE_PREAD")
add_definitions("-DHAVE_MMAP")
add_definitions("-DHAVE_STRNDUP")
endif()

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
