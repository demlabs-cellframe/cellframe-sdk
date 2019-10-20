cmake_minimum_required(VERSION 2.8)
project (dap_chain_crypto)
  
set(DAP_CHAIN_CRYPTO_SRCS 
        dap_hash.c
        dap_hash_fusion.c
        dap_hash_keccak.c
        dap_hash_slow.c
        dap_chain_pkey.c
        dap_chain_sign.c
        dap_chain_cert.c
        dap_chain_cert_file.c
        )

set(DAP_CHAIN_CRYPTO_HEADERS
        dap_hash.h
        dap_hash_fusion.h
        dap_hash_keccak.h
        dap_hash_slow.h
        dap_chain_pkey.h
        dap_chain_sign.h
        dap_chain_cert.h
        dap_chain_cert_file.h
    )

if(NOT (${SUBMODULES_NO_BUILD} MATCHES ON))
  set(SUBMODULES_NO_BUILD ON)

  # Check whether we're on a 32-bit or 64-bit system
  if(CMAKE_SIZEOF_VOID_P EQUAL "8")
    set(DEFAULT_BUILD_64 ON)
  else()
    set(DEFAULT_BUILD_64 OFF)
  endif()
  option(BUILD_64 "Build for 64-bit? 'OFF' builds for 32-bit." ${DEFAULT_BUILD_64})

  add_definitions ("-DDAP_SERVER")
  add_definitions ("-DNODE_NETNAME=\"kelvin\"")

  set(_CCOPT "-Wall -O2 -pg -fPIC -fno-pie -no-pie")
  set(_LOPT "-pg")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -pg")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_CCOPT}")
  set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} ${_LOPT}")

  if (NOT (TARGET dap_core))
    add_subdirectory(libdap)
  endif()
  if (NOT (TARGET dap_crypto))
    add_subdirectory(libdap-crypto)
  endif()
  if (NOT (TARGET dap_chain))
    add_subdirectory(libdap-chain)
  endif()
  if (NOT (TARGET dap_chain_mempool))
    add_subdirectory(libdap-chain-mempool)
  endif()
  if (NOT (TARGET dap_server_core))
    add_subdirectory(libdap-server-core)
  endif()
  if (NOT (TARGET dap_chain_net))
    add_subdirectory(libdap-chain-net)
  endif()
  if (NOT (TARGET dap_chain_global_db))
    add_subdirectory(libdap-chain-global-db)
  endif()
  if (NOT (TARGET dap_client))
    add_subdirectory(libdap-client)
  endif()
  if (NOT (TARGET dap_server))
    add_subdirectory(libdap-server)
  endif()
  if (NOT (TARGET dap_udp_server))
    add_subdirectory(libdap-server-udp)
  endif()
  if (NOT (TARGET libdap-stream))
    add_subdirectory(libdap-stream)
  endif()
  if (NOT (TARGET dap_stream_ch))
    add_subdirectory(libdap-stream-ch)
  endif()
  if (NOT (TARGET dap_stream_ch_chain))
    add_subdirectory(libdap-stream-ch-chain)
  endif()
  if (NOT (TARGET dap_stream_ch_chain_net))
    add_subdirectory(libdap-stream-ch-chain-net)
  endif()
  if (NOT (TARGET dap_chain_wallet))
    add_subdirectory(libdap-chain-wallet)
  endif()
  if (NOT (TARGET dap_chain_net_srv))
    add_subdirectory(libdap-chain-net-srv)
  endif()
  if (NOT (TARGET dap_server_http_db_auth))
    add_subdirectory(libdap-server-http-db-auth)
  endif()
  if (NOT (TARGET dap_chain_gdb))
    add_subdirectory(libdap-chain-gdb)
  endif()
endif()

add_subdirectory(monero_crypto)

include_directories("${monero_crypto_INCLUDE_DIRS}")
add_definitions ("${monero_crypto_DEFINITIONS}")

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_CRYPTO_SRCS} ${DAP_CHAIN_CRYPTO_HEADERS})

target_include_directories(dap_chain_crypto INTERFACE .)
target_link_libraries(dap_chain_crypto dap_core dap_crypto dap_chain monero_crypto)

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)
set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)

if (${BUILD_DAP_CHAIN_CRYPTO_TESTS} MATCHES ON)
    enable_testing()
    add_subdirectory(test)
endif()
