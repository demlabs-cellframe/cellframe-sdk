cmake_minimum_required(VERSION 2.8)
project (dap_chain_crypto)
  
set(DAP_CHAIN_CRYPTO_SRCS 
        dap_hash.c
        dap_hash_fusion.c
        dap_hash_keccak.c
        dap_hash_slow.c
        dap_chain_pkey.c
        dap_chain_sign.c
        )

set(DAP_CHAIN_CRYPTO_HEADERS
        dap_hash.h
        dap_hash_fusion.h
        dap_hash_keccak.h
        dap_hash_slow.h
        dap_chain_pkey.h
        dap_chain_sign.h

    )

add_subdirectory(monero_crypto)

include_directories("${monero_crypto_INCLUDE_DIRS}")
add_definitions ("${monero_crypto_DEFINITIONS}")


add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_CRYPTO_SRCS} ${DAP_CHAIN_CRYPTO_HEADERS})

target_include_directories(dap_chain_crypto INTERFACE .)
target_link_libraries(dap_chain_crypto dap_core dap_crypto dap_chain monero_crypto)

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
