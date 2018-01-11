cmake_minimum_required(VERSION 2.8)
project (dap_crypto)
  
set(CRYPTO_SRCS
    dap_enc.c

    dap_enc_aes.c
    dap_enc_newhope.c

    dap_enc_key.c

    dap_hash.c
    dap_hash_fusion.c
    )

set(CRYPTO_HEADERS
    dap_enc.h

    dap_enc_aes.h
    dap_enc_newhope.h

    dap_enc_key.h

    dap_hash.h
    dap_hash_fusion.h
    dap_hash_slow.h
    dap_hash_keccak.h
    )

add_subdirectory(monero_crypto)

include_directories("${dap_core_INCLUDE_DIRS}")
include_directories("${monero_crypto_INCLUDE_DIRS}")
add_definitions ("${dap_core_DEFINITIONS}")
add_definitions ("${monero_crypto_DEFINITIONS}")
add_library(${PROJECT_NAME} STATIC ${CRYPTO_SRCS} ${CRYPTO_HEADERS} )

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)
set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
