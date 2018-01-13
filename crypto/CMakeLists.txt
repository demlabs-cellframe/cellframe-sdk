cmake_minimum_required(VERSION 2.8)
project (dap_crypto)
  
set(CRYPTO_SRCS
        dap_enc.c
        dap_enc_base64.c
        dap_enc_aes.c
        dap_enc_newhope.c

        dap_enc_key.c
    )

set(CRYPTO_HEADERS
    dap_enc.h
    dap_enc_base64.h
    dap_enc_aes.h
    dap_enc_newhope.h

    dap_enc_key.h

    )


include_directories("${dap_core_INCLUDE_DIRS}")
add_definitions ("${dap_core_DEFINITIONS}")
add_library(${PROJECT_NAME} STATIC ${CRYPTO_SRCS} ${CRYPTO_HEADERS} )

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)
set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
