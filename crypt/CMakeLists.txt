cmake_minimum_required(VERSION 2.8)
project (dap_crypto)
  
set(CRYPT_SRCS dap_enc.c dap_enc_aes.c dap_enc_newhope.c dap_enc_key.c  )

add_subdirectory(monero_crypto)

include_directories("${dap_core_INCLUDE_DIRS}")
include_directories("${monero_crypto_INCLUDE_DIRS}")
add_definitions ("${dap_core_DEFINITIONS}")
add_definitions ("${monero_crypto_DEFINITIONS}")
add_library(${PROJECT_NAME} STATIC ${CRYPT_SRCS} ${crypto_sources} )

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)
set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
