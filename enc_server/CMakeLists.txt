cmake_minimum_required(VERSION 2.8)
project (dap_enc_server)
  
set(DAP_ENC_SERVER_SRCS  dap_enc_http.c  dap_enc_ks.c )

include_directories("${INCLUDE_DIRECTORIES} ${dap_core_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_crypto_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_client_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_http_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_db_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_core_server_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dap_http_server_INCLUDE_DIRS}")

add_definitions ("${dap_core_DEFINITIONS}")
add_definitions ("${dap_db_DEFINITIONS}")
add_definitions ("${dap_crypto_DEFINITIONS}")
add_definitions ("${dap_client_DEFINITIONS}")
add_definitions ("${dap_http_DEFINITIONS}")
add_definitions ("${dap_core_server_DEFINITIONS}")
add_definitions ("${dap_http_server_DEFINITIONS}")

add_library(${PROJECT_NAME} STATIC ${DAP_ENC_SERVER_SRCS})

target_link_libraries(dap_enc_server dap_http_server)
target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_core_server dap_http_server)

target_include_directories(dap_core_server INTERFACE .)
