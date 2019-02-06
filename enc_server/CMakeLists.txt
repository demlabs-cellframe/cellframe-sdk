cmake_minimum_required(VERSION 3.0)
project(dap_enc_server C)
  
set(DAP_ENC_SERVER_SRCS  dap_enc_http.c  dap_enc_ks.c)

add_library(${PROJECT_NAME} STATIC ${DAP_ENC_SERVER_SRCS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto
    dap_core_server dap_http_server)

target_include_directories(dap_enc_server INTERFACE .)
