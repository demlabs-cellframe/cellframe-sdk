cmake_minimum_required(VERSION 3.0)
project(dap_enc_server C)
  
set(DAP_ENC_SERVER_SRCS  dap_enc_http.c  dap_enc_ks.c)

if(WIN32)
    add_definitions ("-DUNDEBUG")
    add_definitions ("-DNDEBUG")
    add_definitions ("-DWIN32")
    add_definitions ("-D_WINDOWS")
    add_definitions ("-D__WINDOWS__")
    add_definitions ("-D_CRT_SECURE_NO_WARNINGS")
    add_definitions ("-DCURL_STATICLIB")

  include_directories(../../3rdparty/wepoll/)
  include_directories(../../3rdparty/uthash/src/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_ENC_SERVER_SRCS})

if(WIN32)
  target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_server_core dap_http_server json-c
  KERNEL32
  USER32
  SHELL32
  WINMM
  GDI32
  ADVAPI32
  Ole32
  Version
  Imm32
  OleAut32
  ws2_32
  ntdll
  psapi
  Shlwapi
  Bcrypt
  Crypt32
  Secur32
)
endif()

if(UNIX)
  target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_server_core dap_http_server json-c )
endif()

target_include_directories(${PROJECT_NAME} INTERFACE .)
