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
#    add_definitions ("-DDAP_SERVER NODE_NETNAME=\"kelvin\"")

  include_directories(../../libdap/src/win32/)
  include_directories(../../3rdparty/wepoll/include/)
  include_directories(../../3rdparty/uthash/src/)
  include_directories(../../3rdparty/libjson-c/)
  include_directories(../../3rdparty/libmagic/src/)
  include_directories(../../3rdparty/curl/include/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_ENC_SERVER_SRCS})

if(WIN32)
  target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_server_core dap_http_server

  ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/[x86_64CLANG]/libmagic[x86_64CLANG].a
  ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/[x86_64CLANG]/curl[x86_64CLANG].a
  ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/[x86_64CLANG]/libjson-c[x86_64CLANG].a
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
