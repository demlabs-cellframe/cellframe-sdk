cmake_minimum_required(VERSION 3.0)
project (dap_http_server C)

include_directories(http_client)

set(HTTP_SERVER_SRCS
    dap_http.c
    dap_http_folder.c
    dap_http_simple.c
    http_client/dap_http_client.c
    http_client/dap_http_header.c
    http_client/dap_http_user_agent.c)

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
  #include_directories(../../3rdparty/curl/include/)
endif()

add_library(${PROJECT_NAME} STATIC ${HTTP_SERVER_SRCS})

target_include_directories(dap_http_server INTERFACE . http_client)

if(WIN32)
  target_link_libraries(dap_http_server dap_core dap_crypto dap_server_core magic regex tre intl iconv
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
  target_link_libraries(dap_http_server curl dap_core dap_server_core magic json-c)
endif()
