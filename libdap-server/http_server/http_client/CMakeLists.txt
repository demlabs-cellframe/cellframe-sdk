cmake_minimum_required(VERSION 3.0)
project (dap_http_client)

set(HTTP_SRCS dap_http_client.c dap_http_header.c)

if(WIN32)
  include_directories(../../../libdap/src/win32/)
  include_directories(../../../3rdparty/libmemcached/)
  include_directories(../../../3rdparty/libmemcached/win32/)
  include_directories(../../../3rdparty/wepoll/include/)
  include_directories(../../../3rdparty/uthash/src/)
  include_directories(../../../3rdparty/libjson-c/)
  include_directories(../../../3rdparty/libmagic/src/)
  include_directories(../../../3rdparty/curl/include/)
endif()

add_library(${PROJECT_NAME} STATIC ${HTTP_SRCS})

