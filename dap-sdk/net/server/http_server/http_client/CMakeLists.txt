cmake_minimum_required(VERSION 3.0)
project (dap_http_client)

set(HTTP_SRCS FILES *.c)
set(HTTP_HDRS FILES include/*.h)

if(WIN32)
  include_directories(../../../../os/win32/)
  include_directories(../../../../3rdparty/wepoll/include/)
  include_directories(../../../../3rdparty/uthash/src/)
  include_directories(../../../../3rdparty/libmagic/src/)
endif()

add_library(${PROJECT_NAME} STATIC ${HTTP_SRCS} ${HTTP_HDRS})

