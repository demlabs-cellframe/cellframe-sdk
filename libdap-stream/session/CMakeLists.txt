cmake_minimum_required(VERSION 2.8)
project (dap_session)
  
set(SESSION_SRCS dap_stream_session.c)

if(WIN32)
  include_directories(../../3rdparty/wepoll/)
  include_directories(../../3rdparty/uthash/src/)
  #include_directories(../../3rdparty/curl/include/)
endif()

add_library(${PROJECT_NAME} STATIC ${SESSION_SRCS})

target_link_libraries(dap_session dap_core dap_crypto)

target_include_directories(dap_session INTERFACE .)
