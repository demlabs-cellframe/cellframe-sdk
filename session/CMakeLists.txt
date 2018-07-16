cmake_minimum_required(VERSION 2.8)
project (dap_session)
  
set(SESSION_SRCS stream_session.c)

add_library(${PROJECT_NAME} STATIC ${SESSION_SRCS})

target_link_libraries(dap_session dap_core dap_crypto)

target_include_directories(dap_session INTERFACE .)
