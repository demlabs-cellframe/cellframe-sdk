cmake_minimum_required(VERSION 2.8)
project (dap_stream)
  
file(GLOB STREAM_SRCS *.c)
file(GLOB STREAM_HDRS include/*.h)

if(WIN32)
  include_directories(../../../3rdparty/wepoll/)
  include_directories(../../../3rdparty/uthash/src/)
  #include_directories(../../3rdparty/curl/include/)
endif()

add_library(${PROJECT_NAME} STATIC ${STREAM_SRCS} ${STREAM_HDRS})

target_link_libraries(dap_stream dap_core dap_server_core dap_crypto
    dap_http_server dap_enc_server dap_session dap_stream_ch)

target_include_directories(dap_stream INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
