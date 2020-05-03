cmake_minimum_required(VERSION 3.0)
project (dap_stream_ch)
  
set(DAP_STREAM_CH_SRCS dap_stream_ch.c dap_stream_ch_pkt.c dap_stream_ch_proc.c)

if(WIN32)
  include_directories(../3rdparty/wepoll/)
  include_directories(../3rdparty/uthash/src/)
  #include_directories(../3rdparty/curl/include/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_STREAM_CH_SRCS})

target_link_libraries(dap_stream_ch dap_core dap_crypto dap_stream)

target_include_directories(dap_stream_ch INTERFACE .)
