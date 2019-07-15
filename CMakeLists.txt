cmake_minimum_required(VERSION 3.0)
project (dap_stream_ch_chain)
  
set(DAP_STREAM_CH_CHAIN_SRCS dap_stream_ch_chain.c dap_stream_ch_chain_pkt.c)

if(WIN32)
  include_directories(../libdap/src/win32/)
  include_directories(../3rdparty/libmemcached/)
  include_directories(../3rdparty/libmemcached/win32/)
  include_directories(../3rdparty/wepoll/include/)
  include_directories(../3rdparty/uthash/src/)
  include_directories(../3rdparty/libjson-c/)
  include_directories(../3rdparty/libmagic/src/)
  include_directories(../3rdparty/curl/include/)
  include_directories(../3rdparty/libsqlite3/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_STREAM_CH_CHAIN_SRCS})

target_link_libraries(dap_stream_ch_chain dap_core dap_crypto dap_chain dap_stream dap_stream_ch)

target_include_directories(dap_stream_ch_chain INTERFACE .)

