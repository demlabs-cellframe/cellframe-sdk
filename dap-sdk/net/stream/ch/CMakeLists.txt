cmake_minimum_required(VERSION 3.0)
project (dap_stream_ch)
  
file(GLOB DAP_STREAM_CH_SRCS *.c)
file(GLOB DAP_STREAM_CH_HDRS include/*.h)

if(WIN32)
  include_directories(../3rdparty/wepoll/)
  include_directories(../3rdparty/uthash/src/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_STREAM_CH_SRCS} ${DAP_STREAM_CH_HDRS})

target_link_libraries(dap_stream_ch dap_core dap_crypto dap_stream)

target_include_directories(dap_stream_ch INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
