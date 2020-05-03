cmake_minimum_required(VERSION 3.1)
project (dap_udp_server C)


file(GLOB DAP_UDP_SERVER_SRCS *.c)
file(GLOB DAP_UDP_SERVER_HEADERS include/*.h)

if(WIN32)
  include_directories(../../../3rdparty/wepoll/)
  include_directories(../../../3rdparty/uthash/src/)
  #include_directories(../3rdparty/curl/include/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_UDP_SERVER_SRCS} ${DAP_UDP_SERVER_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core dap_server_core)

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
