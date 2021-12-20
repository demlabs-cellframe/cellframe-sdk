cmake_minimum_required(VERSION 3.10)
project (dap_session)
  
file(GLOB SESSION_SRCS *.c)
file(GLOB SESSION_HDRS include/*.h)

add_library(${PROJECT_NAME} STATIC ${SESSION_SRCS})

include_directories(include/)
target_link_libraries(dap_session dap_core dap_crypto)
target_include_directories(dap_session INTERFACE . include/)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../3rdparty/uthash/src)
