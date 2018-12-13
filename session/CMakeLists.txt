cmake_minimum_required(VERSION 2.8)
project (dap_session)
  
set(SESSION_SRCS dap_stream_session.c)

add_library(${PROJECT_NAME} STATIC ${SESSION_SRCS})

target_link_libraries(dap_session dap_core dap_crypto)

target_include_directories(dap_session INTERFACE .)
set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
