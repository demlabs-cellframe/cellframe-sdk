cmake_minimum_required(VERSION 2.8)
project (dapcore)
  
set(CORE_SRCS dap_common.c )
 
add_library(${PROJECT_NAME} STATIC ${CORE_SRCS})

target_link_libraries(${PROJECT_NAME}  ev)

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
