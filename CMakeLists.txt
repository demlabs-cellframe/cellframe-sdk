cmake_minimum_required(VERSION 2.8)
project (libdap-chain)
  
set(DAP_CHAIN_SRCS dap_chain.c)
 
add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_SRCS})

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
