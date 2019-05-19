cmake_minimum_required(VERSION 2.8)
project (dap_chain_gdb)
  
file(GLOB DAP_CHAIN_GDB_SRC *.c)
file(GLOB DAP_CHAIN_GDB_HDR *.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_GDB_SRC} ${DAP_CHAIN_GDB_HDR})

target_link_libraries(dap_chain_gdb dap_core dap_chain dap_chain_global_db dap_chain_mempool dap_chain_net)
target_include_directories(dap_chain_gdb INTERFACE .)

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
