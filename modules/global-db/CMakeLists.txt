cmake_minimum_required(VERSION 3.1)
project (dap_chain_global_db C)
  
file(GLOB DAP_CHAIN_GLOBAL_DB_SRC *.c)
file(GLOB DAP_CHAIN_GLOBAL_DB_HDR include/*.h)

if(WIN32)
  include_directories(../../../3rdparty/wepoll/)
  include_directories(../../../3rdparty/uthash/src/)
endif()


add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_GLOBAL_DB_SRC} ${DAP_CHAIN_GLOBAL_DB_HDR})

add_subdirectory(../../../3rdparty/cuttdb)

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_crypto sqlite3 dap_cuttdb json-c)

target_include_directories(dap_chain_global_db INTERFACE .)

#set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

#set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
