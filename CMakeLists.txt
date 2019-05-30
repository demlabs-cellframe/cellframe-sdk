cmake_minimum_required(VERSION 2.8)
project (dap_chain_global_db)
  
file(GLOB DAP_CHAIN_GLOBAL_DB_SRC *.c)
file(GLOB DAP_CHAIN_GLOBAL_DB_HDR *.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_GLOBAL_DB_SRC} ${DAP_CHAIN_GLOBAL_DB_HDR})

target_link_libraries(dap_chain_global_db dap_core dap_crypto dap_chain dap_chain_crypto ldb talloc tevent sqlite3)
target_include_directories(dap_chain_global_db INTERFACE .)

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
