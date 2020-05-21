cmake_minimum_required(VERSION 3.1)
project (dap_chain_global_db C)
  
file(GLOB DAP_CHAIN_GLOBAL_DB_SRC *.c)
file(GLOB DAP_CHAIN_GLOBAL_DB_HDR include/*.h)

if(WIN32)
  include_directories(../../3rdparty/wepoll/)
  include_directories(../../3rdparty/uthash/src/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_GLOBAL_DB_SRC} ${DAP_CHAIN_GLOBAL_DB_HDR})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain sqlite3 dap_cuttdb json-c)

target_include_directories(dap_chain_global_db INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

