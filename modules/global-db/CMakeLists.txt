cmake_minimum_required(VERSION 3.1)
project (dap_chain_global_db C)
  
file(GLOB DAP_CHAIN_GLOBAL_DB_SRC *.c)
file(GLOB DAP_CHAIN_GLOBAL_DB_HDR include/*.h)


add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_GLOBAL_DB_SRC} ${DAP_CHAIN_GLOBAL_DB_HDR})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain sqlite3 dap_cuttdb json-c mdbx-static)
add_definitions ("-DDAP_CHAIN_GDB_ENGINE_MDBX")

target_include_directories(dap_chain_global_db INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/uthash/src)

